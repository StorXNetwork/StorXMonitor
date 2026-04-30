// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"context"
	"fmt"
	"maps"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"
)

var mon = monkit.Package()

type batchBucket struct {
	sender    *WebhookSender
	events    []TableChangeEvent
	firstTime time.Time
}

type Service struct {
	config           Config
	log              *zap.Logger
	sourceConn       *pgx.Conn
	adminConn        *pgx.Conn
	webhookSenders   map[string]*WebhookSender
	defaultSender    *WebhookSender
	relationCache    map[uint32]*pglogrepl.RelationMessage
	replicatedTables map[string]bool
	tableOptions     map[string]map[string]string

	eventChan      chan TableChangeEvent
	sendSem        chan struct{}
	ingressWg      sync.WaitGroup
	workerWg       sync.WaitGroup
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func NewService(log *zap.Logger, config Config) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	sourceDB := config.SourceDB
	adminDB := sourceDB
	if strings.Contains(adminDB, "replication=") {
		adminDB = strings.ReplaceAll(adminDB, "&replication=database", "")
		adminDB = strings.ReplaceAll(adminDB, "?replication=database", "")
		adminDB = strings.ReplaceAll(adminDB, "replication=database&", "")
	}

	adminConnConfig, err := pgx.ParseConfig(adminDB)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	adminConn, err := pgx.ConnectConfig(context.Background(), adminConnConfig)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	replConfig := *adminConnConfig
	replConfig.RuntimeParams = make(map[string]string)
	for k, v := range adminConnConfig.RuntimeParams {
		replConfig.RuntimeParams[k] = v
	}
	replConfig.RuntimeParams["replication"] = "database"

	sourceConn, err := pgx.ConnectConfig(context.Background(), &replConfig)
	if err != nil {
		adminConn.Close(context.Background())
		return nil, Error.Wrap(err)
	}

	webhookSenders := make(map[string]*WebhookSender)
	var defaultSender *WebhookSender

	if config.WebhookURL != "" {
		var err error
		defaultSender, err = NewWebhookSender(
			log.Named("webhook"),
			config.WebhookURL,
			config.WebhookPublicKey,
			config.MaxRetries,
			config.RetryDelay,
			config.WebhookTimeout,
		)
		if err != nil {
			adminConn.Close(context.Background())
			sourceConn.Close(context.Background())
			return nil, Error.Wrap(err)
		}
	}

	for _, tableConfig := range config.Tables {
		webhookURL := config.GetWebhookURL(tableConfig.Table)
		if webhookURL == "" {
			continue
		}

		if webhookURL == config.WebhookURL && defaultSender != nil {
			webhookSenders[tableConfig.Table] = defaultSender
			continue
		}

		sender, err := NewWebhookSender(
			log.Named("webhook").Named(tableConfig.Table),
			webhookURL,
			config.WebhookPublicKey,
			config.MaxRetries,
			config.RetryDelay,
			config.WebhookTimeout,
		)
		if err != nil {
			adminConn.Close(context.Background())
			sourceConn.Close(context.Background())
			return nil, Error.Wrap(fmt.Errorf("failed to create webhook sender for table %s: %w", tableConfig.Table, err))
		}
		webhookSenders[tableConfig.Table] = sender
	}

	replicatedTables := make(map[string]bool)
	tableOptions := make(map[string]map[string]string)
	for _, tableConfig := range config.Tables {
		replicatedTables[tableConfig.Table] = true
		if len(tableConfig.Options) > 0 {
			tableOptions[tableConfig.Table] = maps.Clone(tableConfig.Options)
		}
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	workerPoolSize := config.WorkerPoolSize
	if workerPoolSize < 1 {
		workerPoolSize = 50
	}
	channelBuffer := config.EventChannelBuffer
	if channelBuffer < 1 {
		channelBuffer = 500
	}

	service := &Service{
		config:           config,
		log:              log,
		sourceConn:       sourceConn,
		adminConn:        adminConn,
		webhookSenders:   webhookSenders,
		defaultSender:    defaultSender,
		relationCache:    make(map[uint32]*pglogrepl.RelationMessage),
		replicatedTables: replicatedTables,
		tableOptions:     tableOptions,
		eventChan:        make(chan TableChangeEvent, channelBuffer),
		sendSem:          make(chan struct{}, workerPoolSize),
		shutdownCtx:      shutdownCtx,
		shutdownCancel:   shutdownCancel,
	}

	service.ingressWg.Add(1)
	go service.runBatchIngress()

	return service, nil
}

func (s *Service) Run(ctx context.Context) error {
	defer mon.Task()(&ctx)(nil)

	slotExists, err := s.createReplicationSlot(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if !slotExists {
		s.log.Info("created replication slot", zap.String("slot", s.config.SlotName))
	} else {
		s.log.Info("replication slot already exists", zap.String("slot", s.config.SlotName))
	}

	err = s.createPublication(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if err := s.ensureReplicaIdentity(ctx); err != nil {
		return Error.Wrap(err)
	}

	lsn, err := s.getCurrentLSN(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	s.log.Info("starting replication",
		zap.String("slot", s.config.SlotName),
		zap.String("publication", s.config.PublicationName),
		zap.String("lsn", lsn.String()),
	)

	err = pglogrepl.StartReplication(ctx, s.sourceConn.PgConn(), s.config.SlotName, lsn,
		pglogrepl.StartReplicationOptions{
			PluginArgs: []string{
				"proto_version '1'",
				fmt.Sprintf("publication_names '%s'", s.config.PublicationName),
			},
		})
	if err != nil {
		return Error.Wrap(err)
	}

	clientXLogPos := lsn
	nextStandbyMessageDeadline := time.Now().Add(s.config.StatusUpdateInterval)

	s.log.Info("replication started successfully")

	for {
		if time.Now().After(nextStandbyMessageDeadline) {
			err = pglogrepl.SendStandbyStatusUpdate(ctx, s.sourceConn.PgConn(),
				pglogrepl.StandbyStatusUpdate{
					WALWritePosition: clientXLogPos,
					WALFlushPosition: clientXLogPos,
					WALApplyPosition: clientXLogPos,
				})
			if err != nil {
				s.log.Error("failed to send standby status", zap.Error(err))
			}
			nextStandbyMessageDeadline = time.Now().Add(s.config.StatusUpdateInterval)
		}

		ctxWithTimeout, cancel := context.WithDeadline(ctx, nextStandbyMessageDeadline)
		msg, err := s.sourceConn.PgConn().ReceiveMessage(ctxWithTimeout)
		cancel()

		if err != nil {
			if ctxWithTimeout.Err() == context.DeadlineExceeded {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return Error.Wrap(err)
		}

		switch msg := msg.(type) {
		case *pgproto3.CopyData:
			switch msg.Data[0] {
			case pglogrepl.PrimaryKeepaliveMessageByteID:
				pkm, err := pglogrepl.ParsePrimaryKeepaliveMessage(msg.Data[1:])
				if err != nil {
					s.log.Warn("failed to parse keepalive message", zap.Error(err))
					continue
				}
				if pkm.ReplyRequested {
					nextStandbyMessageDeadline = time.Time{}
				}

			case pglogrepl.XLogDataByteID:
				xld, err := pglogrepl.ParseXLogData(msg.Data[1:])
				if err != nil {
					s.log.Error("failed to parse xlog data", zap.Error(err))
					continue
				}

				logicalMsg, err := pglogrepl.Parse(xld.WALData)
				if err != nil {
					s.log.Error("failed to parse logical message", zap.Error(err))
					continue
				}

				err = s.handleMessage(ctx, logicalMsg)
				if err != nil {
					s.log.Error("failed to handle message", zap.Error(err))
				}

				clientXLogPos = xld.WALStart + pglogrepl.LSN(len(xld.WALData))
			}
		}
	}
}

func (s *Service) handleMessage(ctx context.Context, msg pglogrepl.Message) error {
	switch msg := msg.(type) {
	case *pglogrepl.RelationMessage:
		s.relationCache[msg.RelationID] = msg
		return nil

	case *pglogrepl.InsertMessage:
		return s.handleInsert(ctx, msg)

	case *pglogrepl.UpdateMessage:
		return s.handleUpdate(ctx, msg)

	case *pglogrepl.DeleteMessage:
		return s.handleDelete(ctx, msg)

	case *pglogrepl.BeginMessage:
		return nil

	case *pglogrepl.CommitMessage:
		return nil

	default:
		return nil
	}
}

func (s *Service) handleInsert(ctx context.Context, msg *pglogrepl.InsertMessage) error {
	return s.handleChange(ctx, msg.RelationID, "INSERT", msg.Tuple, nil)
}

func (s *Service) handleUpdate(ctx context.Context, msg *pglogrepl.UpdateMessage) error {
	return s.handleChange(ctx, msg.RelationID, "UPDATE", msg.NewTuple, msg.OldTuple)
}

func (s *Service) handleDelete(ctx context.Context, msg *pglogrepl.DeleteMessage) error {
	return s.handleChange(ctx, msg.RelationID, "DELETE", nil, msg.OldTuple)
}

func (s *Service) handleChange(ctx context.Context, relationID uint32, operation string, newTuple, oldTuple *pglogrepl.TupleData) error {
	rel, ok := s.relationCache[relationID]
	if !ok {
		return Error.New("unknown relation ID: %d", relationID)
	}

	tableName := rel.RelationName

	if len(s.replicatedTables) > 0 && !s.isTableReplicated(tableName) {
		return nil
	}

	if !s.config.ShouldReplicateEvent(tableName, operation) {
		return nil
	}

	var data, oldData map[string]interface{}
	var err error

	if newTuple != nil {
		data, err = extractTableData(rel, newTuple)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	if oldTuple != nil {
		oldData, err = extractTableData(rel, oldTuple)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	if operation == "DELETE" && tableOptionSkipPendingCleanup(s.tableOptions[tableName]) {
		if shouldSkipPendingCleanupDelete(rel, oldTuple, oldData) {
			return nil
		}
	}

	event := TableChangeEvent{
		Operation: operation,
		Table:     tableName,
		Timestamp: time.Now(),
		Data:      data,
		OldData:   oldData,
	}
	if opts := s.tableOptions[tableName]; len(opts) > 0 {
		event.TableOptions = opts
	}

	select {
	case s.eventChan <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.shutdownCtx.Done():
		return s.shutdownCtx.Err()
	}
}

func (s *Service) getWebhookSender(tableName string) *WebhookSender {
	if sender, ok := s.webhookSenders[tableName]; ok {
		return sender
	}
	return s.defaultSender
}

func (s *Service) isTableReplicated(tableName string) bool {
	if len(s.replicatedTables) == 0 {
		return true
	}
	return s.replicatedTables[tableName]
}

func (s *Service) setAdminSearchPathFromDSN(ctx context.Context, purpose string) {
	schema := extractSchemaFromConnectionString(s.config.SourceDB)
	if schema == "" {
		return
	}
	_, err := s.adminConn.Exec(ctx, fmt.Sprintf("SET search_path TO \"%s\"", schema))
	if err != nil {
		s.log.Warn("failed to set search_path",
			zap.String("for", purpose),
			zap.String("schema", schema),
			zap.Error(err))
		return
	}
	s.log.Debug("set search_path", zap.String("for", purpose), zap.String("schema", schema))
}

func (s *Service) createReplicationSlot(ctx context.Context) (bool, error) {
	var exists bool
	err := s.adminConn.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_replication_slots WHERE slot_name = $1)",
		s.config.SlotName).Scan(&exists)
	if err != nil {
		return false, Error.Wrap(err)
	}

	if exists {
		return true, nil
	}

	_, err = s.adminConn.Exec(ctx,
		"SELECT pg_create_logical_replication_slot($1, 'pgoutput')",
		s.config.SlotName)
	if err != nil {
		return false, Error.Wrap(err)
	}

	return false, nil
}

func (s *Service) createPublication(ctx context.Context) error {
	var exists bool
	err := s.adminConn.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_publication WHERE pubname = $1)",
		s.config.PublicationName).Scan(&exists)
	if err != nil {
		return Error.Wrap(err)
	}

	if exists {
		s.log.Info("publication already exists", zap.String("publication", s.config.PublicationName))
		return nil
	}

	s.setAdminSearchPathFromDSN(ctx, "publication")
	schema := extractSchemaFromConnectionString(s.config.SourceDB)

	tableNames := s.config.GetTableNames()
	if len(tableNames) == 0 {
		query := fmt.Sprintf("CREATE PUBLICATION %s FOR ALL TABLES", s.config.PublicationName)
		_, err = s.adminConn.Exec(ctx, query)
		if err != nil {
			return Error.Wrap(err)
		}
		s.log.Info("created publication for all tables",
			zap.String("publication", s.config.PublicationName),
			zap.String("schema", schema),
		)
	} else {
		tableNamesClean := make([]string, 0, len(tableNames))
		for _, table := range tableNames {
			tableName := table
			if strings.Contains(table, ".") {
				parts := strings.Split(table, ".")
				tableName = parts[len(parts)-1]
			}
			tableNamesClean = append(tableNamesClean, tableName)
		}
		tables := strings.Join(tableNamesClean, ", ")
		query := fmt.Sprintf("CREATE PUBLICATION %s FOR TABLE %s", s.config.PublicationName, tables)
		_, err = s.adminConn.Exec(ctx, query)
		if err != nil {
			return Error.Wrap(err)
		}
		s.log.Info("created publication",
			zap.String("publication", s.config.PublicationName),
			zap.String("tables", tables),
			zap.String("schema", schema),
		)
	}

	return nil
}

func (s *Service) ensureReplicaIdentity(ctx context.Context) error {
	alters, err := collectReplicaIdentityAlters(&s.config)
	if err != nil {
		return err
	}
	if len(alters) == 0 {
		return nil
	}

	s.setAdminSearchPathFromDSN(ctx, "replica_identity")

	for _, a := range alters {
		if _, err := s.adminConn.Exec(ctx, a.SQL); err != nil {
			return Error.Wrap(err)
		}
		s.log.Info("replication: replica identity DDL applied",
			zap.String("table", a.Table),
			zap.String("mode", a.Mode),
		)
	}
	return nil
}

func (s *Service) getCurrentLSN(ctx context.Context) (pglogrepl.LSN, error) {
	var lsnStr string
	err := s.adminConn.QueryRow(ctx, "SELECT pg_current_wal_lsn()").Scan(&lsnStr)
	if err != nil {
		return 0, Error.Wrap(err)
	}

	lsn, err := pglogrepl.ParseLSN(lsnStr)
	if err != nil {
		return 0, Error.Wrap(err)
	}

	return lsn, nil
}

func (s *Service) runBatchIngress() {
	defer s.ingressWg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in batch ingress",
				zap.Any("panic", r),
				zap.ByteString("stack", debug.Stack()),
			)
		}
	}()

	batchSize := s.config.WebhookBatchSize
	flushInterval := s.config.WebhookBatchFlushInterval
	buckets := make(map[string]*batchBucket)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-s.eventChan:
			if !ok {
				s.flushAllWebhookBuckets(buckets)
				return
			}
			s.addEventToWebhookBuckets(buckets, ev, batchSize)

		case <-ticker.C:
			s.flushExpiredWebhookBuckets(buckets, flushInterval)
		}
	}
}

func (s *Service) addEventToWebhookBuckets(buckets map[string]*batchBucket, ev TableChangeEvent, batchSize int) {
	sender := s.getWebhookSender(ev.Table)
	if sender == nil {
		s.log.Warn("no webhook sender configured for table", zap.String("table", ev.Table))
		return
	}

	key := sender.url
	b := buckets[key]
	if b == nil {
		b = &batchBucket{
			sender: sender,
			events: make([]TableChangeEvent, 0, batchSize),
		}
		buckets[key] = b
	}
	if len(b.events) == 0 {
		b.firstTime = time.Now()
	}
	b.events = append(b.events, ev)
	if len(b.events) >= batchSize {
		s.emitWebhookBatch(b)
		delete(buckets, key)
	}
}

func (s *Service) emitWebhookBatch(b *batchBucket) {
	if len(b.events) == 0 {
		return
	}
	events := make([]TableChangeEvent, len(b.events))
	copy(events, b.events)
	s.workerWg.Add(1)
	go s.sendWebhookBatch(b.sender, events)
}

func (s *Service) flushExpiredWebhookBuckets(buckets map[string]*batchBucket, flushInterval time.Duration) {
	now := time.Now()
	for key, b := range buckets {
		if b == nil || len(b.events) == 0 {
			continue
		}
		if now.Sub(b.firstTime) >= flushInterval {
			s.emitWebhookBatch(b)
			delete(buckets, key)
		}
	}
}

func (s *Service) flushAllWebhookBuckets(buckets map[string]*batchBucket) {
	for key, b := range buckets {
		if b == nil || len(b.events) == 0 {
			delete(buckets, key)
			continue
		}
		s.emitWebhookBatch(b)
		delete(buckets, key)
	}
}

func (s *Service) sendWebhookBatch(sender *WebhookSender, events []TableChangeEvent) {
	defer s.workerWg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in webhook batch sender",
				zap.Any("panic", r),
				zap.ByteString("stack", debug.Stack()),
			)
		}
	}()
	s.sendSem <- struct{}{}
	defer func() { <-s.sendSem }()

	ctx, cancel := context.WithTimeout(s.shutdownCtx, s.config.WebhookTimeout)
	err := sender.SendEvents(ctx, events)
	cancel()

	if err != nil {
		s.log.Error("failed to send webhook batch",
			zap.Int("batch_size", len(events)),
			zap.Error(err),
		)
	}
}

func (s *Service) Close() error {
	s.shutdownCancel()

	close(s.eventChan)

	ingressDone := make(chan struct{})
	go func() {
		s.ingressWg.Wait()
		close(ingressDone)
	}()

	select {
	case <-ingressDone:
	case <-time.After(30 * time.Second):
		s.log.Warn("timeout waiting for batch ingress to finish")
	}

	done := make(chan struct{})
	go func() {
		s.workerWg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.log.Warn("timeout waiting for webhook senders to finish")
	}

	var errs []error
	if s.sourceConn != nil {
		if err := s.sourceConn.Close(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	if s.adminConn != nil {
		if err := s.adminConn.Close(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return Error.New("errors closing connections: %v", errs)
	}
	return nil
}

func extractSchemaFromConnectionString(connStr string) string {
	if !strings.Contains(connStr, "search_path") {
		return ""
	}

	parts := strings.Split(connStr, "options=")
	if len(parts) < 2 {
		return ""
	}

	options := parts[1]
	if strings.Contains(options, "&") {
		options = strings.Split(options, "&")[0]
	}

	if strings.Contains(options, "--search_path") {
		searchPathParts := strings.Split(options, "--search_path")
		if len(searchPathParts) < 2 {
			return ""
		}

		valuePart := searchPathParts[1]
		valuePart = strings.TrimPrefix(valuePart, "=")
		valuePart = strings.TrimPrefix(valuePart, "%3D")

		valuePart = strings.Trim(valuePart, `"`)
		valuePart = strings.Trim(valuePart, `'`)
		valuePart = strings.ReplaceAll(valuePart, "%22", "")
		valuePart = strings.ReplaceAll(valuePart, "%27", "")

		if strings.Contains(valuePart, ",") {
			valuePart = strings.Split(valuePart, ",")[0]
		}

		schema := strings.ReplaceAll(valuePart, "%2F", "/")
		schema = strings.ReplaceAll(schema, "%2D", "-")
		schema = strings.TrimSpace(schema)

		return schema
	}

	return ""
}
