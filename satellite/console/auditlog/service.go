// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package auditlog

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/sync2"
	"github.com/StorXNetwork/common/uuid"
)

var (
	mon   = monkit.Package()
	Error = errs.Class("auditlog")
)

// Service writes audit events in the background and reads them for the console API.
type Service struct {
	log       *zap.Logger
	db        DB
	config    Config
	events    chan Event
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewService creates the service and starts worker goroutines that persist queued events.
func NewService(log *zap.Logger, db DB, config Config) *Service {
	if config.WorkerCount <= 0 {
		config.WorkerCount = 4
	}
	if config.ChannelCapacity <= 0 {
		config.ChannelCapacity = 1000
	}
	if config.MaxExportDays <= 0 {
		config.MaxExportDays = 90
	}
	if config.MaxExportRows <= 0 {
		config.MaxExportRows = 100000
	}

	s := &Service{
		log:    log.Named("auditlog"),
		db:     db,
		config: config,
		events: make(chan Event, config.ChannelCapacity),
	}
	for i := 0; i < config.WorkerCount; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}
	return s
}

func (s *Service) Config() Config {
	return s.config
}

// RecordAsync queues an event for a worker to persist. It does not block on the database.
// When the queue is full, a separate goroutine inserts the event directly as a fallback.
func (s *Service) RecordAsync(ctx context.Context, event Event) {
	select {
	case s.events <- event:
	default:
		mon.Event("audit_log_channel_overflow")
		go func() {
			if err := s.record(context.Background(), event); err != nil {
				s.log.Warn("audit log overflow fallback failed",
					zap.String("action", event.Action),
					zap.Error(err))
			}
		}()
	}
}

func (s *Service) worker(id int) {
	defer s.wg.Done()
	for event := range s.events {
		if err := s.record(context.Background(), event); err != nil {
			s.log.Warn("audit log worker failed to persist event",
				zap.Int("worker", id),
				zap.String("action", event.Action),
				zap.Error(err))
		}
	}
}

func (s *Service) record(ctx context.Context, event Event) error {
	action, err := normalizeAction(event.Action)
	if err != nil {
		return Error.Wrap(err)
	}
	message, err := normalizeMessage(event.Message)
	if err != nil {
		return Error.Wrap(err)
	}
	status, err := normalizeStatus(event.Status)
	if err != nil {
		return Error.Wrap(err)
	}

	id, err := uuid.New()
	if err != nil {
		return Error.Wrap(err)
	}

	record := Record{
		ID:        id,
		Timestamp: time.Now().UTC(),
		ActorID:   event.ActorID,
		Action:    action,
		Resource:  event.Resource,
		Message:   message,
		IPAddress: event.IPAddress,
		Status:    status,
	}
	if err := s.db.Insert(ctx, record); err != nil {
		mon.Event("audit_log_record_failed")
		return Error.Wrap(err)
	}
	mon.Event("audit_log_recorded")
	return nil
}

// List returns one page of records for the given filters. Limit defaults to 50 and caps at 200.
func (s *Service) List(ctx context.Context, params ListParams) (result ListResult, err error) {
	defer mon.Task()(&ctx)(&err)
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 200 {
		params.Limit = 200
	}
	return s.db.List(ctx, params)
}

func (s *Service) Count(ctx context.Context, params ListParams) (count int, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.db.Count(ctx, params)
}

// ListUserActions returns distinct action codes already stored for actorID.
func (s *Service) ListUserActions(ctx context.Context, actorID string) (actions []string, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.db.ListActions(ctx, actorID)
}

// ExportCSV streams all matching rows to w as CSV. from and to are required.
// The date range and row count are capped by service config.
func (s *Service) ExportCSV(ctx context.Context, params ListParams, actor ActorDisplay, w io.Writer) (err error) {
	defer mon.Task()(&ctx)(&err)

	if params.From == nil || params.To == nil {
		return Error.New("from and to timestamps are required for export")
	}
	maxRange := time.Duration(s.config.MaxExportDays) * 24 * time.Hour
	if params.To.Sub(*params.From) > maxRange {
		return Error.New("export date range exceeds maximum of %d days", s.config.MaxExportDays)
	}

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"timestamp", "actor", "action", "resource", "message", "ip_address", "status"}); err != nil {
		return Error.Wrap(err)
	}

	params.Limit = 500
	written := 0
	for {
		if written >= s.config.MaxExportRows {
			break
		}
		page, err := s.db.List(ctx, params)
		if err != nil {
			return Error.Wrap(err)
		}
		ApplyActorDisplay(page.Items, actor)
		for _, r := range page.Items {
			if written >= s.config.MaxExportRows {
				break
			}
			if err := cw.Write([]string{
				r.Timestamp.Format(time.RFC3339),
				r.ActorName,
				r.Action,
				r.Resource,
				r.Message,
				r.IPAddress,
				string(r.Status),
			}); err != nil {
				return Error.Wrap(err)
			}
			written++
		}
		if page.NextCursor == "" || len(page.Items) == 0 {
			break
		}
		params.Cursor = page.NextCursor
	}
	cw.Flush()
	return Error.Wrap(cw.Error())
}

func (s *Service) DeleteBefore(ctx context.Context, before time.Time) (deleted int64, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.db.DeleteBefore(ctx, before)
}

// Close stops accepting new events and waits for workers to finish.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		close(s.events)
	})
	s.wg.Wait()
	return nil
}

// ListParamsFromQuery maps HTTP query parameters onto ListParams for the authenticated user.
func ListParamsFromQuery(q url.Values, actorID string) (ListParams, error) {
	params := ListParams{
		ActorID: actorID,
		Action:  q.Get("action"),
		Status:  q.Get("status"),
		Search:  q.Get("search"),
		Cursor:  q.Get("cursor"),
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			return ListParams{}, Error.Wrap(err)
		}
		params.Limit = limit
	}
	if fromStr := q.Get("from"); fromStr != "" {
		from, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return ListParams{}, Error.New("invalid from timestamp")
		}
		params.From = &from
	}
	if toStr := q.Get("to"); toStr != "" {
		to, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			return ListParams{}, Error.New("invalid to timestamp")
		}
		params.To = &to
	}
	return params, nil
}

func normalizeAction(action string) (string, error) {
	action = strings.TrimSpace(action)
	if action == "" {
		return "", Error.New("action is required")
	}
	if len(action) > 128 {
		return "", Error.New("action exceeds maximum length")
	}
	for _, r := range action {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			continue
		}
		return "", Error.New("action contains invalid characters")
	}
	return action, nil
}

func normalizeMessage(message string) (string, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return "", Error.New("message is required")
	}
	if len(message) > 1024 {
		return "", Error.New("message exceeds maximum length")
	}
	return message, nil
}

func normalizeStatus(status Status) (Status, error) {
	if status == "" {
		return StatusSuccess, nil
	}
	switch status {
	case StatusSuccess, StatusFailed:
		return status, nil
	default:
		return "", Error.New("invalid status: only success and failed are allowed")
	}
}

// EncodeCursor builds an opaque pagination token from the last row of a page.
func EncodeCursor(t time.Time, id uuid.UUID) string {
	payload := fmt.Sprintf("%s|%s", t.UTC().Format(time.RFC3339Nano), id.String())
	return base64.URLEncoding.EncodeToString([]byte(payload))
}

// DecodeCursor parses a pagination token produced by EncodeCursor.
func DecodeCursor(cursor string) (time.Time, uuid.UUID, error) {
	if cursor == "" {
		return time.Time{}, uuid.UUID{}, nil
	}
	raw, err := base64.URLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.UUID{}, Error.Wrap(err)
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.UUID{}, Error.New("invalid cursor format")
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.UUID{}, Error.Wrap(err)
	}
	id, err := uuid.FromString(parts[1])
	if err != nil {
		return time.Time{}, uuid.UUID{}, Error.Wrap(err)
	}
	return ts, id, nil
}

// Chore deletes audit rows older than the configured retention period.
type Chore struct {
	log     *zap.Logger
	service *Service
	Loop    *sync2.Cycle
}

func NewChore(log *zap.Logger, service *Service, interval time.Duration) *Chore {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &Chore{
		log:     log.Named("auditlog-chore"),
		service: service,
		Loop:    sync2.NewCycle(interval),
	}
}

func (c *Chore) Run(ctx context.Context) error {
	return c.Loop.Run(ctx, func(ctx context.Context) error {
		return c.RunOnce(ctx)
	})
}

func (c *Chore) Close() error {
	c.Loop.Close()
	return nil
}

func (c *Chore) RunOnce(ctx context.Context) error {
	retentionDays := c.service.config.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 180
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	deleted, err := c.service.DeleteBefore(ctx, cutoff)
	if err != nil {
		return err
	}
	if deleted > 0 {
		c.log.Info("audit log retention completed",
			zap.Int64("deleted", deleted),
			zap.Time("cutoff", cutoff))
	}
	return nil
}
