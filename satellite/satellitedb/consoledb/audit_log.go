// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/auditlog"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/StorXMonitor/shared/tagsql"
	"github.com/StorXNetwork/common/uuid"
)

var _ auditlog.DB = (*auditLogsDB)(nil)

var ErrAuditLog = errs.Class("auditlog")

type auditLogsDB struct {
	db *dbx.DB
}

func (db *ConsoleDB) AuditLogs() auditlog.DB {
	return &auditLogsDB{db: db.DB}
}

func (a *auditLogsDB) Insert(ctx context.Context, record auditlog.Record) (err error) {
	defer mon.Task()(&ctx)(&err)

	optional := dbx.AuditLog_Create_Fields{}
	if record.Resource != "" {
		optional.Resource = dbx.AuditLog_Resource(record.Resource)
	}
	if record.IPAddress != "" {
		optional.IpAddress = dbx.AuditLog_IpAddress(record.IPAddress)
	}

	err = a.db.CreateNoReturn_AuditLog(ctx,
		dbx.AuditLog_Id(record.ID[:]),
		dbx.AuditLog_ActorId(record.ActorID),
		dbx.AuditLog_Action(record.Action),
		dbx.AuditLog_Message(record.Message),
		dbx.AuditLog_Status(string(record.Status)),
		optional,
	)
	return ErrAuditLog.Wrap(err)
}

func (a *auditLogsDB) List(ctx context.Context, params auditlog.ListParams) (_ auditlog.ListResult, err error) {
	defer mon.Task()(&ctx)(&err)

	query, args := buildAuditLogQuery(params, true)
	rows, err := a.db.QueryContext(ctx, a.db.Rebind(query), args...)
	if err != nil {
		return auditlog.ListResult{}, ErrAuditLog.Wrap(err)
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	items, err := scanAuditLogRows(rows)
	if err != nil {
		return auditlog.ListResult{}, err
	}

	var nextCursor string
	if len(items) == params.Limit {
		last := items[len(items)-1]
		nextCursor = auditlog.EncodeCursor(last.Timestamp, last.ID)
	}

	return auditlog.ListResult{Items: items, NextCursor: nextCursor}, nil
}

func (a *auditLogsDB) Count(ctx context.Context, params auditlog.ListParams) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	where, args := buildAuditLogWhere(params)
	query := "SELECT COUNT(*) FROM audit_logs"
	if where != "" {
		query += " WHERE " + where
	}
	err = a.db.QueryRowContext(ctx, a.db.Rebind(query), args...).Scan(&count)
	return count, ErrAuditLog.Wrap(err)
}

func (a *auditLogsDB) ListActions(ctx context.Context, actorID string) (_ []string, err error) {
	defer mon.Task()(&ctx)(&err)

	if actorID == "" {
		return nil, nil
	}

	rows, err := a.db.QueryContext(ctx, a.db.Rebind(
		`SELECT DISTINCT action FROM audit_logs WHERE actor_id = ? ORDER BY action`),
		actorID,
	)
	if err != nil {
		return nil, ErrAuditLog.Wrap(err)
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, ErrAuditLog.Wrap(err)
		}
		actions = append(actions, action)
	}
	return actions, ErrAuditLog.Wrap(rows.Err())
}

func (a *auditLogsDB) DeleteBefore(ctx context.Context, before time.Time) (deleted int64, err error) {
	defer mon.Task()(&ctx)(&err)

	result, err := a.db.ExecContext(ctx, a.db.Rebind(
		"DELETE FROM audit_logs WHERE timestamp < ?"), before)
	if err != nil {
		return 0, ErrAuditLog.Wrap(err)
	}
	n, err := result.RowsAffected()
	return n, ErrAuditLog.Wrap(err)
}

func buildAuditLogWhere(params auditlog.ListParams) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if params.ActorID != "" {
		conditions = append(conditions, "actor_id = ?")
		args = append(args, params.ActorID)
	}
	if params.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, params.Action)
	}
	if params.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, params.Status)
	}
	if search := strings.TrimSpace(params.Search); search != "" {
		pattern := "%" + search + "%"
		if id, err := uuid.FromString(search); err == nil {
			conditions = append(conditions, "(id = ? OR action ILIKE ? OR resource ILIKE ? OR message ILIKE ?)")
			args = append(args, id[:], pattern, pattern, pattern)
		} else {
			conditions = append(conditions, "(action ILIKE ? OR resource ILIKE ? OR message ILIKE ?)")
			args = append(args, pattern, pattern, pattern)
		}
	}
	if params.From != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, *params.From)
	}
	if params.To != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, *params.To)
	}
	if params.Cursor != "" {
		cursorTS, cursorID, err := auditlog.DecodeCursor(params.Cursor)
		if err == nil && !cursorTS.IsZero() {
			conditions = append(conditions, "(timestamp < ? OR (timestamp = ? AND id < ?))")
			args = append(args, cursorTS, cursorTS, cursorID[:])
		}
	}

	return strings.Join(conditions, " AND "), args
}

func buildAuditLogQuery(params auditlog.ListParams, withLimit bool) (string, []interface{}) {
	where, args := buildAuditLogWhere(params)

	query := "SELECT id, timestamp, actor_id, action, resource, message, ip_address, status FROM audit_logs"
	if where != "" {
		query += " WHERE " + where
	}
	query += " ORDER BY timestamp DESC, id DESC"
	if withLimit {
		limit := params.Limit
		if limit <= 0 {
			limit = 50
		}
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	return query, args
}

func scanAuditLogRows(rows tagsql.Rows) ([]auditlog.Record, error) {
	var items []auditlog.Record
	for rows.Next() {
		var (
			idBytes   []byte
			timestamp time.Time
			actorID   *string
			action    string
			resource  *string
			message   string
			ipAddress *string
			status    string
		)
		if err := rows.Scan(
			&idBytes, &timestamp, &actorID,
			&action, &resource, &message, &ipAddress, &status,
		); err != nil {
			return nil, ErrAuditLog.Wrap(err)
		}
		id, err := uuid.FromBytes(idBytes)
		if err != nil {
			return nil, ErrAuditLog.Wrap(err)
		}
		items = append(items, auditlog.Record{
			ID:        id,
			Timestamp: timestamp,
			ActorID:   derefString(actorID),
			Action:    action,
			Resource:  derefString(resource),
			Message:   message,
			IPAddress: derefString(ipAddress),
			Status:    auditlog.Status(status),
		})
	}
	return items, ErrAuditLog.Wrap(rows.Err())
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
