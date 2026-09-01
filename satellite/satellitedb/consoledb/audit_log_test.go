// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/auditlog"
)

func TestBuildAuditLogQueries(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name              string
		params            auditlog.ListParams
		withLimit         bool
		wantContains      []string
		wantNotContains   []string
	}{
		{
			name: "list query orders and limits",
			params: auditlog.ListParams{
				ActorID: "user-1",
				Limit:   25,
			},
			withLimit: true,
			wantContains: []string{
				"SELECT id, timestamp",
				"WHERE actor_id = ?",
				"ORDER BY timestamp DESC, id DESC",
				"LIMIT 25",
			},
		},
		{
			name: "count query has no order by",
			params: auditlog.ListParams{
				ActorID: "user-1",
				Action:  "AUTH_LOGIN",
				Status:  "failed",
				From:    &from,
				To:      &to,
			},
			withLimit: false,
			wantContains: []string{
				"SELECT COUNT(*) FROM audit_logs",
				"actor_id = ?",
				"action = ?",
				"status = ?",
				"timestamp >= ?",
				"timestamp <= ?",
			},
			wantNotContains: []string{
				"ORDER BY",
				"LIMIT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var query string
			if tt.withLimit {
				query, _ = buildAuditLogQuery(tt.params, true)
			} else {
				where, _ := buildAuditLogWhere(tt.params)
				query = "SELECT COUNT(*) FROM audit_logs"
				if where != "" {
					query += " WHERE " + where
				}
			}

			for _, want := range tt.wantContains {
				require.Contains(t, query, want)
			}
			for _, omit := range tt.wantNotContains {
				require.NotContains(t, strings.ToUpper(query), strings.ToUpper(omit))
			}
		})
	}
}
