// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestAccessRestoreAuditMessage(t *testing.T) {
	grants := []console.MemberBucketGrantInput{
		{Bucket: "gmail", AllowList: true, AllowDownload: true},
		{Bucket: "drive", AllowList: true},
	}
	require.Equal(t,
		"Invite access and restore updated for a@b.com: vault access gmail, drive, restore on",
		accessRestoreAuditMessage("Invite access and restore", "a@b.com", &grants),
	)

	readOnly := []console.MemberBucketGrantInput{
		{Bucket: "outlook", AllowList: true},
	}
	require.Equal(t,
		"Member access and restore updated for a@b.com: vault access outlook, restore off",
		accessRestoreAuditMessage("Member access and restore", "a@b.com", &readOnly),
	)

	require.Equal(t,
		"Invite access and restore updated for a@b.com",
		accessRestoreAuditMessage("Invite access and restore", "a@b.com", nil),
	)
}

func TestRecordDownloadActivity(t *testing.T) {
	projectID := "11111111-1111-1111-1111-111111111111"
	handler := &AuditLogs{
		log:     zaptest.NewLogger(t),
		service: &console.Service{},
	}

	tests := []struct {
		name   string
		user   bool
		body   string
		status int
	}{
		{name: "missing user", body: `{"projectId":"` + projectID + `","action":"GB_DOWNLOAD","resource":"mail.json"}`, status: http.StatusUnauthorized},
		{name: "unknown field", user: true, body: `{"projectId":"` + projectID + `","action":"GB_DOWNLOAD","resource":"mail.json","extra":1}`, status: http.StatusBadRequest},
		{name: "bad action", user: true, body: `{"projectId":"` + projectID + `","action":"GB_RESTORE_INITIATED","resource":"mail.json"}`, status: http.StatusBadRequest},
		{name: "empty resource", user: true, body: `{"projectId":"` + projectID + `","action":"MB_DOWNLOAD","resource":"  "}`, status: http.StatusBadRequest},
		{name: "bad project", user: true, body: `{"projectId":"not-a-uuid","action":"GB_DOWNLOAD","resource":"mail.json"}`, status: http.StatusBadRequest},
		{name: "gmail download", user: true, body: `{"projectId":"` + projectID + `","action":"GB_DOWNLOAD","resource":"mail.json"}`, status: http.StatusNoContent},
		{name: "outlook download", user: true, body: `{"projectId":"` + projectID + `","action":"MB_DOWNLOAD","resource":"archive.zip"}`, status: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v0/audit-logs/activity", bytes.NewBufferString(tt.body))
			if tt.user {
				req = req.WithContext(console.WithUser(req.Context(), &console.User{Email: "invitee@example.com"}))
			}
			rec := httptest.NewRecorder()
			handler.RecordActivity(rec, req)
			require.Equal(t, tt.status, rec.Code)
		})
	}

	long := strings.Repeat("a", 513)
	req := httptest.NewRequest(http.MethodPost, "/api/v0/audit-logs/activity", bytes.NewBufferString(
		`{"projectId":"`+projectID+`","action":"GB_DOWNLOAD","resource":"`+long+`"}`,
	))
	req = req.WithContext(console.WithUser(req.Context(), &console.User{Email: "invitee@example.com"}))
	rec := httptest.NewRecorder()
	handler.RecordActivity(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
