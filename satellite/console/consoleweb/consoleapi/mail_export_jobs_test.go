// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestMailExportJobsValidateBearerToken(t *testing.T) {
	tests := []struct {
		name         string
		serviceToken string
		authHeader   string
		want         bool
	}{
		{
			name:         "empty configured token fails closed",
			serviceToken: "",
			authHeader:   "Bearer secret",
			want:         false,
		},
		{
			name:         "missing authorization header",
			serviceToken: "secret",
			authHeader:   "",
			want:         false,
		},
		{
			name:         "wrong scheme",
			serviceToken: "secret",
			authHeader:   "X-API-Key secret",
			want:         false,
		},
		{
			name:         "wrong token",
			serviceToken: "secret",
			authHeader:   "Bearer other",
			want:         false,
		},
		{
			name:         "matching bearer token",
			serviceToken: "secret",
			authHeader:   "Bearer secret",
			want:         true,
		},
		{
			name:         "trims whitespace",
			serviceToken: "secret",
			authHeader:   "  Bearer   secret  ",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewMailExportJobs(zaptest.NewLogger(t), nil, tt.serviceToken)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			require.Equal(t, tt.want, h.validateBearerToken(req))
		})
	}
}

func TestMailExportJobsUnauthorizedWithoutToken(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		handler func(*MailExportJobs) http.HandlerFunc
	}{
		{name: "create", method: http.MethodPost, path: "/api/v0/internal/mail-export-jobs", handler: func(h *MailExportJobs) http.HandlerFunc { return h.Create }},
		{name: "claim", method: http.MethodPost, path: "/api/v0/internal/mail-export-jobs/claim", handler: func(h *MailExportJobs) http.HandlerFunc { return h.Claim }},
		{name: "expire", method: http.MethodPost, path: "/api/v0/internal/mail-export-jobs/expire", handler: func(h *MailExportJobs) http.HandlerFunc { return h.Expire }},
		{name: "requeue", method: http.MethodPost, path: "/api/v0/internal/mail-export-jobs/requeue-stale", handler: func(h *MailExportJobs) http.HandlerFunc { return h.RequeueStale }},
		{name: "get", method: http.MethodGet, path: "/api/v0/internal/mail-export-jobs/job-1", handler: func(h *MailExportJobs) http.HandlerFunc { return h.Get }},
		{name: "patch", method: http.MethodPatch, path: "/api/v0/internal/mail-export-jobs/job-1", handler: func(h *MailExportJobs) http.HandlerFunc { return h.Patch }},
		{name: "cancel", method: http.MethodPost, path: "/api/v0/internal/mail-export-jobs/job-1/cancel", handler: func(h *MailExportJobs) http.HandlerFunc { return h.Cancel }},
		{name: "quota", method: http.MethodGet, path: "/api/v0/internal/bandwidth-quota", handler: func(h *MailExportJobs) http.HandlerFunc { return h.BandwidthQuota }},
		{name: "usage", method: http.MethodPost, path: "/api/v0/internal/bandwidth-usage", handler: func(h *MailExportJobs) http.HandlerFunc { return h.BandwidthUsage }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewMailExportJobs(zaptest.NewLogger(t), nil, "expected-token")
			var body *bytes.Reader
			switch tt.name {
			case "requeue":
				body = bytes.NewReader([]byte(`{"olderThan":"30m"}`))
			case "patch":
				body = bytes.NewReader([]byte(`{"status":"SUCCEEDED"}`))
			case "usage":
				body = bytes.NewReader([]byte(`{"accessGrant":"g","bytes":1,"jobId":"j","chargeId":"c"}`))
			default:
				body = bytes.NewReader([]byte(`{}`))
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req = mux.SetURLVars(req, map[string]string{"id": "job-1"})
			rr := httptest.NewRecorder()
			tt.handler(h)(rr, req)
			require.Equal(t, http.StatusUnauthorized, rr.Code)

			var resp mailExportErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			require.Equal(t, "unauthorized", resp.Error)
		})
	}
}
