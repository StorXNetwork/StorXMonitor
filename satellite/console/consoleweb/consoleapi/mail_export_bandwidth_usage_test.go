// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestBandwidthUsageValidation_table(t *testing.T) {
	tests := []struct {
		name       string
		auth       string
		body       string
		wantStatus int
	}{
		{
			name:       "unauthorized",
			auth:       "Bearer wrong",
			body:       `{"accessGrant":"g","bytes":1,"jobId":"j","chargeId":"c"}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid json",
			auth:       "Bearer secret",
			body:       `{`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown field rejected",
			auth:       "Bearer secret",
			body:       `{"accessGrant":"g","bytes":1,"jobId":"j","chargeId":"c","projectId":"forged"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewMailExportJobs(zaptest.NewLogger(t), nil, "secret")
			req := httptest.NewRequest(http.MethodPost, "/api/v0/internal/bandwidth-usage", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Authorization", tt.auth)
			rr := httptest.NewRecorder()
			h.BandwidthUsage(rr, req)
			require.Equal(t, tt.wantStatus, rr.Code)
			if tt.wantStatus == http.StatusUnauthorized {
				var resp mailExportErrorResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
				require.Equal(t, "unauthorized", resp.Error)
			}
		})
	}
}
