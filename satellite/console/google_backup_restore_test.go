// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoogleBackupRestorePrepareParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  GoogleBackupRestorePrepareParams
		wantErr string
	}{
		{
			name: "valid gmail",
			params: GoogleBackupRestorePrepareParams{
				ProjectID: "37159d9b-6f3c-4c38-bfe2-0efbbc4b568d",
				LoginID:   "user@company.com",
				Service:   "gmail",
			},
		},
		{
			name:    "missing project_id",
			params:  GoogleBackupRestorePrepareParams{LoginID: "a@b.com", Service: "drive"},
			wantErr: "project_id is required",
		},
		{
			name:    "unsupported service",
			params:  GoogleBackupRestorePrepareParams{ProjectID: "p", LoginID: "a@b.com", Service: "youtube"},
			wantErr: "unsupported service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&tt.params).Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestGoogleBackupRestoreAllRequest_Validate_andPayload(t *testing.T) {
	tests := []struct {
		name       string
		req        GoogleBackupRestoreAllRequest
		wantTarget bool
	}{
		{
			name: "without target_email",
			req: GoogleBackupRestoreAllRequest{
				Service:   "Gmail",
				ProjectID: "37159d9b-6f3c-4c38-bfe2-0efbbc4b568d",
				LoginID:   " child@company.com ",
			},
		},
		{
			name: "with target_email",
			req: GoogleBackupRestoreAllRequest{
				Service:     "drive",
				ProjectID:   "proj-1",
				LoginID:     "alice@company.com",
				TargetEmail: " bob@company.com ",
			},
			wantTarget: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, (&tt.req).Validate())

			raw, err := (&tt.req).backupToolsPayload()
			require.NoError(t, err)

			var m map[string]string
			require.NoError(t, json.Unmarshal(raw, &m))
			require.Equal(t, strings.TrimSpace(strings.ToLower(tt.req.Service)), m["service"])
			require.Equal(t, strings.TrimSpace(tt.req.ProjectID), m["project_id"])
			require.Equal(t, strings.TrimSpace(tt.req.LoginID), m["login_id"])
			if tt.wantTarget {
				require.Equal(t, "bob@company.com", m["target_email"])
			} else {
				_, ok := m["target_email"]
				require.False(t, ok)
			}
		})
	}
}

func TestGoogleBackupManualRestoreRequest_Validate(t *testing.T) {
	req := GoogleBackupManualRestoreRequest{
		GoogleAuth: "eyJhbGciOiJIUzI1NiIs...",
		Keys:       []string{"dXNlckBnbWFpbC5jb20="},
	}
	require.NoError(t, req.Validate())

	err := GoogleBackupManualRestoreRequest{Keys: []string{"k"}}.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Authorization header is required")

	err = GoogleBackupManualRestoreRequest{
		GoogleAuth: "jwt",
		Keys:       []string{"dXNlckBnbWFpbC5jb20="},
	}.Validate()
	require.NoError(t, err)

	err = GoogleBackupManualRestoreRequest{GoogleAuth: "jwt"}.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys or ids is required")
}

func TestGoogleBackupRestorePrepareParams_queryString(t *testing.T) {
	tests := []struct {
		name        string
		params      GoogleBackupRestorePrepareParams
		wantTarget  bool
		wantService string
	}{
		{
			name: "without target_email",
			params: GoogleBackupRestorePrepareParams{
				ProjectID: "proj-1",
				LoginID:   "user@x.com",
				Service:   "photos",
			},
			wantService: "photos",
		},
		{
			name: "with target_email",
			params: GoogleBackupRestorePrepareParams{
				ProjectID:   "proj-1",
				LoginID:     "alice@company.com",
				Service:     "gmail",
				TargetEmail: "bob@company.com",
			},
			wantTarget:  true,
			wantService: "gmail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := (&tt.params).queryString()
			require.Contains(t, q, "project_id=proj-1")
			require.Contains(t, q, "service="+tt.wantService)
			if tt.wantTarget {
				require.Contains(t, q, "target_email=bob%40company.com")
			} else {
				require.NotContains(t, q, "target_email=")
			}
		})
	}
}

func TestFilterRestoreQuery(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		allowed map[string]struct{}
		want    string
	}{
		{
			name:    "credentials drops project_id and legacy filters",
			raw:     "search=alice&limit=20&offset=0&login_id=src%40x.com&project_id=p1&credential_id=9&account_kind=personal",
			allowed: restoreCredentialsAllowedQuery,
			want:    "limit=20&login_id=src%40x.com&offset=0&search=alice",
		},
		{
			name:    "workspaces keeps domain filters only",
			raw:     "domain=company.com&search=bob&limit=10&project_id=p1&credential_id=9",
			allowed: restoreWorkspacesAllowedQuery,
			want:    "domain=company.com&limit=10&search=bob",
		},
		{
			name:    "empty query",
			raw:     "",
			allowed: restoreCredentialsAllowedQuery,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterRestoreQuery(tt.raw, tt.allowed)
			if tt.want == "" {
				require.Equal(t, "", got)
				return
			}
			gotValues, err := url.ParseQuery(got)
			require.NoError(t, err)
			wantValues, err := url.ParseQuery(tt.want)
			require.NoError(t, err)
			require.Equal(t, wantValues, gotValues)
		})
	}
}
