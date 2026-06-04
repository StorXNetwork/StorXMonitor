// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
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
	req := GoogleBackupRestoreAllRequest{
		Service:   "Gmail",
		ProjectID: "37159d9b-6f3c-4c38-bfe2-0efbbc4b568d",
		LoginID:   " child@company.com ",
	}
	require.NoError(t, (&req).Validate())

	raw, err := (&req).backupToolsPayload()
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(raw, &m))
	require.Equal(t, "gmail", m["service"])
	require.Equal(t, req.ProjectID, m["project_id"])
	require.Equal(t, "child@company.com", m["login_id"])
}

func TestGoogleBackupRestorePrepareParams_queryString(t *testing.T) {
	q := (&GoogleBackupRestorePrepareParams{
		ProjectID: "proj-1",
		LoginID:   "user@x.com",
		Service:   "photos",
	}).queryString()
	require.Contains(t, q, "project_id=proj-1")
	require.Contains(t, q, "login_id=user%40x.com")
	require.Contains(t, q, "service=photos")
}
