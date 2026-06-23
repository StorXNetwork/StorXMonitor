// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateGoogleBackupAutoSyncJobsByProjectRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateGoogleBackupAutoSyncJobsByProjectRequest
		wantErr string
	}{
		{
			name: "valid minimal identifiers with update field",
			req: UpdateGoogleBackupAutoSyncJobsByProjectRequest{
				ProjectID:   "00000000-0000-0000-0000-000000000001",
				GoogleEmail: "user@gmail.com",
				Active:      boolPtr(true),
			},
		},
		{
			name: "missing project_id",
			req: UpdateGoogleBackupAutoSyncJobsByProjectRequest{
				GoogleEmail: "user@gmail.com",
				Active:      boolPtr(true),
			},
			wantErr: "project_id is required",
		},
		{
			name: "missing google_email",
			req: UpdateGoogleBackupAutoSyncJobsByProjectRequest{
				ProjectID: "00000000-0000-0000-0000-000000000001",
				Active:    boolPtr(true),
			},
			wantErr: "google_email is required",
		},
		{
			name: "no update fields",
			req: UpdateGoogleBackupAutoSyncJobsByProjectRequest{
				ProjectID:   "00000000-0000-0000-0000-000000000001",
				GoogleEmail: "user@gmail.com",
			},
			wantErr: "at least one update field is required",
		},
		{
			name: "code counts as update field",
			req: UpdateGoogleBackupAutoSyncJobsByProjectRequest{
				ProjectID:   "00000000-0000-0000-0000-000000000001",
				GoogleEmail: "user@gmail.com",
				Code:        "oauth-code",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestUpdateGoogleBackupAutoSyncJobsByProjectRequest_backupToolsPayload(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateGoogleBackupAutoSyncJobsByProjectRequest
		want    map[string]interface{}
		wantErr string
	}{
		{
			name: "omits code and sends refresh_token",
			req: UpdateGoogleBackupAutoSyncJobsByProjectRequest{
				ProjectID:    "proj-1",
				GoogleEmail:  "user@gmail.com",
				RefreshToken: "rt-1",
				Active:       boolPtr(false),
			},
			want: map[string]interface{}{
				"project_id":    "proj-1",
				"google_email":  "user@gmail.com",
				"refresh_token": "rt-1",
				"active":        false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := tt.req.backupToolsPayload()
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			var got map[string]interface{}
			require.NoError(t, json.Unmarshal(body, &got))
			require.Equal(t, tt.want, got)
			_, hasCode := got["code"]
			require.False(t, hasCode)
		})
	}
}

func TestUpdateGoogleBackupAutoSyncJobRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateGoogleBackupAutoSyncJobRequest
		wantErr string
	}{
		{
			name: "active only",
			req:  UpdateGoogleBackupAutoSyncJobRequest{Active: boolPtr(true)},
		},
		{
			name:    "missing active",
			req:     UpdateGoogleBackupAutoSyncJobRequest{},
			wantErr: "active is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestUpdateGoogleBackupAutoSyncJobRequest_backupToolsPayload(t *testing.T) {
	body, err := UpdateGoogleBackupAutoSyncJobRequest{Active: boolPtr(true)}.backupToolsPayload()
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, map[string]interface{}{"active": true}, got)
}

func boolPtr(v bool) *bool { return &v }
