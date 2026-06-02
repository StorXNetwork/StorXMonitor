// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateGoogleBackupAutoSyncPolicyRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateGoogleBackupAutoSyncPolicyRequest
		wantErr string
	}{
		{
			name: "interval and on",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval: "3h",
				On:       "",
			},
		},
		{
			name: "daily schedule with retention",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "daily",
				On:            "12am",
				RetentionType: "1_year",
			},
		},
		{
			name: "selective renew",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:       "daily",
				On:             "12am",
				RetentionType:  "1_year",
				ApplyAll:       boolPtr(false),
				SelectedJobIDs: []int{101, 102},
			},
		},
		{
			name:    "missing interval",
			req:     UpdateGoogleBackupAutoSyncPolicyRequest{On: "12am"},
			wantErr: "interval is required",
		},
		{
			name: "unsupported interval",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval: "1h",
				On:       "",
			},
			wantErr: "unsupported interval",
		},
		{
			name: "unsupported retention",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "daily",
				On:            "12am",
				RetentionType: "forever",
			},
			wantErr: "unsupported retention_type",
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

func TestUpdateGoogleBackupAutoSyncPolicyRequest_backupToolsPayload(t *testing.T) {
	tests := []struct {
		name string
		req  UpdateGoogleBackupAutoSyncPolicyRequest
		want map[string]interface{}
	}{
		{
			name: "apply all with retention",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "nightly",
				On:            "12am",
				RetentionType: "1_year",
				ApplyAll:      boolPtr(true),
			},
			want: map[string]interface{}{
				"interval":       "daily",
				"on":             "12am",
				"retention_type": "1_year",
				"apply_all":      true,
			},
		},
		{
			name: "selective jobs",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:       "weekly",
				On:             "Monday",
				ApplyAll:       boolPtr(false),
				SelectedJobIDs: []int{101},
			},
			want: map[string]interface{}{
				"interval":         "weekly",
				"on":               "Monday",
				"apply_all":        false,
				"selected_job_ids": []interface{}{float64(101)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := tt.req.backupToolsPayload()
			require.NoError(t, err)

			var got map[string]interface{}
			require.NoError(t, json.Unmarshal(body, &got))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMergeGoogleBackupAutoSyncPoliciesRequest_backupToolsPayload(t *testing.T) {
	body, err := MergeGoogleBackupAutoSyncPoliciesRequest{DryRun: true}.backupToolsPayload()
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, map[string]interface{}{"dry_run": true}, got)
}
