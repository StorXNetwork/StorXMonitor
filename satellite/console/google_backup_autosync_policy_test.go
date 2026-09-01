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
			name: "valid 3h schedule",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "3h",
				On:            "",
				RetentionType: "never",
			},
		},
		{
			name: "valid daily schedule",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "daily",
				On:            "12am",
				RetentionType: "1_year",
			},
		},
		{
			name:    "missing interval",
			req:     UpdateGoogleBackupAutoSyncPolicyRequest{On: "12am", RetentionType: "never"},
			wantErr: "interval is required",
		},
		{
			name: "unsupported interval",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "1h",
				On:            "",
				RetentionType: "never",
			},
			wantErr: "unsupported interval",
		},
		{
			name: "missing retention_type",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval: "daily",
				On:       "12am",
			},
			wantErr: "retention_type is required",
		},
		{
			name: "unsupported retention_type",
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
			name: "daily schedule",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "nightly",
				On:            "12am",
				RetentionType: "1_year",
			},
			want: map[string]interface{}{
				"interval":       "daily",
				"on":             "12am",
				"retention_type": "1_year",
			},
		},
		{
			name: "weekly schedule",
			req: UpdateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "weekly",
				On:            "Monday",
				RetentionType: "never",
			},
			want: map[string]interface{}{
				"interval":       "weekly",
				"on":             "Monday",
				"retention_type": "never",
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

func TestCreateGoogleBackupAutoSyncPolicyRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     CreateGoogleBackupAutoSyncPolicyRequest
		wantErr string
	}{
		{
			name: "empty policy",
			req: CreateGoogleBackupAutoSyncPolicyRequest{
				Name:          "Empty template",
				Interval:      "daily",
				On:            "12am",
				RetentionType: "never",
			},
		},
		{
			name: "split with job ids",
			req: CreateGoogleBackupAutoSyncPolicyRequest{
				Name:          "Executive Team Policy",
				Interval:      "12h",
				On:            "",
				RetentionType: "never",
				JobIDs:        []int{101, 102},
			},
		},
		{
			name: "missing name",
			req: CreateGoogleBackupAutoSyncPolicyRequest{
				Interval:      "daily",
				On:            "12am",
				RetentionType: "never",
			},
			wantErr: "name is required",
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

func TestCreateGoogleBackupAutoSyncPolicyRequest_backupToolsPayload(t *testing.T) {
	tests := []struct {
		name string
		req  CreateGoogleBackupAutoSyncPolicyRequest
		want map[string]interface{}
	}{
		{
			name: "without job_ids",
			req: CreateGoogleBackupAutoSyncPolicyRequest{
				Name:          "Empty template",
				Interval:      "daily",
				On:            "12am",
				RetentionType: "never",
			},
			want: map[string]interface{}{
				"name":           "Empty template",
				"interval":       "daily",
				"on":             "12am",
				"retention_type": "never",
			},
		},
		{
			name: "with job_ids",
			req: CreateGoogleBackupAutoSyncPolicyRequest{
				Name:          "Executive Team Policy",
				Interval:      "12h",
				On:            "",
				RetentionType: "never",
				JobIDs:        []int{101, 102, 103},
			},
			want: map[string]interface{}{
				"name":           "Executive Team Policy",
				"interval":       "12h",
				"on":             "",
				"retention_type": "never",
				"job_ids":        []interface{}{float64(101), float64(102), float64(103)},
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

func TestMoveGoogleBackupAutoSyncPolicyAssignmentsRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     MoveGoogleBackupAutoSyncPolicyAssignmentsRequest
		wantErr string
	}{
		{
			name: "valid move",
			req: MoveGoogleBackupAutoSyncPolicyAssignmentsRequest{
				TargetPolicyID: 61,
				JobIDs:         []int{101, 102},
			},
		},
		{
			name:    "missing target_policy_id",
			req:     MoveGoogleBackupAutoSyncPolicyAssignmentsRequest{JobIDs: []int{101}},
			wantErr: "target_policy_id is required",
		},
		{
			name:    "missing job_ids",
			req:     MoveGoogleBackupAutoSyncPolicyAssignmentsRequest{TargetPolicyID: 61},
			wantErr: "job_ids is required",
		},
		{
			name: "duplicate job_ids",
			req: MoveGoogleBackupAutoSyncPolicyAssignmentsRequest{
				TargetPolicyID: 61,
				JobIDs:         []int{101, 101},
			},
			wantErr: "job_ids must not contain duplicates",
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

func TestMergeGoogleBackupAutoSyncPoliciesRequest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		policyIDs []int
		policyName string
		wantErr   string
	}{
		{
			name:       "valid merge",
			policyIDs:  []int{52, 55, 56},
			policyName: "My Unified Backup Policy",
		},
		{
			name:       "two policy ids",
			policyIDs:  []int{12, 18},
			policyName: "Merged Policy",
		},
		{
			name:      "single policy id",
			policyIDs: []int{12},
			policyName: "Merged Policy",
			wantErr:   "at least two policy_ids are required",
		},
		{
			name:    "empty policy ids",
			wantErr: "at least two policy_ids are required",
		},
		{
			name:      "missing name",
			policyIDs: []int{12, 18},
			wantErr:   "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MergeGoogleBackupAutoSyncPoliciesRequest{
				PolicyIDs: tt.policyIDs,
				Name:      tt.policyName,
			}.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMergeGoogleBackupAutoSyncPoliciesRequest_backupToolsPayload(t *testing.T) {
	body, err := MergeGoogleBackupAutoSyncPoliciesRequest{
		PolicyIDs: []int{52, 55, 56},
		Name:      "My Unified Backup Policy",
	}.backupToolsPayload()
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, map[string]interface{}{
		"policy_ids": []interface{}{float64(52), float64(55), float64(56)},
		"name":       "My Unified Backup Policy",
	}, got)
}

func TestGoogleBackupAutoSyncPolicyAvailableAssignmentsQuery(t *testing.T) {
	tests := []struct {
		name      string
		policyID  string
		search    string
		email     string
		wantQuery string
		wantErr   string
	}{
		{
			name:      "policy_id only",
			policyID:  "50",
			wantQuery: "policy_id=50",
		},
		{
			name:      "with search",
			policyID:  "50",
			search:    "admin",
			wantQuery: "policy_id=50&search=admin",
		},
		{
			name:      "step two email",
			policyID:  "50",
			email:     "admin@acme.com",
			wantQuery: "email=admin%40acme.com&policy_id=50",
		},
		{
			name:    "missing policy_id",
			wantErr: "policy_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := googleBackupAutoSyncPolicyAvailableAssignmentsQuery(tt.policyID, tt.search, tt.email)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantQuery, got)
		})
	}
}
