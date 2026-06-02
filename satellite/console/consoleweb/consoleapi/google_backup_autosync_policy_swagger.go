// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// UpdateGoogleBackupAutoSyncPolicySwaggerRequest is the UI body for PUT .../auto-sync/policy/{policy_id}.
type UpdateGoogleBackupAutoSyncPolicySwaggerRequest struct {
	Interval       string `json:"interval" binding:"required" example:"daily"`
	On             string `json:"on" example:"12am"`
	RetentionType  string `json:"retention_type,omitempty" example:"1_year"`
	ApplyAll       *bool  `json:"apply_all,omitempty" example:"true"`
	SelectedJobIDs []int  `json:"selected_job_ids,omitempty" example:"101,102"`
}

// MergeGoogleBackupAutoSyncPoliciesSwaggerRequest is the UI body for POST .../auto-sync/policy/merge.
type MergeGoogleBackupAutoSyncPoliciesSwaggerRequest struct {
	DryRun bool `json:"dry_run" example:"false"`
}
