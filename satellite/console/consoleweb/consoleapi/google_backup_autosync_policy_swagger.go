// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// UpdateGoogleBackupAutoSyncPolicySwaggerRequest is the UI body for PUT .../auto-sync/policy/{policy_id}.
type UpdateGoogleBackupAutoSyncPolicySwaggerRequest struct {
	Interval      string `json:"interval" binding:"required" example:"3h" enums:"3h,12h,daily,weekly,monthly"`
	On            string `json:"on" example:""`
	RetentionType string `json:"retention_type" binding:"required" example:"never" enums:"never,30_days,1_year,7_years"`
}

// CreateGoogleBackupAutoSyncPolicySwaggerRequest is the UI body for POST .../auto-sync/policy.
type CreateGoogleBackupAutoSyncPolicySwaggerRequest struct {
	Name          string `json:"name" binding:"required" example:"Executive Team Policy"`
	Interval      string `json:"interval" binding:"required" example:"12h" enums:"3h,12h,daily,weekly,monthly"`
	On            string `json:"on" example:""`
	RetentionType string `json:"retention_type" binding:"required" example:"never" enums:"never,30_days,1_year,7_years"`
	JobIDs        []int  `json:"job_ids,omitempty" example:"101,102,103"`
}

// MoveGoogleBackupAutoSyncPolicyAssignmentsSwaggerRequest is the UI body for POST .../auto-sync/policy/move.
type MoveGoogleBackupAutoSyncPolicyAssignmentsSwaggerRequest struct {
	TargetPolicyID int   `json:"target_policy_id" binding:"required" example:"61"`
	JobIDs         []int `json:"job_ids" binding:"required" example:"101,102"`
}

// MergeGoogleBackupAutoSyncPoliciesSwaggerRequest is the UI body for POST .../auto-sync/policy/merge.
type MergeGoogleBackupAutoSyncPoliciesSwaggerRequest struct {
	PolicyIDs []int  `json:"policy_ids" binding:"required" example:"52,55,56"`
	Name      string `json:"name" binding:"required" example:"My Unified Backup Policy"`
}
