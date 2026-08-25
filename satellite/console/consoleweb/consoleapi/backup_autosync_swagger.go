// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// Swagger models for common /backup/auto-sync/* routes.

// UpdateBackupAutoSyncJobsByProjectSwaggerRequest is the UI body for PUT /backup/auto-sync/jobs/project.
type UpdateBackupAutoSyncJobsByProjectSwaggerRequest struct {
	ProjectID      string `json:"project_id" binding:"required" example:"00000000-0000-0000-0000-000000000000"`
	GoogleEmail    string `json:"google_email,omitempty" example:"user@gmail.com"`
	MicrosoftEmail string `json:"microsoft_email,omitempty" example:"user@contoso.com"`
	CredentialID   *int   `json:"credential_id,omitempty" example:"12"`
	Code           string `json:"code,omitempty" example:""`
	StorxToken     string `json:"storx_token,omitempty" example:"<storx access grant>"`
	RefreshToken   string `json:"refresh_token,omitempty" example:"<oauth refresh token>"`
	Active         *bool  `json:"active,omitempty" example:"true"`
}

// UpdateBackupAutoSyncJobSwaggerRequest is the UI body for PUT /backup/auto-sync/jobs/{job_id}.
type UpdateBackupAutoSyncJobSwaggerRequest struct {
	Active                        *bool  `json:"active,omitempty" example:"true"`
	RefreshToken                  string `json:"refresh_token,omitempty"`
	StorxToken                    string `json:"storx_token,omitempty"`
	ApplyStorxToAllLinkedAccounts *bool  `json:"apply_storx_to_all_linked_accounts,omitempty"`
}

// BackupAutoSyncJobServiceStatsSwagger is one service row from GET /backup/auto-sync/jobs/services.
type BackupAutoSyncJobServiceStatsSwagger struct {
	Service string `json:"service" example:"gmail"`
	Count   int    `json:"count" example:"5"`
	Active  int    `json:"active" example:"4"`
}

// BackupAutoSyncJobServicesSwaggerResponse is returned from GET /backup/auto-sync/jobs/services.
type BackupAutoSyncJobServicesSwaggerResponse struct {
	Success bool                                   `json:"success" example:"true"`
	Data    []BackupAutoSyncJobServiceStatsSwagger `json:"data"`
}

// BackupAutoSyncLiveTaskSwagger is one running/failed task on a live backup job.
type BackupAutoSyncLiveTaskSwagger struct {
	ID     string `json:"id" example:"task-123"`
	Status string `json:"status" example:"running" enums:"running,failed"`
}

// BackupAutoSyncLiveJobSwagger is one job in GET /backup/auto-sync/live data[].
type BackupAutoSyncLiveJobSwagger struct {
	ID            string                        `json:"id" example:"job-456"`
	Email         string                        `json:"email" example:"user@gmail.com"`
	Method        string                        `json:"method" example:"gmail"`
	BackupStatus  string                        `json:"backup_status" example:"running"`
	Tasks         []BackupAutoSyncLiveTaskSwagger `json:"tasks"`
}

// BackupAutoSyncLiveSwaggerResponse is returned from GET /backup/auto-sync/live.
type BackupAutoSyncLiveSwaggerResponse struct {
	Success bool                           `json:"success" example:"true"`
	Data    []BackupAutoSyncLiveJobSwagger `json:"data"`
}

// BackupAutoSyncBackupNowTaskSwagger is the task object from POST .../task/{job_id}/backup-now.
type BackupAutoSyncBackupNowTaskSwagger struct {
	ID        string `json:"id" example:"task-789"`
	JobID     string `json:"job_id" example:"job-456"`
	Status    string `json:"status" example:"queued"`
	Trigger   string `json:"trigger" example:"on_demand"`
	CreatedAt string `json:"created_at" example:"2026-01-01T00:00:00Z"`
}

// BackupAutoSyncBackupNowSwaggerResponse is returned from POST /backup/auto-sync/task/{job_id}/backup-now.
type BackupAutoSyncBackupNowSwaggerResponse struct {
	Success bool                             `json:"success" example:"true"`
	Data    BackupAutoSyncBackupNowTaskSwagger `json:"data"`
}

// UpdateBackupAutoSyncPolicySwaggerRequest is the UI body for PUT /backup/auto-sync/policy/{policy_id}.
type UpdateBackupAutoSyncPolicySwaggerRequest struct {
	Interval      string `json:"interval" binding:"required" example:"3h" enums:"3h,12h,daily,weekly,monthly"`
	On            string `json:"on" example:""`
	RetentionType string `json:"retention_type" binding:"required" example:"never" enums:"never,30_days,1_year,7_years"`
}

// CreateBackupAutoSyncPolicySwaggerRequest is the UI body for POST /backup/auto-sync/policy.
type CreateBackupAutoSyncPolicySwaggerRequest struct {
	Name          string `json:"name" binding:"required" example:"Executive Team Policy"`
	Interval      string `json:"interval" binding:"required" example:"12h" enums:"3h,12h,daily,weekly,monthly"`
	On            string `json:"on" example:""`
	RetentionType string `json:"retention_type" binding:"required" example:"never" enums:"never,30_days,1_year,7_years"`
	JobIDs        []int  `json:"job_ids,omitempty" example:"101,102,103"`
}

// MoveBackupAutoSyncPolicyAssignmentsSwaggerRequest is the UI body for POST /backup/auto-sync/policy/move.
type MoveBackupAutoSyncPolicyAssignmentsSwaggerRequest struct {
	TargetPolicyID int   `json:"target_policy_id" binding:"required" example:"61"`
	JobIDs         []int `json:"job_ids" binding:"required" example:"101,102"`
}

// MergeBackupAutoSyncPoliciesSwaggerRequest is the UI body for POST /backup/auto-sync/policy/merge.
type MergeBackupAutoSyncPoliciesSwaggerRequest struct {
	PolicyIDs []int  `json:"policy_ids" binding:"required" example:"52,55,56"`
	Name      string `json:"name" binding:"required" example:"My Unified Backup Policy"`
}
