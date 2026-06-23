// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// Swagger models for Google Backup restore proxy (Backup-Tools /google-auth, /restore/*, /google/* manual restore).

// GoogleBackupAuthSwaggerRequest is the UI body for POST /google-backup/google-auth.
type GoogleBackupAuthSwaggerRequest struct {
	GoogleKey string `json:"google_key" binding:"required" example:"<Google OAuth id_token or access_token>"`
}

// GoogleBackupAuthSwaggerResponse is returned from Backup-Tools POST /google-auth (passthrough).
type GoogleBackupAuthSwaggerResponse struct {
	GoogleAuth string `json:"google-auth" example:"eyJhbGciOiJIUzI1NiIs..."`
}

// GoogleBackupRestoreAllSwaggerRequest starts async restore-all on Backup-Tools (token_key only; credentials from DB).
type GoogleBackupRestoreAllSwaggerRequest struct {
	Service   string `json:"service" binding:"required" example:"gmail" enums:"gmail,drive,photos,calendar,contacts"`
	ProjectID string `json:"project_id" binding:"required" example:"37159d9b-6f3c-4c38-bfe2-0efbbc4b568d"`
	LoginID   string `json:"login_id" binding:"required" example:"user@company.com"`
}

// GoogleBackupManualRestoreSwaggerRequest is the UI body for manual restore (1–10 base64 vault keys per request).
// Same body for single or multiple items: send keys or ids (not both). Backup-Tools JWT goes in Authorization header only.
type GoogleBackupManualRestoreSwaggerRequest struct {
	Keys []string `json:"keys,omitempty" example:"dXNlckBnbWFpbC5jb20vcGF0aC9maWxl"`
	IDs  []string `json:"ids,omitempty" example:"dXNlckBnbWFpbC5jb20vcGF0aC9maWxl"`
}

// RestoreMissingPermissionSwagger is one OAuth or grant gap from GET /restore/prepare.
type RestoreMissingPermissionSwagger struct {
	Type        string `json:"type" example:"oauth"`
	Service     string `json:"service" example:"gmail"`
	Scope       string `json:"scope,omitempty" example:"https://www.googleapis.com/auth/gmail.insert"`
	Description string `json:"description,omitempty" example:"OAuth scope required for restore"`
}

// RestorePrepareSwaggerResponse is the flat body from GET /restore/prepare (and 422 from POST /restore/all when not ready).
type RestorePrepareSwaggerResponse struct {
	Ready              bool                              `json:"ready" example:"false"`
	Reason             string                            `json:"reason,omitempty" example:"missing_permissions"`
	AuthMode           string                            `json:"auth_mode,omitempty" example:"oauth" enums:"oauth,dwd"`
	AccountType        string                            `json:"account_type,omitempty" example:"personal" enums:"personal,employee_workspace,admin_workspace"`
	Service            string                            `json:"service,omitempty" example:"gmail"`
	ProjectID          string                            `json:"project_id,omitempty" example:"37159d9b-6f3c-4c38-bfe2-0efbbc4b568d"`
	LoginID            string                            `json:"login_id,omitempty" example:"user@gmail.com"`
	CronJobID          uint                              `json:"cron_job_id,omitempty" example:"57"`
	CredentialID       uint                              `json:"credential_id,omitempty" example:"12"`
	BackupItemCount    uint                              `json:"backup_item_count,omitempty" example:"1988"`
	OAuthHolderEmail   string                            `json:"oauth_holder_email,omitempty" example:"user@gmail.com"`
	MissingPermissions []RestoreMissingPermissionSwagger `json:"missing_permissions,omitempty"`
	DelegationSetup    map[string]interface{}            `json:"delegation_setup,omitempty" swaggertype:"object"`
	ReconnectHint      string                            `json:"reconnect_hint,omitempty"`
	GrantedScopes      []string                          `json:"granted_scopes,omitempty"`
	RequiredDWDScopes  []string                          `json:"required_dwd_scopes,omitempty"`
	Message            string                            `json:"message,omitempty"`
}

// RestoreAllQueuedSwaggerResponse is returned on 202 from POST /restore/all.
type RestoreAllQueuedSwaggerResponse struct {
	JobID   uint   `json:"job_id" example:"2"`
	Status  string `json:"status" example:"queued" enums:"queued,running,completed,partial_completed,failed,cancelled"`
	Message string `json:"message" example:"restore job queued"`
}

// RestoreJobInputDataSwagger is input_data on restore job list/detail rows.
type RestoreJobInputDataSwagger struct {
	CredentialID int    `json:"credential_id,omitempty" example:"12"`
	CronJobID    int    `json:"cron_job_id,omitempty" example:"57"`
	ProjectID    string `json:"project_id,omitempty" example:"37159d9b-6f3c-4c38-bfe2-0efbbc4b568d"`
}

// RestoreJobListItemSwagger is one job in GET /restore/jobs success[] (metadata only; no progress counters).
type RestoreJobListItemSwagger struct {
	ID            uint                       `json:"ID" example:"2"`
	Method        string                     `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_calendar,google_contacts"`
	LoginID       string                     `json:"login_id" example:"user@gmail.com"`
	Status        string                     `json:"status" example:"running" enums:"queued,running,completed,partial_completed,failed,cancelled"`
	Message       string                     `json:"message" example:"restore in progress"`
	MessageStatus string                     `json:"message_status" example:"info" enums:"info,warning,error"`
	AccountType   string                     `json:"account_type" example:"personal" enums:"personal,employee_workspace,admin_workspace"`
	AuthMode      string                     `json:"auth_mode" example:"oauth" enums:"oauth,dwd"`
	InputData     RestoreJobInputDataSwagger `json:"input_data"`
	CreatedAt     time.Time                  `json:"created_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

// RestoreJobListSwaggerResponse is returned from GET /restore/jobs (autosync-style envelope).
type RestoreJobListSwaggerResponse struct {
	Message string                      `json:"message" example:"Restore jobs list"`
	Success []RestoreJobListItemSwagger `json:"success"`
	Failed  []interface{}               `json:"failed" swaggertype:"array,object"`
}

// RestoreJobDetailSwagger is one job in GET /restore/job/{job_id} success[0] (includes progress).
type RestoreJobDetailSwagger struct {
	ID              uint                       `json:"ID" example:"2"`
	Method          string                     `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_calendar,google_contacts"`
	LoginID         string                     `json:"login_id" example:"user@gmail.com"`
	Status          string                     `json:"status" example:"running" enums:"queued,running,completed,partial_completed,failed,cancelled"`
	Message         string                     `json:"message" example:"restore in progress"`
	MessageStatus   string                     `json:"message_status" example:"info" enums:"info,warning,error"`
	AccountType     string                     `json:"account_type" example:"personal" enums:"personal,employee_workspace,admin_workspace"`
	AuthMode        string                     `json:"auth_mode" example:"oauth" enums:"oauth,dwd"`
	InputData       RestoreJobInputDataSwagger `json:"input_data"`
	Total           uint                       `json:"total" example:"1988"`
	Processed       uint                       `json:"processed" example:"249"`
	Failed          uint                       `json:"failed" example:"0"`
	CursorID        uint                       `json:"cursor_id" example:"7807"`
	ProgressPercent float64                    `json:"progress_percent" example:"12.5"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
	CancelledAt     *time.Time                 `json:"cancelled_at,omitempty"`
}

// RestoreJobDetailSwaggerResponse is returned from GET /restore/job/{job_id}.
type RestoreJobDetailSwaggerResponse struct {
	Message string                    `json:"message" example:"Restore Account Details"`
	Success []RestoreJobDetailSwagger `json:"success"`
	Failed  []interface{}             `json:"failed" swaggertype:"array,object"`
}

// RestoreLiveTaskSwagger is one running batch on a live restore job.
type RestoreLiveTaskSwagger struct {
	StartTime  *time.Time `json:"start_time,omitempty"`
	Status     string     `json:"status" example:"running" enums:"running,retrying,completed,failed"`
	BatchIndex uint       `json:"batch_index" example:"0"`
}

// RestoreLiveJobSwagger is one item in GET /restore/live success[].
type RestoreLiveJobSwagger struct {
	ID              uint                     `json:"id" example:"2"`
	Method          string                   `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_calendar,google_contacts"`
	LoginID         string                   `json:"login_id" example:"user@gmail.com"`
	Status          string                   `json:"status" example:"running" enums:"queued,running,completed,partial_completed,failed,cancelled"`
	Message         string                   `json:"message" example:"restore in progress"`
	MessageStatus   string                   `json:"message_status" example:"info" enums:"info,warning,error"`
	Total           uint                     `json:"total" example:"1988"`
	Processed       uint                     `json:"processed" example:"249"`
	Failed          uint                     `json:"failed" example:"0"`
	CursorID        uint                     `json:"cursor_id" example:"7807"`
	ProgressPercent float64                  `json:"progress_percent" example:"12.5"`
	Tasks           []RestoreLiveTaskSwagger `json:"tasks"`
}

// RestoreLiveSwaggerResponse is returned from GET /restore/live.
type RestoreLiveSwaggerResponse struct {
	Message string                  `json:"message" example:"Active Restore Jobs List"`
	Success []RestoreLiveJobSwagger `json:"success"`
	Failed  []interface{}           `json:"failed" swaggertype:"array,object"`
}

// RestoreCancelSwaggerResponse is returned from POST /restore/job/{job_id}/cancel.
type RestoreCancelSwaggerResponse struct {
	Message string `json:"message" example:"restore cancelled"`
	JobID   uint   `json:"job_id" example:"2"`
}

// RestoreDeadItemSwagger is one DLQ row from GET /restore/job/{job_id}/dead-items.
type RestoreDeadItemSwagger struct {
	RestoreJobID uint   `json:"restore_job_id" example:"2"`
	ObjectKey    string `json:"object_key" example:"user@gmail.com/path/file"`
	ErrorCode    string `json:"error_code" example:"api_error"`
	Reason       string `json:"reason" example:"google api returned 403"`
}

// RestoreDeadItemsSwaggerResponse is returned from GET /restore/job/{job_id}/dead-items.
type RestoreDeadItemsSwaggerResponse struct {
	Items []RestoreDeadItemSwagger `json:"items"`
}
