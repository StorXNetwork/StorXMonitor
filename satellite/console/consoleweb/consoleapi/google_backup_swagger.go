// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// Swagger models for Google Backup and related auth routes (used by swag only).

// GoogleBackupOnboardingSwagger is the onboarding block on GET /auth/google-backup responses.
type GoogleBackupOnboardingSwagger struct {
	OnboardingStart  bool   `json:"onboardingStart" example:"true"`
	OnboardingEnd    bool   `json:"onboardingEnd" example:"false"`
	OnboardingStep   string `json:"onboardingStep" example:"GoogleBackupPending"`
	OnboardingStatus string `json:"onboarding_status" example:"pending" enums:"pending,in_progress,completed"`
}

// GoogleBackupAuthSuccess is returned from GET /auth/google-backup on success.
type GoogleBackupAuthSuccess struct {
	Success      bool                          `json:"success" example:"true"`
	Action       string                        `json:"action" example:"registered" enums:"registered,logged_in"`
	Onboarding   GoogleBackupOnboardingSwagger `json:"onboarding"`
	GoogleBackup map[string]interface{}        `json:"google_backup,omitempty" swaggertype:"object"`
}

// GoogleBackupAuthError is returned when GET /auth/google-backup fails.
type GoogleBackupAuthError struct {
	Success bool   `json:"success" example:"false"`
	Error   string `json:"error" example:"Error getting token from Google!"`
}

// CreateGoogleBackupAutoSyncJobsSwaggerRequest is the UI → satellite body for job create.
// services: gmail, drive, photos, contacts, calendar.
// interval/on: forwarded when policy_id is absent; omitted when policy_id is set (schedule from policy). Required/optional rules are enforced by Backup-Tools.
// emails: required for corporate gmail when backing up delegated mailboxes.
type CreateGoogleBackupAutoSyncJobsSwaggerRequest struct {
	Services   []string `json:"services" binding:"required" example:"gmail,drive"`
	Interval   string   `json:"interval,omitempty" example:"6h"`
	On         string   `json:"on,omitempty" example:"12am"`
	Emails     []string `json:"emails,omitempty" example:"billing@salestalker.com,support@salestalker.com"`
	PolicyID   *int     `json:"policy_id,omitempty" example:"50"`
	PolicyName string   `json:"policy_name,omitempty" example:"New team policy"`
}

// UpdateGoogleBackupAutoSyncJobSwaggerRequest is the UI body for PUT .../auto-sync/jobs/{job_id} (active toggle only).
type UpdateGoogleBackupAutoSyncJobSwaggerRequest struct {
	Active bool `json:"active" binding:"required" example:"true"`
}

// UpdateGoogleBackupAutoSyncJobsByProjectSwaggerRequest is the UI body for PUT .../auto-sync/jobs/project.
// Requires project_id and google_email. Send code OR refresh_token for token updates (Satellite exchanges code; Backup-Tools never receives code).
type UpdateGoogleBackupAutoSyncJobsByProjectSwaggerRequest struct {
	ProjectID    string `json:"project_id" binding:"required" example:"00000000-0000-0000-0000-000000000000"`
	GoogleEmail  string `json:"google_email" binding:"required" example:"user@gmail.com"`
	Code         string `json:"code,omitempty" example:""`
	StorxToken   string `json:"storx_token,omitempty" example:"<storx access grant>"`
	RefreshToken string `json:"refresh_token,omitempty" example:"<google refresh token>"`
	Active       *bool  `json:"active,omitempty" example:"true"`
}

// SwaggerErrorResponse is a generic API error body.
type SwaggerErrorResponse struct {
	Error string `json:"error" example:"error message"`
}

// BackupToolsJSONResponse is an opaque Backup-Tools JSON payload (passthrough).
type BackupToolsJSONResponse map[string]interface{}

// GoogleBackupConnectSwaggerRequest is the body for POST /google-backup/connect.
type GoogleBackupConnectSwaggerRequest struct {
	Code string `json:"code" binding:"required" example:"4/0AeanS..."`
}

// GoogleBackupConnectSwaggerResponse is returned after connecting Google for backup.
type GoogleBackupConnectSwaggerResponse struct {
	Success      bool                   `json:"success" example:"true"`
	GoogleEmail  string                 `json:"google_email" example:"user@gmail.com"`
	Created      bool                   `json:"created" example:"true"`
	GoogleBackup map[string]interface{} `json:"google_backup,omitempty" swaggertype:"object"`
}

// GoogleBackupDomainUsersSwaggerResponse is returned from GET /google-backup/domain-users.
type GoogleBackupDomainUsersSwaggerResponse struct {
	Success      bool                   `json:"success" example:"true"`
	GoogleBackup map[string]interface{} `json:"google_backup,omitempty" swaggertype:"object"`
}

// GoogleBackupAutoSyncJobServiceStatsSwagger is per-service job counts on the Services Update page.
type GoogleBackupAutoSyncJobServiceStatsSwagger struct {
	Method       string `json:"method" example:"gmail"`
	TotalJobs    int    `json:"total_jobs" example:"4"`
	ActiveJobs   int    `json:"active_jobs" example:"3"`
	DeactiveJobs int    `json:"deactive_jobs" example:"1"`
}

// GoogleBackupAutoSyncJobServicesSwaggerResponse is returned from GET .../auto-sync/jobs/services.
type GoogleBackupAutoSyncJobServicesSwaggerResponse struct {
	Message  string                                       `json:"message" example:"Connected autosync services"`
	Services []GoogleBackupAutoSyncJobServiceStatsSwagger `json:"services"`
}

// GoogleBackupAutoSyncLiveTaskSwagger is one running/failed task on a live backup job.
type GoogleBackupAutoSyncLiveTaskSwagger struct {
	StartTime *time.Time `json:"start_time,omitempty" example:"2026-06-17T10:30:00Z"`
	Status    string     `json:"status" example:"running" enums:"running,failed"`
}

// GoogleBackupAutoSyncLiveJobSwagger is one job in GET .../auto-sync/live data[].
type GoogleBackupAutoSyncLiveJobSwagger struct {
	ID            uint                                  `json:"id" example:"12"`
	Name          string                                `json:"name" example:"user@example.com"`
	Method        string                                `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_contacts,google_calendar"`
	Message       string                                `json:"message" example:"Backup in progress..."`
	MessageStatus string                                `json:"message_status" example:"info" enums:"info,warning,error"`
	Tasks         []GoogleBackupAutoSyncLiveTaskSwagger `json:"tasks"`
}

// GoogleBackupAutoSyncLiveSwaggerResponse is returned from GET .../auto-sync/live (Backup-Tools passthrough).
type GoogleBackupAutoSyncLiveSwaggerResponse struct {
	Message string                               `json:"message" example:"Active Automatic Backup Accounts List"`
	Data    []GoogleBackupAutoSyncLiveJobSwagger `json:"data"`
}

// AutosyncJobListFilter is URL-encoded JSON for GET .../auto-sync/jobs?filter=...
// Build: encodeURIComponent(JSON.stringify({ method: 'gmail', active: true }))
//
// UI mapping:
//   - method (Service dropdown): gmail, google_drive, google_photos, google_calendar, google_contacts
//   - active (Active/Inactive toggle): true / false — user on/off; not the same as status
//   - status (Success/Failed/Running): success, failed, in_progress, in_queue, created — last run result
//   - name (Search bar): partial email text (e.g. jenkins, user@gmail.com). No separate search param on job list.
//   - project_id, policy_id, sync_type: optional Backup-Tools filters (combinable with the above).
type AutosyncJobListFilter struct {
	Method    string `json:"method,omitempty" example:"gmail" enums:"gmail,google_drive,google_photos,google_calendar,google_contacts"`
	Active    *bool  `json:"active,omitempty" example:"true"`
	Status    string `json:"status,omitempty" example:"failed" enums:"success,failed,in_progress,in_queue,created"`
	Name      string `json:"name,omitempty" example:"dhavalder@gmail.com"`
	ProjectID string `json:"project_id,omitempty" example:"00000000-0000-0000-0000-000000000000"`
	PolicyID  *int   `json:"policy_id,omitempty" example:"37"`
	SyncType  string `json:"sync_type,omitempty" example:"daily" enums:"daily,weekly,monthly"`
}

// AutosyncJobInputDataSwagger is input_data on a Backup-Tools auto-sync job.
type AutosyncJobInputDataSwagger struct {
	Email        string `json:"email" example:"dhavalder93@gmail.com"`
	CredentialID int    `json:"credential_id" example:"12"`
}

// AutosyncJobSwagger is one job in Backup-Tools success[] (GET/PUT by id returns success[0]).
type AutosyncJobSwagger struct {
	ID              int                         `json:"ID" example:"57"`
	Name            string                      `json:"name" example:"dhavalder93@gmail.com"`
	Method          string                      `json:"method" example:"gmail"`
	Active          bool                        `json:"active" example:"false"`
	SyncType        string                      `json:"sync_type" example:"daily"`
	Interval        string                      `json:"interval" example:"3h"`
	On              string                      `json:"on" example:""`
	PolicyID        int                         `json:"policy_id" example:"37"`
	Message         string                      `json:"message" example:"Backup scheduled"`
	MessageStatus   string                      `json:"message_status" example:"info"`
	LastRun         interface{}                 `json:"last_run" swaggertype:"object"`
	InputData       AutosyncJobInputDataSwagger `json:"input_data"`
	TaskMemory      map[string]interface{}      `json:"task_memory" swaggertype:"object"`
	Autodeactivated bool                        `json:"autodeactivated" example:"false"`
	FailurePeriods  int                         `json:"failure_periods" example:"0"`
}

// AutosyncJobDetailResponse is returned from GET/PUT .../auto-sync/jobs/{job_id} (passthrough from Backup-Tools).
type AutosyncJobDetailResponse struct {
	Message string               `json:"message" example:"Automatic Backup Account Details"`
	Success []AutosyncJobSwagger `json:"success"`
	Failed  []interface{}        `json:"failed" swaggertype:"array,object"`
}

// AutosyncJobListResponse is returned from GET .../auto-sync/jobs?filter=... (passthrough from Backup-Tools).
type AutosyncJobListResponse struct {
	Message string               `json:"message" example:"Automatic backup jobs"`
	Success []AutosyncJobSwagger `json:"success"`
	Failed  []interface{}        `json:"failed" swaggertype:"array,object"`
}

// AutosyncJobListFilterExamples documents example filter JSON values for the job list UI.
type AutosyncJobListFilterExamples struct {
	AllFields      AutosyncJobListFilter                      `json:"all_fields"`
	ByMethod       AutosyncJobListFilterByMethodExample       `json:"by_method"`
	ByActiveStatus AutosyncJobListFilterByActiveStatusExample `json:"by_active_status"`
	ByName         AutosyncJobListFilterByNameExample         `json:"by_name"`
	Combined       AutosyncJobListFilterCombinedExample       `json:"combined"`
}

// AutosyncJobListFilterByMethodExample is filter example `{"method":"gmail"}`.
type AutosyncJobListFilterByMethodExample struct {
	Method string `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_calendar,google_contacts"`
}

// AutosyncJobListFilterByActiveStatusExample is filter example `{"active":true,"status":"failed"}`.
type AutosyncJobListFilterByActiveStatusExample struct {
	Active *bool  `json:"active" example:"true"`
	Status string `json:"status" example:"failed" enums:"success,failed,in_progress,in_queue,created"`
}

// AutosyncJobListFilterByNameExample is filter example `{"name":"dhavalder@gmail.com"}`.
type AutosyncJobListFilterByNameExample struct {
	Name string `json:"name" example:"dhavalder@gmail.com"`
}

// AutosyncJobListFilterCombinedExample is filter example `{"method":"gmail","name":"jenkins","active":true,"status":"success"}`.
type AutosyncJobListFilterCombinedExample struct {
	Method string `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_calendar,google_contacts"`
	Name   string `json:"name" example:"jenkins"`
	Active *bool  `json:"active" example:"true"`
	Status string `json:"status" example:"success" enums:"success,failed,in_progress,in_queue,created"`
}

// AutoSyncJobListFilterSchema exposes AutosyncJobListFilter in Swagger definitions (not registered on server).
//
// @Summary      Auto-sync job list filter schema
// @Description  **Not a live route.** Documents `AutosyncJobListFilter` and four filter examples for `GET /api/v0/google-backup/auto-sync/jobs?filter=` (URL-encoded JSON). UI: method=Service dropdown; active=on/off toggle; status=last run result; name=search bar (partial email).
// @Tags         google-backup
// @Produce      json
// @Success      200  {object}  AutosyncJobListFilterExamples
// @Router       /google-backup/auto-sync/jobs/filter-schema [get]
func AutoSyncJobListFilterSchema() {}
