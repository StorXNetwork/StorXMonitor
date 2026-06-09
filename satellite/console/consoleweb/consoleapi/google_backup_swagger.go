// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

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
// services: gmail, drive, photos, contacts, calendar. interval: 1h, 6h, nightly (daily/24h/7d map to nightly).
// emails: required for corporate gmail when backing up delegated mailboxes.
type CreateGoogleBackupAutoSyncJobsSwaggerRequest struct {
	Services []string `json:"services" binding:"required" example:"gmail,drive"`
	Interval string   `json:"interval" binding:"required" example:"6h"`
	On       string   `json:"on" example:""`
	Emails   []string `json:"emails,omitempty" example:"billing@salestalker.com,support@salestalker.com"`
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

// GoogleBackupUsersGroupsDomainsSwaggerResponse is returned from GET .../auto-sync/users-groups/domains.
type GoogleBackupUsersGroupsDomainsSwaggerResponse struct {
	Domains []string `json:"domains" example:"acme.com,gmail.com"`
}

// GoogleBackupUsersGroupsServiceSwagger is one service row on a Users & Groups entity (all services shown per email even when method filter is set).
type GoogleBackupUsersGroupsServiceSwagger struct {
	Method string `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_contacts,google_calendar"`
	Active bool   `json:"active" example:"true"`
}

// GoogleBackupUsersGroupsEntitySwagger is one email row on the Users & Groups table.
type GoogleBackupUsersGroupsEntitySwagger struct {
	Name     string                                `json:"name" example:"s.jenkins"`
	Email    string                                `json:"email" example:"s.jenkins@acme.com"`
	PolicyID int                                   `json:"policy_id" example:"5"`
	Services []GoogleBackupUsersGroupsServiceSwagger `json:"services"`
}

// GoogleBackupUsersGroupsPaginationSwagger is pagination metadata on the Users & Groups listing.
type GoogleBackupUsersGroupsPaginationSwagger struct {
	Limit      int `json:"limit" example:"10"`
	Offset     int `json:"offset" example:"0"`
	Page       int `json:"page" example:"1"`
	TotalPages int `json:"total_pages" example:"3"`
	TotalCount int `json:"total_count" example:"25"`
}

// GoogleBackupUsersGroupsSwaggerResponse is returned from GET .../auto-sync/users-groups.
type GoogleBackupUsersGroupsSwaggerResponse struct {
	PolicyLink string                                   `json:"policy_link" example:"/auto-sync/policy"`
	Entities   []GoogleBackupUsersGroupsEntitySwagger   `json:"entities"`
	Pagination GoogleBackupUsersGroupsPaginationSwagger `json:"pagination"`
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
