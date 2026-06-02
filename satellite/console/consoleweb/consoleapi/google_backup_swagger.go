// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// Swagger models for Google Backup and related auth routes (used by swag only).

// GoogleBackupRegisterSuccess is returned from register-google on success.
type GoogleBackupRegisterSuccess struct {
	Success      bool                   `json:"success" example:"true"`
	GoogleBackup map[string]interface{} `json:"google_backup,omitempty" swaggertype:"object"`
}

// GoogleOAuthCallbackError is an HTML error page body when OAuth callback fails (redirect flow).
type GoogleOAuthCallbackError struct {
	Message string `json:"message" example:"Authorization code not provided!"`
}

// GoogleOAuthJSONSuccess is returned from login-google when query json=true (existing SendResponse path).
type GoogleOAuthJSONSuccess struct {
	Success     bool   `json:"success" example:"true"`
	RedirectURL string `json:"redirect_url" example:"https://storx.io/"`
}

// GoogleOAuthJSONError is returned from login-google when query json=true and the callback fails.
type GoogleOAuthJSONError struct {
	Error       string `json:"error" example:"Error getting token from Google"`
	RedirectURL string `json:"redirect_url" example:"https://storx.io/login"`
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
	Success     bool   `json:"success" example:"true"`
	GoogleEmail string `json:"google_email" example:"user@gmail.com"`
	Created     bool   `json:"created" example:"true"`
}

// GoogleBackupDomainUsersSwaggerResponse matches register-google google_backup metadata (domain-users).
type GoogleBackupDomainUsersSwaggerResponse struct {
	Success      bool                   `json:"success" example:"true"`
	GoogleBackup map[string]interface{} `json:"google_backup,omitempty" swaggertype:"object"`
}
