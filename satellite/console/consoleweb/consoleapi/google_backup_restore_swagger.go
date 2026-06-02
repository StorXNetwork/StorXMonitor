// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// Swagger models for Google Backup restore proxy (Backup-Tools /google-auth, /restore/*, /google/* manual restore).

// GoogleBackupAuthSwaggerRequest is the UI body for POST /google-backup/google-auth.
type GoogleBackupAuthSwaggerRequest struct {
	GoogleKey string `json:"google_key" binding:"required" example:"<Google OAuth id_token or access_token>"`
}

// GoogleBackupAuthSwaggerResponse is returned from Backup-Tools POST /google-auth (passthrough).
type GoogleBackupAuthSwaggerResponse struct {
	GoogleAuth string `json:"google-auth" example:"eyJhbGciOiJIUzI1NiIs..."`
}

// GoogleBackupRestoreAllSwaggerRequest starts async restore-all on Backup-Tools.
type GoogleBackupRestoreAllSwaggerRequest struct {
	Service          string `json:"service" binding:"required" example:"drive"`
	LoginID          string `json:"login_id" binding:"required" example:"user@gmail.com"`
	StorxAccessGrant string `json:"storx_access_grant" binding:"required" example:"<storx access grant>"`
	GoogleAuth       string `json:"google_auth" binding:"required" example:"<JWT from POST /google-backup/google-auth>"`
}

// GoogleBackupManualRestoreSwaggerRequest is the UI body for batch manual restore (≤10 base64 vault keys).
type GoogleBackupManualRestoreSwaggerRequest struct {
	StorxAccessGrant string   `json:"storx_access_grant" binding:"required" example:"<storx access grant>"`
	GoogleAuth       string   `json:"google_auth" binding:"required" example:"<JWT from POST /google-backup/google-auth>"`
	Keys             []string `json:"keys" binding:"required" example:"dXNlckBnbWFpbC5jb20vcGF0aC9maWxl"`
}
