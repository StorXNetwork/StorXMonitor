// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// Swagger models for Backup-Tools GET /autosync/dashboard-alerts (proxied via Users & Groups).

// GoogleBackupDashboardAlertsSwaggerResponse is returned from GET /google-backup/users-groups/dashboard-alerts.
type GoogleBackupDashboardAlertsSwaggerResponse struct {
	ReAuthRequired          GoogleBackupDashboardAlertSectionSwagger `json:"re_auth_required"`
	PausedBackups           GoogleBackupDashboardAlertSectionSwagger `json:"paused_backups"`
	NewConnectedAccounts24h GoogleBackupDashboardAlertSectionSwagger `json:"new_connected_accounts_24h"`
}

// GoogleBackupDashboardAlertSectionSwagger is one alert card: count plus mailbox rows.
type GoogleBackupDashboardAlertSectionSwagger struct {
	Count int                                   `json:"count" example:"2"`
	Items []GoogleBackupDashboardMailboxSwagger `json:"items"`
}

// GoogleBackupDashboardMailboxSwagger is one mailbox row with nested services.
type GoogleBackupDashboardMailboxSwagger struct {
	Email            string                                  `json:"email" example:"john@gmail.com"`
	AccountType      string                                  `json:"account_type" example:"individual" enums:"corporate,individual"`
	CredentialStatus string                                  `json:"credential_status" example:"re_auth_required" enums:"healthy,re_auth_required"`
	ConnectedAt      *time.Time                              `json:"connected_at,omitempty" example:"2026-06-10T08:00:00Z"`
	Credential       GoogleBackupDashboardCredentialSwagger  `json:"credential"`
	Services         []GoogleBackupDashboardServiceSwagger   `json:"services"`
}

// GoogleBackupDashboardCredentialSwagger is Google OAuth reconnect state for the mailbox.
type GoogleBackupDashboardCredentialSwagger struct {
	CredentialID             uint `json:"credential_id,omitempty" example:"12"`
	NeedsReconnectGoogleAuth bool `json:"needs_reconnect_google_auth" example:"true"`
}

// GoogleBackupDashboardServiceSwagger is one backup job under a mailbox.
type GoogleBackupDashboardServiceSwagger struct {
	JobID     uint  `json:"job_id,omitempty" example:"101"`
	Method    string `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_contacts,google_calendar"`
	Connected bool  `json:"connected" example:"true"`
	Active    *bool `json:"active,omitempty" example:"true"`
}
