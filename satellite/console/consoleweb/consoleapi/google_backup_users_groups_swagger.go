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
	Email            string                                 `json:"email" example:"john@gmail.com"`
	AccountType      string                                 `json:"account_type" example:"individual" enums:"corporate,individual"`
	CredentialStatus string                                 `json:"credential_status" example:"re_auth_required" enums:"healthy,re_auth_required"`
	ConnectedAt      *time.Time                             `json:"connected_at,omitempty" example:"2026-06-10T08:00:00Z"`
	Credential       GoogleBackupDashboardCredentialSwagger `json:"credential"`
	Services         []GoogleBackupDashboardServiceSwagger  `json:"services"`
}

// GoogleBackupUsersGroupsListSwaggerResponse is Backup-Tools GET /users-groups (proxied as-is).
type GoogleBackupUsersGroupsListSwaggerResponse struct {
	Entities   []GoogleBackupUsersGroupsEntitySwagger   `json:"entities"`
	OrgUnits   []string                                 `json:"org_units,omitempty" example:"/,/SAles"`
	Pagination GoogleBackupUsersGroupsPaginationSwagger `json:"pagination"`
}

// GoogleBackupUsersGroupsEntitySwagger is one mailbox row on Users & Groups.
type GoogleBackupUsersGroupsEntitySwagger struct {
	Name             string                                 `json:"name" example:"billing"`
	Email            string                                 `json:"email" example:"billing@salestalker.com"`
	AccountType      string                                 `json:"account_type" example:"corporate" enums:"corporate,individual"`
	OrgUnitPath      string                                 `json:"org_unit_path,omitempty" example:"/"`
	CredentialStatus string                                 `json:"credential_status" example:"healthy" enums:"healthy,re_auth_required"`
	Credential       GoogleBackupDashboardCredentialSwagger `json:"credential"`
	Services         []GoogleBackupDashboardServiceSwagger  `json:"services"`
}

// GoogleBackupUsersGroupsPaginationSwagger is list pagination.
type GoogleBackupUsersGroupsPaginationSwagger struct {
	Limit      int `json:"limit" example:"10"`
	Offset     int `json:"offset" example:"0"`
	Page       int `json:"page" example:"1"`
	TotalPages int `json:"total_pages" example:"1"`
	TotalCount int `json:"total_count" example:"2"`
}

// GoogleBackupDashboardCredentialSwagger is Google OAuth reconnect state for the mailbox.
type GoogleBackupDashboardCredentialSwagger struct {
	CredentialID             uint `json:"credential_id,omitempty" example:"12"`
	NeedsReconnectGoogleAuth bool `json:"needs_reconnect_google_auth" example:"true"`
}

// GoogleBackupDashboardServiceSwagger is one backup job under a mailbox.
type GoogleBackupDashboardServiceSwagger struct {
	JobID     uint   `json:"job_id,omitempty" example:"101"`
	Method    string `json:"method" example:"gmail" enums:"gmail,google_drive,google_photos,google_contacts,google_calendar"`
	Connected bool   `json:"connected" example:"true"`
	Active    *bool  `json:"active,omitempty" example:"true"`
}
