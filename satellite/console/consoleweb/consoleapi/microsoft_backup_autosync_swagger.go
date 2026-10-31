// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// CreateMicrosoftBackupAutoSyncJobsSwaggerRequest is the UI body for POST /microsoft-backup/auto-sync/job.
type CreateMicrosoftBackupAutoSyncJobsSwaggerRequest struct {
	// CredentialID selects the Microsoft account; required when several accounts are connected.
	CredentialID string `json:"credential_id,omitempty" example:"6f1c2a1e-4c1b-4d2a-9c3e-2f6a7b8c9d0e"`
	// TenantID is the tenant connected for backup (POST /microsoft-backup/tenants/{tid}/connect); required.
	TenantID       string                        `json:"tenant_id,omitempty" example:"72f988bf-86f1-41af-91ab-2d7cd011db47"`
	Services       []string                      `json:"services" binding:"required" example:"outlook,calendar,contacts,onedrive,sharepoint,teams"`
	MicrosoftEmail string                        `json:"microsoft_email" example:"user@contoso.com"`
	ProjectID      string                        `json:"project_id" example:"00000000-0000-0000-0000-000000000001"`
	StorxToken     string                        `json:"storx_token,omitempty"`
	Emails         []string                      `json:"emails,omitempty" example:"user@contoso.com"`
	Sites          []SharePointSiteSwaggerInput  `json:"sites,omitempty"`
	Teams          []TeamsOnboardingSwaggerInput `json:"teams,omitempty"`
	PolicyID       *int                          `json:"policy_id,omitempty"`
	PolicyName     string                        `json:"policy_name,omitempty" example:"Outlook defaults"`
	Interval       string                        `json:"interval,omitempty" example:"daily"`
	On             string                        `json:"on,omitempty" example:"12am"`
	BackupScope    string                        `json:"backup_scope,omitempty" example:"all_tenant"`
	// BackupMode self = delegated own-mailbox backup; organization = app-only tenant backup (no refresh token sent).
	BackupMode string   `json:"backup_mode,omitempty" enums:"self,organization" example:"organization"`
	AllUsers   bool     `json:"all_users,omitempty"`
	UserIDs    []string `json:"user_ids,omitempty"`
}

// SharePointSiteSwaggerInput selects a SharePoint site for outlook_sharepoint jobs.
type SharePointSiteSwaggerInput struct {
	SiteID  string `json:"site_id" example:"contoso.sharepoint.com,abc123,def456"`
	SiteURL string `json:"site_url" example:"https://contoso.sharepoint.com/sites/HR"`
}

// TeamsOnboardingSwaggerInput selects a Team for outlook_teams jobs.
type TeamsOnboardingSwaggerInput struct {
	TeamID     string   `json:"team_id" example:"00000000-0000-0000-0000-000000000001"`
	TeamName   string   `json:"team_name,omitempty" example:"Engineering"`
	ChannelIDs []string `json:"channel_ids,omitempty"`
}
