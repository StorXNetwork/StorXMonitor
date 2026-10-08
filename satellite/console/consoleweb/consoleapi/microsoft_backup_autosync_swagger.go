// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// CreateMicrosoftBackupAutoSyncJobsSwaggerRequest is the UI body for POST .../auto-sync/job and .../backup/onboarding/jobs.
type CreateMicrosoftBackupAutoSyncJobsSwaggerRequest struct {
	// CredentialID selects the Microsoft account; required when several accounts are connected.
	CredentialID string `json:"credential_id,omitempty" example:"6f1c2a1e-4c1b-4d2a-9c3e-2f6a7b8c9d0e"`
	// TenantID is the tenant connected for backup (POST /microsoft-backup/tenants/{tid}/connect); required.
	TenantID        string                         `json:"tenant_id,omitempty" example:"72f988bf-86f1-41af-91ab-2d7cd011db47"`
	Services        []string                       `json:"services" binding:"required" example:"outlook,calendar,contacts,onedrive,sharepoint,teams,groups"`
	MicrosoftEmail  string                         `json:"microsoft_email" example:"user@contoso.com"`
	ProjectID       string                         `json:"project_id" example:"00000000-0000-0000-0000-000000000001"`
	RefreshToken    string                         `json:"refresh_token"`
	StorxToken      string                         `json:"storx_token,omitempty"`
	Emails          []string                       `json:"emails,omitempty" example:"user@contoso.com"`
	Sites           []SharePointSiteSwaggerInput   `json:"sites,omitempty"`
	Teams           []TeamsOnboardingSwaggerInput  `json:"teams,omitempty"`
	Groups          []GroupsOnboardingSwaggerInput `json:"groups,omitempty"`
	PolicyID        *int                           `json:"policy_id,omitempty"`
	PolicyName      string                         `json:"policy_name,omitempty" example:"Outlook defaults"`
	Interval        string                         `json:"interval,omitempty" example:"daily"`
	On              string                         `json:"on,omitempty" example:"12am"`
	SatelliteUserID string                         `json:"satellite_user_id,omitempty"`
	BackupScope     string                         `json:"backup_scope,omitempty" example:"all_tenant"`
	// BackupMode self = delegated own-mailbox backup; organization = app-only tenant backup (no refresh token sent).
	BackupMode       string                                     `json:"backup_mode,omitempty" enums:"self,organization" example:"organization"`
	AllUsers         bool                                       `json:"all_users,omitempty"`
	UserIDs          []string                                   `json:"user_ids,omitempty"`
	PolicyScope      string                                     `json:"policy_scope,omitempty" example:"org_unit"`
	EmailOrgUnits    map[string]string                          `json:"email_org_units,omitempty"`
	OrgUnitSchedules map[string]MicrosoftOrgUnitScheduleSwagger `json:"org_unit_schedules,omitempty"`
}

// MicrosoftOrgUnitScheduleSwagger is a per-org-unit schedule for policy_scope=org_unit.
type MicrosoftOrgUnitScheduleSwagger struct {
	PolicyName string   `json:"policy_name,omitempty" example:"Sales nightly"`
	Interval   string   `json:"interval" example:"daily"`
	On         string   `json:"on,omitempty" example:"12am"`
	Services   []string `json:"services,omitempty" example:"outlook,onedrive"`
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

// GroupsOnboardingSwaggerInput selects an M365 Group for outlook_groups jobs.
type GroupsOnboardingSwaggerInput struct {
	GroupID   string `json:"group_id" example:"00000000-0000-0000-0000-000000000002"`
	GroupName string `json:"group_name,omitempty" example:"HR Team"`
}
