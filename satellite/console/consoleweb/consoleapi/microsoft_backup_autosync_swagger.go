// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// CreateMicrosoftBackupAutoSyncJobsSwaggerRequest is the UI body for POST .../auto-sync/job and .../backup/onboarding/jobs.
type CreateMicrosoftBackupAutoSyncJobsSwaggerRequest struct {
	Services        []string                        `json:"services" binding:"required" example:"outlook,calendar,contacts,onedrive,sharepoint,teams,groups"`
	MicrosoftEmail  string                          `json:"microsoft_email" example:"user@contoso.com"`
	ProjectID       string                          `json:"project_id" example:"00000000-0000-0000-0000-000000000001"`
	RefreshToken    string                          `json:"refresh_token"`
	StorxToken      string                          `json:"storx_token,omitempty"`
	Emails          []string                        `json:"emails,omitempty" example:"user@contoso.com"`
	Sites           []SharePointSiteSwaggerInput    `json:"sites,omitempty"`
	Teams           []TeamsOnboardingSwaggerInput   `json:"teams,omitempty"`
	Groups          []GroupsOnboardingSwaggerInput  `json:"groups,omitempty"`
	PolicyID        *int     `json:"policy_id,omitempty"`
	PolicyName      string   `json:"policy_name,omitempty" example:"Outlook defaults"`
	Interval        string   `json:"interval,omitempty" example:"daily"`
	On              string   `json:"on,omitempty" example:"12am"`
	SatelliteUserID string   `json:"satellite_user_id,omitempty"`
	BackupScope     string   `json:"backup_scope,omitempty" example:"all_tenant"`
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
