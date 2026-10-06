// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeMicrosoftBackupServices(t *testing.T) {
	tests := []struct {
		name     string
		services []string
		want     []string
		wantErr  string
	}{
		{
			name:     "outlook aliases mail",
			services: []string{"mail", "calendar", "contacts"},
			want:     []string{"outlook", "calendar", "contacts"},
		},
		{
			name:     "onedrive",
			services: []string{"onedrive"},
			want:     []string{"onedrive"},
		},
		{
			name:     "sharepoint",
			services: []string{"sharepoint"},
			want:     []string{"sharepoint"},
		},
		{
			name:     "mail plus onedrive",
			services: []string{"outlook", "onedrive"},
			want:     []string{"outlook", "onedrive"},
		},
		{
			name:     "rejects google services",
			services: []string{"gmail"},
			wantErr:  "unsupported service",
		},
		{
			name:     "duplicate after normalize",
			services: []string{"mail", "outlook"},
			wantErr:  "duplicate service",
		},
		{
			name:     "empty",
			services: nil,
			wantErr:  "at least one service is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMicrosoftBackupServices(tt.services, false)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCreateMicrosoftBackupAutoSyncJobsRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     CreateMicrosoftBackupAutoSyncJobsRequest
		wantErr string
	}{
		{
			name: "valid with interval",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"outlook"},
				MicrosoftEmail: "user@contoso.com",
				Interval:       "daily",
			},
		},
		{
			name: "rejects jwt refresh_token",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"outlook"},
				MicrosoftEmail: "user@contoso.com",
				RefreshToken:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb",
				Interval:       "daily",
			},
			wantErr: "looks like an access/id token",
		},
		{
			name: "missing schedule without policy",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"outlook"},
				MicrosoftEmail: "user@contoso.com",
			},
			wantErr: "interval is required",
		},
		{
			name: "policy_id skips interval",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"calendar"},
				MicrosoftEmail: "user@contoso.com",
				PolicyID:       intPtr(55),
			},
		},
		{
			name: "sharepoint requires sites",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"sharepoint"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
			},
			wantErr: "sites is required",
		},
		{
			name: "sharepoint all_tenant skips sites",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"sharepoint"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				BackupScope:    "all_tenant",
			},
		},
		{
			name: "teams requires teams array",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"teams"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
			},
			wantErr: "teams is required",
		},
		{
			name: "teams with team_id",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"teams"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				Teams:          []TeamsOnboardingInput{{TeamID: "team-1"}},
			},
		},
		{
			name: "teams all_tenant without teams array",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"teams"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				BackupScope:    "all_tenant",
			},
		},
		{
			name: "invalid backup_scope",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"teams"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				BackupScope:    "bogus",
			},
			wantErr: "unsupported backup_scope",
		},
		{
			name: "groups requires groups array",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"groups"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
			},
			wantErr: "groups is required",
		},
		{
			name: "groups with group_id",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"groups"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				Groups:         []GroupsOnboardingInput{{GroupID: "group-1"}},
			},
		},
		{
			name: "groups all_tenant without groups array",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"groups"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				BackupScope:    "all_tenant",
			},
		},
		{
			name: "sharepoint with site_id",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				Services:       []string{"sharepoint"},
				MicrosoftEmail: "admin@contoso.com",
				Interval:       "daily",
				Sites:          []SharePointSiteOnboardingInput{{SiteID: "contoso.sharepoint.com,abc,def"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCreateMicrosoftBackupAutoSyncJobsRequest_backupScopePayload(t *testing.T) {
	req := CreateMicrosoftBackupAutoSyncJobsRequest{
		Services:       []string{"teams"},
		MicrosoftEmail: "admin@contoso.com",
		Interval:       "daily",
		BackupScope:    "all_tenant",
	}
	require.NoError(t, req.Validate())

	// Payload assembly is inside CreateMicrosoftBackupAutoSyncJobs; verify field survives validation.
	require.Equal(t, "all_tenant", req.BackupScope)
	require.Equal(t, MicrosoftBackupModeOrganization, req.BackupMode)
}

func TestCreateMicrosoftBackupAutoSyncJobsRequest_backupMode(t *testing.T) {
	tests := []struct {
		name         string
		req          CreateMicrosoftBackupAutoSyncJobsRequest
		wantMode     string
		wantAuthMode string
		wantErr      string
	}{
		{
			name:         "omitted defaults to self",
			req:          CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, Interval: "daily"},
			wantMode:     MicrosoftBackupModeSelf,
			wantAuthMode: microsoftAuthModeDelegated,
		},
		{
			name:         "omitted with all_users defaults to organization",
			req:          CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, Interval: "daily", AllUsers: true},
			wantMode:     MicrosoftBackupModeOrganization,
			wantAuthMode: microsoftAuthModeApplication,
		},
		{
			name:         "explicit organization with user_ids",
			req:          CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, Interval: "daily", BackupMode: "Organization", UserIDs: []string{" a ", "A", "b"}},
			wantMode:     MicrosoftBackupModeOrganization,
			wantAuthMode: microsoftAuthModeApplication,
		},
		{
			name:    "self rejects all_users",
			req:     CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, Interval: "daily", BackupMode: "self", AllUsers: true},
			wantErr: "backup_mode=self only backs up your own mailbox",
		},
		{
			name:    "self rejects org units",
			req:     CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, BackupMode: "self", PolicyScope: "org_unit", OrgUnitSchedules: map[string]GoogleBackupOrgUnitSchedule{"/Sales": {Interval: "daily"}}},
			wantErr: "backup_mode=self only backs up your own mailbox",
		},
		{
			name:    "unknown mode",
			req:     CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, Interval: "daily", BackupMode: "tenant"},
			wantErr: "unsupported backup_mode",
		},
		{
			name: "org unit schedules carry services and schedule",
			req: CreateMicrosoftBackupAutoSyncJobsRequest{
				BackupMode:  "organization",
				PolicyScope: "org_unit",
				OrgUnitSchedules: map[string]GoogleBackupOrgUnitSchedule{
					"/Sales": {Interval: "daily", Services: []string{"mail", "onedrive"}},
				},
			},
			wantMode:     MicrosoftBackupModeOrganization,
			wantAuthMode: microsoftAuthModeApplication,
		},
		{
			name:    "org unit scope requires schedules",
			req:     CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, BackupMode: "organization", PolicyScope: "org_unit"},
			wantErr: "org_unit_schedules is required",
		},
		{
			name:    "org unit schedule rejects google service",
			req:     CreateMicrosoftBackupAutoSyncJobsRequest{BackupMode: "organization", PolicyScope: "org_unit", OrgUnitSchedules: map[string]GoogleBackupOrgUnitSchedule{"/Sales": {Interval: "daily", Services: []string{"gmail"}}}},
			wantErr: "unsupported service",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantMode, tt.req.BackupMode)
			require.Equal(t, tt.wantAuthMode, tt.req.authMode())
		})
	}

	req := CreateMicrosoftBackupAutoSyncJobsRequest{Services: []string{"outlook"}, Interval: "daily", BackupMode: "organization", UserIDs: []string{" a ", "A", "b"}}
	require.NoError(t, req.Validate())
	require.Equal(t, []string{"a", "b"}, req.UserIDs)
}

func TestUpdateBackupAutoSyncJobsByProjectRequest_microsoftEmailPayload(t *testing.T) {
	req := UpdateBackupAutoSyncJobsByProjectRequest{
		ProjectID:      "proj-1",
		MicrosoftEmail: "user@contoso.com",
		RefreshToken:   "rt-1",
		Active:         boolPtr(true),
	}
	body, err := req.backupToolsPayload()
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, "proj-1", got["project_id"])
	require.Equal(t, "user@contoso.com", got["google_email"])
	require.Equal(t, "rt-1", got["refresh_token"])
	require.Equal(t, true, got["active"])
}

func TestUpdateBackupAutoSyncJobsByProjectRequest_microsoftCodeValidate(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateBackupAutoSyncJobsByProjectRequest
		wantErr string
	}{
		{
			name: "microsoft email + code ok",
			req: UpdateBackupAutoSyncJobsByProjectRequest{
				ProjectID:      "proj-1",
				MicrosoftEmail: "user@outlook.com",
				Code:           "auth-code",
			},
		},
		{
			name: "code without mailbox rejected",
			req: UpdateBackupAutoSyncJobsByProjectRequest{
				ProjectID: "proj-1",
				Code:      "auth-code",
			},
			wantErr: "google_email or microsoft_email is required when code is set",
		},
		{
			name: "both emails with code rejected",
			req: UpdateBackupAutoSyncJobsByProjectRequest{
				ProjectID:      "proj-1",
				GoogleEmail:    "a@gmail.com",
				MicrosoftEmail: "b@outlook.com",
				Code:           "auth-code",
			},
			wantErr: "set only one of google_email or microsoft_email when code is set",
		},
		{
			name: "google email + code ok (same grant shape as microsoft)",
			req: UpdateBackupAutoSyncJobsByProjectRequest{
				ProjectID:   "proj-1",
				GoogleEmail: "user@gmail.com",
				Code:        "auth-code",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
