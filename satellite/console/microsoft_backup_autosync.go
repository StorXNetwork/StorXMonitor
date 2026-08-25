// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SharePointSiteOnboardingInput selects a SharePoint site for outlook_sharepoint jobs.
type SharePointSiteOnboardingInput struct {
	SiteID  string `json:"site_id"`
	SiteURL string `json:"site_url"`
}

// TeamsOnboardingInput selects a Team for outlook_teams jobs.
type TeamsOnboardingInput struct {
	TeamID     string   `json:"team_id"`
	TeamName   string   `json:"team_name,omitempty"`
	ChannelIDs []string `json:"channel_ids,omitempty"`
}

// GroupsOnboardingInput selects an M365 Group for outlook_groups jobs.
type GroupsOnboardingInput struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name,omitempty"`
}

// CreateMicrosoftBackupAutoSyncJobsRequest is the UI → Satellite body for Microsoft job create / onboarding.
type CreateMicrosoftBackupAutoSyncJobsRequest struct {
	Services        []string                        `json:"services"`
	MicrosoftEmail  string                          `json:"microsoft_email"`
	ProjectID       string                          `json:"project_id"`
	RefreshToken    string                          `json:"refresh_token"`
	StorxToken      string                          `json:"storx_token,omitempty"`
	Emails          []string                        `json:"emails,omitempty"`
	Sites           []SharePointSiteOnboardingInput `json:"sites,omitempty"`
	Teams           []TeamsOnboardingInput          `json:"teams,omitempty"`
	Groups          []GroupsOnboardingInput         `json:"groups,omitempty"`
	PolicyID        *int                            `json:"policy_id,omitempty"`
	PolicyName      string                          `json:"policy_name,omitempty"`
	Interval        string                          `json:"interval,omitempty"`
	On              string                          `json:"on,omitempty"`
	SatelliteUserID string                          `json:"satellite_user_id,omitempty"`
	// BackupScope when "all_tenant" lets Backup-Tools expand tenant teams/groups without teams[]/groups[].
	BackupScope     string                          `json:"backup_scope,omitempty"`
}

// UI service → body value forwarded to Backup-Tools (BT maps onedrive → method outlook_onedrive).
var allowedMicrosoftBackupServices = map[string]string{
	"outlook":  "outlook",
	"mail":     "outlook",
	"calendar": "calendar",
	"contacts": "contacts",
	"onedrive": "onedrive",
	"sharepoint": "sharepoint",
	"teams":      "teams",
	"groups":     "groups",
}

func normalizeMicrosoftBackupServices(services []string) ([]string, error) {
	if len(services) == 0 {
		return nil, ErrValidation.New("at least one service is required")
	}
	seen := make(map[string]struct{}, len(services))
	out := make([]string, 0, len(services))
	for _, service := range services {
		raw := strings.ToLower(strings.TrimSpace(service))
		if raw == "" {
			return nil, ErrValidation.New("service name cannot be empty")
		}
		normalized, ok := allowedMicrosoftBackupServices[raw]
		if !ok {
			return nil, ErrValidation.New("unsupported service: %s", service)
		}
		if _, dup := seen[normalized]; dup {
			return nil, ErrValidation.New("duplicate service: %s", service)
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

func (r *CreateMicrosoftBackupAutoSyncJobsRequest) Validate() error {
	var err error
	r.Services, err = normalizeMicrosoftBackupServices(r.Services)
	if err != nil {
		return err
	}
	r.MicrosoftEmail = strings.TrimSpace(r.MicrosoftEmail)
	// microsoft_email optional when Satellite loads credentials from DB (Google-style).
	if r.MicrosoftEmail != "" {
		if _, err := mail.ParseAddress(r.MicrosoftEmail); err != nil {
			return ErrValidation.New("invalid microsoft_email: %s", r.MicrosoftEmail)
		}
	}
	if v := strings.TrimSpace(r.RefreshToken); v != "" && looksLikeOAuthJWT(v) {
		return ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
	}
	if r.PolicyID == nil && strings.TrimSpace(r.PolicyName) == "" && strings.TrimSpace(r.Interval) == "" {
		return ErrValidation.New("interval is required when policy_id and policy_name are not set")
	}
	emails := make([]string, 0, len(r.Emails))
	seen := make(map[string]struct{}, len(r.Emails))
	for _, email := range r.Emails {
		email = strings.TrimSpace(email)
		if email == "" {
			return ErrValidation.New("email cannot be empty")
		}
		if _, err := mail.ParseAddress(email); err != nil {
			return ErrValidation.New("invalid email: %s", email)
		}
		key := strings.ToLower(email)
		if _, dup := seen[key]; dup {
			return ErrValidation.New("duplicate email: %s", email)
		}
		seen[key] = struct{}{}
		emails = append(emails, email)
	}
	r.Emails = emails

	r.BackupScope = strings.TrimSpace(r.BackupScope)
	if r.BackupScope != "" && r.BackupScope != "all_tenant" {
		return ErrValidation.New("unsupported backup_scope: %s", r.BackupScope)
	}

	hasSharePoint := false
	for _, svc := range r.Services {
		if svc == "sharepoint" {
			hasSharePoint = true
			break
		}
	}
	if hasSharePoint {
		if len(r.Sites) == 0 {
			return ErrValidation.New("sites is required when sharepoint service is selected")
		}
		for i, site := range r.Sites {
			siteID := strings.TrimSpace(site.SiteID)
			siteURL := strings.TrimSpace(site.SiteURL)
			if siteID == "" && siteURL == "" {
				return ErrValidation.New("sites[%d] requires site_id or site_url", i)
			}
		}
	}

	hasTeams := false
	for _, svc := range r.Services {
		if svc == "teams" {
			hasTeams = true
			break
		}
	}
	if hasTeams {
		if r.BackupScope != "all_tenant" && len(r.Teams) == 0 {
			return ErrValidation.New("teams is required when teams service is selected")
		}
		for i, team := range r.Teams {
			if strings.TrimSpace(team.TeamID) == "" {
				return ErrValidation.New("teams[%d] requires team_id", i)
			}
		}
	}

	hasGroups := false
	for _, svc := range r.Services {
		if svc == "groups" {
			hasGroups = true
			break
		}
	}
	if hasGroups {
		if r.BackupScope != "all_tenant" && len(r.Groups) == 0 {
			return ErrValidation.New("groups is required when groups service is selected")
		}
		for i, group := range r.Groups {
			if strings.TrimSpace(group.GroupID) == "" {
				return ErrValidation.New("groups[%d] requires group_id", i)
			}
		}
	}
	return nil
}

// CreateMicrosoftBackupAutoSyncJobs proxies Backup-Tools POST /microsoft/auto-sync/job (onboarding + reconnect).
// Like Google, Satellite loads Microsoft refresh_token from shared backup_credentials when omitted in the body.
func (s *Service) CreateMicrosoftBackupAutoSyncJobs(ctx context.Context, req CreateMicrosoftBackupAutoSyncJobsRequest, tokenKey, syncType string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	if syncType == "" {
		syncType = "daily"
	}

	user, err := GetUser(ctx)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	var credential *BackupCredential
	if email := strings.TrimSpace(req.MicrosoftEmail); email != "" {
		credential, err = s.store.BackupCredentials().GetByUserIDProviderEmail(ctx, user.ID, BackupProviderMicrosoft, email)
	} else {
		credential, err = s.store.BackupCredentials().GetByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth with a real OAuth refresh_token")
		}
		return nil, 0, Error.Wrap(err)
	}
	if err := credential.ValidateForMicrosoftBackup(); err != nil {
		return nil, 0, err
	}

	microsoftEmail := strings.TrimSpace(req.MicrosoftEmail)
	if microsoftEmail == "" {
		microsoftEmail = credential.Email
	}

	bodyRefresh := strings.TrimSpace(req.RefreshToken)
	if bodyRefresh != "" {
		if looksLikeOAuthJWT(bodyRefresh) {
			return nil, 0, ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
		}
		if storeErr := s.StoreMicrosoftBackupCredential(ctx, user.ID, microsoftEmail, credential.AccessToken, bodyRefresh, time.Time{}, credential.AccountType, credential.TenantID, credential.TenantName); storeErr != nil {
			return nil, 0, storeErr
		}
		credential.RefreshToken = bodyRefresh
	}

	projectID := strings.TrimSpace(req.ProjectID)
	var project *Project
	if projectID == "" {
		projects, projErr := s.store.Projects().GetOwnActive(ctx, user.ID)
		if projErr != nil {
			return nil, 0, Error.Wrap(projErr)
		}
		if len(projects) == 0 {
			return nil, 0, ErrNotFound.New("project not found for user")
		}
		project = &projects[0]
		projectID = project.PublicID.String()
	}

	accountType := strings.TrimSpace(credential.AccountType)
	if accountType == "" {
		return nil, 0, ErrValidation.New("microsoft account_type is missing; complete microsoft-backup auth and domain-users detection first")
	}

	satelliteUserID := strings.TrimSpace(req.SatelliteUserID)
	if satelliteUserID == "" {
		satelliteUserID = user.ID.String()
	} else if satelliteUserID != user.ID.String() {
		return nil, 0, ErrValidation.New("satellite_user_id must match the authenticated user")
	}

	payload := map[string]interface{}{
		"services":          req.Services,
		"microsoft_email":   microsoftEmail,
		"account_type":      accountType,
		"project_id":        projectID,
		"satellite_user_id": satelliteUserID,
		"refresh_token":     strings.TrimSpace(credential.RefreshToken),
	}
	if tenantID := strings.TrimSpace(credential.TenantID); tenantID != "" {
		payload["tenant_id"] = tenantID
	}
	if tenantName := strings.TrimSpace(credential.TenantName); tenantName != "" {
		payload["tenant_name"] = tenantName
	}
	if len(req.Sites) > 0 {
		sites := make([]map[string]string, 0, len(req.Sites))
		for _, site := range req.Sites {
			sites = append(sites, map[string]string{
				"site_id":  strings.TrimSpace(site.SiteID),
				"site_url": strings.TrimSpace(site.SiteURL),
			})
		}
		payload["sites"] = sites
	}
	if len(req.Teams) > 0 {
		teams := make([]map[string]interface{}, 0, len(req.Teams))
		for _, team := range req.Teams {
			entry := map[string]interface{}{
				"team_id": strings.TrimSpace(team.TeamID),
			}
			if v := strings.TrimSpace(team.TeamName); v != "" {
				entry["team_name"] = v
			}
			if len(team.ChannelIDs) > 0 {
				entry["channel_ids"] = team.ChannelIDs
			}
			teams = append(teams, entry)
		}
		payload["teams"] = teams
	}
	if len(req.Groups) > 0 {
		groups := make([]map[string]string, 0, len(req.Groups))
		for _, group := range req.Groups {
			entry := map[string]string{
				"group_id": strings.TrimSpace(group.GroupID),
			}
			if v := strings.TrimSpace(group.GroupName); v != "" {
				entry["group_name"] = v
			}
			groups = append(groups, entry)
		}
		payload["groups"] = groups
	}
	if req.PolicyID != nil {
		payload["policy_id"] = *req.PolicyID
	}
	if v := strings.TrimSpace(req.PolicyName); v != "" {
		payload["policy_name"] = v
	}
	if req.PolicyID == nil {
		if interval := strings.TrimSpace(req.Interval); interval != "" {
			payload["interval"] = interval
		}
		if on := strings.TrimSpace(req.On); on != "" {
			payload["on"] = on
		}
	}
	if v := strings.TrimSpace(req.StorxToken); v != "" {
		payload["storx_token"] = v
	} else if project != nil && project.PassphraseEnc != nil {
		storxToken, tokenErr := s.CreateAccessGrantForManagedProject(ctx, project.ID)
		if tokenErr != nil {
			return nil, 0, Error.Wrap(tokenErr)
		}
		payload["storx_token"] = storxToken
	}
	if len(req.Emails) > 0 {
		payload["emails"] = req.Emails
	} else {
		payload["emails"] = []string{microsoftEmail}
	}
	if v := strings.TrimSpace(req.BackupScope); v != "" {
		payload["backup_scope"] = v
	}

	btPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	path := "/microsoft/auto-sync/job?sync_type=" + url.QueryEscape(syncType)
	body, status, err = s.backupToolsRequest(ctx, http.MethodPost, path, tokenKey, "", btPayload)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if status == http.StatusOK {
		s.maybeCompleteMicrosoftBackupOnboarding(ctx, body)
	}
	return body, status, nil
}

func (s *Service) maybeCompleteMicrosoftBackupOnboarding(ctx context.Context, body []byte) {
	var resp struct {
		Failed []json.RawMessage `json:"failed"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return
	}
	if len(resp.Failed) > 0 {
		return
	}
	onboardingStart, onboardingEnd := true, true
	step := OnboardingStepMicrosoftBackupCompleted
	if _, err := s.SetUserSettings(ctx, UpsertUserSettingsRequest{
		OnboardingStart: &onboardingStart,
		OnboardingEnd:   &onboardingEnd,
		OnboardingStep:  &step,
	}); err != nil {
		s.log.Warn("failed to update microsoft backup onboarding status", zap.Error(err))
	}
}

func (s *Service) getMicrosoftBackupWithRefreshToken(ctx context.Context, tokenKey, path, refreshToken, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	resolved, _, err := s.resolveMicrosoftRefreshToken(ctx, refreshToken, "")
	if err != nil {
		return nil, 0, err
	}
	if query != "" {
		path += "?" + query
	}
	return s.backupToolsRequestWithHeaders(ctx, http.MethodGet, path, tokenKey, "", resolved, nil)
}

// GetMicrosoftBackupQueryMessages proxies Backup-Tools GET /microsoft/query-messages.
func (s *Service) GetMicrosoftBackupQueryMessages(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/query-messages", refreshToken, query)
}

// GetMicrosoftBackupContactsList proxies Backup-Tools GET /microsoft/contacts/list.
func (s *Service) GetMicrosoftBackupContactsList(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/contacts/list", refreshToken, query)
}

// GetMicrosoftBackupCalendarList proxies Backup-Tools GET /microsoft/calendar/list.
func (s *Service) GetMicrosoftBackupCalendarList(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/calendar/list", refreshToken, query)
}

// GetMicrosoftBackupCalendarEvents proxies Backup-Tools GET /microsoft/calendar/events/{calendarId}.
func (s *Service) GetMicrosoftBackupCalendarEvents(ctx context.Context, tokenKey, refreshToken, calendarID, query string) (body []byte, status int, err error) {
	calendarID = strings.TrimSpace(calendarID)
	if calendarID == "" {
		return nil, 0, ErrValidation.New("calendarId is required")
	}
	path := "/microsoft/calendar/events/" + url.PathEscape(calendarID)
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, path, refreshToken, query)
}

// GetMicrosoftBackupCorporateDomainUsers proxies Backup-Tools GET /microsoft/outlook/corporate/domain-users
// using DB refresh when the client omits REFRESH_TOKEN (browse raw JSON; prefer GetMicrosoftBackupDomainUsers for onboarding).
func (s *Service) GetMicrosoftBackupCorporateDomainUsers(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/outlook/corporate/domain-users", refreshToken, query)
}

// GetMicrosoftBackupSharePointSites proxies Backup-Tools GET /microsoft/sharepoint/sites.
func (s *Service) GetMicrosoftBackupSharePointSites(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/sharepoint/sites", refreshToken, query)
}

// GetMicrosoftBackupSharePointFlatFiles proxies Backup-Tools GET /microsoft/sharepoint/flat-files.
func (s *Service) GetMicrosoftBackupSharePointFlatFiles(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/sharepoint/flat-files", refreshToken, query)
}

// GetMicrosoftBackupTeamsList proxies Backup-Tools GET /microsoft/teams/list.
func (s *Service) GetMicrosoftBackupTeamsList(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/teams/list", refreshToken, query)
}

// GetMicrosoftBackupTeamChannels proxies Backup-Tools GET /microsoft/teams/channels.
func (s *Service) GetMicrosoftBackupTeamChannels(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/teams/channels", refreshToken, query)
}

// GetMicrosoftBackupTeamsFlatMessages proxies Backup-Tools GET /microsoft/teams/flat-messages.
func (s *Service) GetMicrosoftBackupTeamsFlatMessages(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/teams/flat-messages", refreshToken, query)
}

// GetMicrosoftBackupGroupsList proxies Backup-Tools GET /microsoft/groups/list.
func (s *Service) GetMicrosoftBackupGroupsList(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/groups/list", refreshToken, query)
}

// GetMicrosoftBackupGroupsFlatConversations proxies Backup-Tools GET /microsoft/groups/flat-conversations.
func (s *Service) GetMicrosoftBackupGroupsFlatConversations(ctx context.Context, tokenKey, refreshToken, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupWithRefreshToken(ctx, tokenKey, "/microsoft/groups/flat-conversations", refreshToken, query)
}
