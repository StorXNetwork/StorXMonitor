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

	"github.com/StorXNetwork/common/uuid"
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

const (
	// MicrosoftBackupModeSelf backs up only the caller's own mailbox with their delegated token (/me).
	MicrosoftBackupModeSelf = "self"
	// MicrosoftBackupModeOrganization backs up tenant users with the tenant app-only token (/users/{id}).
	MicrosoftBackupModeOrganization = "organization"

	microsoftAuthModeDelegated   = "delegated"
	microsoftAuthModeApplication = "application"
)

// CreateMicrosoftBackupAutoSyncJobsRequest is the UI → Satellite body for Microsoft job create / onboarding.
type CreateMicrosoftBackupAutoSyncJobsRequest struct {
	// CredentialID selects the Microsoft account (backup_credentials ID); optional with a single account.
	CredentialID string `json:"credential_id,omitempty"`
	// TenantID is the selected tenant. Required for organization mode; self mode defaults to the
	// account's home tenant, where its own mailbox lives.
	TenantID        string                          `json:"tenant_id,omitempty"`
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
	BackupScope string `json:"backup_scope,omitempty"`

	// BackupMode is self (delegated, own mailbox) or organization (application, tenant users).
	// It decides the job's auth_mode; the account type never does.
	BackupMode string `json:"backup_mode,omitempty"`
	// AllUsers selects every enabled user in the tenant directory (organization mode).
	AllUsers bool `json:"all_users,omitempty"`
	// UserIDs selects tenant directory users by object ID (organization mode).
	UserIDs          []string                               `json:"user_ids,omitempty"`
	PolicyScope      string                                 `json:"policy_scope,omitempty"`
	EmailOrgUnits    map[string]string                      `json:"email_org_units,omitempty"`
	OrgUnitSchedules map[string]GoogleBackupOrgUnitSchedule `json:"org_unit_schedules,omitempty"`
}

func (r *CreateMicrosoftBackupAutoSyncJobsRequest) isOrgUnitScope() bool {
	return strings.EqualFold(strings.TrimSpace(r.PolicyScope), "org_unit")
}

// allowsEmptyTopLevelServices is true when every org-unit schedule carries its own services list.
func (r *CreateMicrosoftBackupAutoSyncJobsRequest) allowsEmptyTopLevelServices() bool {
	if !r.isOrgUnitScope() || len(r.OrgUnitSchedules) == 0 {
		return false
	}
	for _, sched := range r.OrgUnitSchedules {
		if len(sched.Services) == 0 {
			return false
		}
	}
	return true
}

// needsScheduleInBody reports whether top-level interval/on should be forwarded to Backup-Tools.
func (r *CreateMicrosoftBackupAutoSyncJobsRequest) needsScheduleInBody() bool {
	return r.PolicyID == nil && !r.isOrgUnitScope()
}

func (r *CreateMicrosoftBackupAutoSyncJobsRequest) hasService(service string) bool {
	for _, svc := range r.Services {
		if svc == service {
			return true
		}
	}
	for _, sched := range r.OrgUnitSchedules {
		for _, svc := range sched.Services {
			if svc == service {
				return true
			}
		}
	}
	return false
}

// normalizeBackupMode defaults an omitted backup_mode: organization when the request selects tenant
// users or org units, otherwise self.
func (r *CreateMicrosoftBackupAutoSyncJobsRequest) normalizeBackupMode() error {
	mode := strings.ToLower(strings.TrimSpace(r.BackupMode))
	if mode == "" {
		mode = MicrosoftBackupModeSelf
		if r.AllUsers || len(r.UserIDs) > 0 || r.BackupScope == "all_tenant" || r.isOrgUnitScope() {
			mode = MicrosoftBackupModeOrganization
		}
	}
	switch mode {
	case MicrosoftBackupModeSelf:
		if r.AllUsers || len(r.UserIDs) > 0 || r.BackupScope == "all_tenant" || r.isOrgUnitScope() || len(r.OrgUnitSchedules) > 0 {
			return ErrValidation.New("backup_mode=self only backs up your own mailbox; use backup_mode=organization for tenant users, org units or all_tenant")
		}
	case MicrosoftBackupModeOrganization:
	default:
		return ErrValidation.New("unsupported backup_mode: %s", r.BackupMode)
	}
	r.BackupMode = mode
	return nil
}

func (r *CreateMicrosoftBackupAutoSyncJobsRequest) authMode() string {
	if r.BackupMode == MicrosoftBackupModeOrganization {
		return microsoftAuthModeApplication
	}
	return microsoftAuthModeDelegated
}

// UI service → body value forwarded to Backup-Tools (BT maps onedrive → method outlook_onedrive).
var allowedMicrosoftBackupServices = map[string]string{
	"outlook":    "outlook",
	"mail":       "outlook",
	"calendar":   "calendar",
	"contacts":   "contacts",
	"onedrive":   "onedrive",
	"sharepoint": "sharepoint",
	"teams":      "teams",
	"groups":     "groups",
}

func normalizeMicrosoftOrgUnitSchedules(in map[string]GoogleBackupOrgUnitSchedule) (map[string]GoogleBackupOrgUnitSchedule, error) {
	out := make(map[string]GoogleBackupOrgUnitSchedule, len(in))
	for path, sched := range in {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		services, err := normalizeMicrosoftBackupServices(sched.Services, true)
		if err != nil {
			return nil, err
		}
		out[path] = GoogleBackupOrgUnitSchedule{
			PolicyName: strings.TrimSpace(sched.PolicyName),
			Interval:   strings.TrimSpace(sched.Interval),
			On:         strings.TrimSpace(sched.On),
			Services:   services,
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func normalizeMicrosoftEmailOrgUnits(units map[string]string) map[string]string {
	out := make(map[string]string, len(units))
	for email, path := range units {
		email = strings.ToLower(strings.TrimSpace(email))
		path = strings.TrimSpace(path)
		if email == "" || path == "" {
			continue
		}
		out[email] = path
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeMicrosoftUserIDs(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, ErrValidation.New("user_ids cannot contain empty values")
		}
		key := strings.ToLower(id)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func normalizeMicrosoftBackupServices(services []string, allowEmpty bool) ([]string, error) {
	if len(services) == 0 {
		if allowEmpty {
			return nil, nil
		}
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
	r.OrgUnitSchedules, err = normalizeMicrosoftOrgUnitSchedules(r.OrgUnitSchedules)
	if err != nil {
		return err
	}
	r.Services, err = normalizeMicrosoftBackupServices(r.Services, r.allowsEmptyTopLevelServices())
	if err != nil {
		return err
	}
	r.PolicyScope = strings.TrimSpace(r.PolicyScope)
	r.EmailOrgUnits = normalizeMicrosoftEmailOrgUnits(r.EmailOrgUnits)
	r.UserIDs, err = normalizeMicrosoftUserIDs(r.UserIDs)
	if err != nil {
		return err
	}
	r.BackupScope = strings.TrimSpace(r.BackupScope)
	if err := r.normalizeBackupMode(); err != nil {
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
	if r.needsScheduleInBody() && strings.TrimSpace(r.PolicyName) == "" && strings.TrimSpace(r.Interval) == "" {
		return ErrValidation.New("interval is required when policy_id and policy_name are not set")
	}
	if r.isOrgUnitScope() && r.PolicyID == nil && len(r.OrgUnitSchedules) == 0 {
		return ErrValidation.New("org_unit_schedules is required when policy_scope is org_unit")
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

	if r.BackupScope != "" && r.BackupScope != "all_tenant" {
		return ErrValidation.New("unsupported backup_scope: %s", r.BackupScope)
	}

	if r.hasService("sharepoint") {
		if r.BackupScope != "all_tenant" && len(r.Sites) == 0 {
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

	if r.hasService("teams") {
		if r.BackupScope != "all_tenant" && len(r.Teams) == 0 {
			return ErrValidation.New("teams is required when teams service is selected")
		}
		for i, team := range r.Teams {
			if strings.TrimSpace(team.TeamID) == "" {
				return ErrValidation.New("teams[%d] requires team_id", i)
			}
		}
	}

	if r.hasService("groups") {
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

	credential, err := s.resolveMicrosoftJobCredential(ctx, user.ID, req.CredentialID, req.MicrosoftEmail)
	if err != nil {
		return nil, 0, err
	}
	microsoftEmail := strings.TrimSpace(req.MicrosoftEmail)
	if microsoftEmail == "" {
		microsoftEmail = credential.Email
	}

	accountType := strings.TrimSpace(credential.AccountType)
	// Jobs belong to the tenant the user connected for backup; the home tenant is never assumed.
	tenantID := strings.ToLower(strings.TrimSpace(req.TenantID))
	if tenantID == "" {
		return nil, 0, ErrMicrosoftTenantRequired.New("tenant_id is required")
	}

	switch req.BackupMode {
	case MicrosoftBackupModeOrganization:
		// Organization jobs run on the tenant app-only token in Backup-Tools; the body carries no delegated
		// refresh token. Backup-Tools decides authorization from consent and capabilities, not account_type.
		if accountType == MicrosoftAccountTypePersonal {
			return nil, 0, ErrValidation.New("organization backup requires a work or school Microsoft account")
		}
	default:
		for _, email := range req.Emails {
			if !strings.EqualFold(email, microsoftEmail) {
				return nil, 0, ErrValidation.New("backup_mode=self only backs up your own mailbox (%s); use backup_mode=organization for other users", microsoftEmail)
			}
		}
		bodyRefresh := strings.TrimSpace(req.RefreshToken)
		if bodyRefresh != "" {
			if looksLikeOAuthJWT(bodyRefresh) {
				return nil, 0, ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
			}
			if storeErr := s.updateMicrosoftCredentialTokens(ctx, credential, "", bodyRefresh, time.Time{}); storeErr != nil {
				return nil, 0, storeErr
			}
		}
		if err := credential.ValidateForMicrosoftBackup(); err != nil {
			return nil, 0, err
		}
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

	satelliteUserID := strings.TrimSpace(req.SatelliteUserID)
	if satelliteUserID == "" {
		satelliteUserID = user.ID.String()
	} else if satelliteUserID != user.ID.String() {
		return nil, 0, ErrValidation.New("satellite_user_id must match the authenticated user")
	}

	payload := map[string]interface{}{
		"microsoft_email":   microsoftEmail,
		"auth_mode":         req.authMode(),
		"project_id":        projectID,
		"satellite_user_id": satelliteUserID,
	}
	if len(req.Services) > 0 {
		payload["services"] = req.Services
	}
	if accountType != "" {
		payload["account_type"] = accountType
	}
	if req.BackupMode == MicrosoftBackupModeSelf {
		payload["refresh_token"] = strings.TrimSpace(credential.RefreshToken)
	}
	payload["tenant_id"] = tenantID
	// The stored name belongs to the home tenant; Backup-Tools knows other tenants' names.
	if strings.EqualFold(tenantID, credential.HomeTenantID()) {
		if tenantName := strings.TrimSpace(credential.HomeTenantName()); tenantName != "" {
			payload["tenant_name"] = tenantName
		}
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
	if req.needsScheduleInBody() {
		if interval := strings.TrimSpace(req.Interval); interval != "" {
			payload["interval"] = interval
		}
		if on := strings.TrimSpace(req.On); on != "" {
			payload["on"] = on
		}
	}
	if req.PolicyScope != "" {
		payload["policy_scope"] = req.PolicyScope
	}
	if len(req.EmailOrgUnits) > 0 {
		payload["email_org_units"] = req.EmailOrgUnits
	}
	if len(req.OrgUnitSchedules) > 0 {
		payload["org_unit_schedules"] = req.OrgUnitSchedules
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
	switch {
	case len(req.Emails) > 0:
		payload["emails"] = req.Emails
	case req.BackupMode == MicrosoftBackupModeSelf:
		payload["emails"] = []string{microsoftEmail}
	}
	if req.BackupMode == MicrosoftBackupModeOrganization {
		if req.AllUsers {
			payload["all_users"] = true
		}
		if len(req.UserIDs) > 0 {
			payload["user_ids"] = req.UserIDs
		}
	}
	if req.BackupScope != "" {
		payload["backup_scope"] = req.BackupScope
	}

	// own_nodes mode: allow job create, but keep inactive until >= MinOwnNodesRequired.
	ownNodesStatus, capacityErr := s.ownNodesCapacityForUser(ctx, user.ID)
	jobsCreatedInactive := false
	if capacityErr != nil {
		s.log.Warn("own-nodes capacity check failed during microsoft job create", zap.Error(capacityErr))
	} else if ownNodesStatus != nil && ownNodesStatus.Required && !ownNodesStatus.Ready {
		payload["active"] = false
		jobsCreatedInactive = true
	}

	btPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	path := "/microsoft/auto-sync/job?sync_type=" + url.QueryEscape(syncType)
	body, status, err = s.backupToolsRequestWithExtraHeaders(ctx, http.MethodPost, path, tokenKey, "", microsoftCredentialRefreshToken(credential), microsoftBackupToolsHeaders(credential, tenantID), btPayload)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if status == http.StatusOK {
		s.maybeCompleteMicrosoftBackupOnboarding(ctx, body)
		if ownNodesStatus != nil {
			if jobsCreatedInactive {
				s.enforceOwnNodesInactiveJobs(ctx, tokenKey, ownNodesStatus)
				body = mergeOwnNodesCreateFlags(body, true)
			}
			body = mergeOwnNodesIntoJSONObject(body, "own_nodes", ownNodesStatus)
		}
	}
	return body, status, nil
}

// resolveMicrosoftJobCredential selects the credential by credentialID, else by microsoftEmail,
// else the only Microsoft credential.
func (s *Service) resolveMicrosoftJobCredential(ctx context.Context, userID uuid.UUID, credentialID, microsoftEmail string) (*BackupCredential, error) {
	email := strings.TrimSpace(microsoftEmail)
	if strings.TrimSpace(credentialID) != "" || email == "" {
		return s.resolveMicrosoftCredential(ctx, userID, credentialID)
	}
	credential, err := s.store.BackupCredentials().GetByUserIDProviderEmail(ctx, userID, BackupProviderMicrosoft, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth with a real OAuth refresh_token")
		}
		return nil, Error.Wrap(err)
	}
	return credential, nil
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
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, 0, ErrValidation.New("invalid query string")
	}
	sel := MicrosoftTenantSelectionFromQuery(values)
	if sel.TenantID == "" {
		return nil, 0, ErrMicrosoftTenantRequired.New("tenant_id is required")
	}
	// credential_id is a Satellite ID; Backup-Tools identifies the account by the headers instead.
	values.Del("credential_id")
	values.Set("tenant_id", sel.TenantID)

	resolved, credential, err := s.resolveMicrosoftRefreshToken(ctx, refreshToken, sel.CredentialID, "")
	if err != nil {
		return nil, 0, err
	}
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return s.backupToolsRequestWithExtraHeaders(ctx, http.MethodGet, path, tokenKey, "", resolved, microsoftBackupToolsHeaders(credential, sel.TenantID), nil)
}

// MicrosoftTenantSelectionFromQuery reads credential_id and tenant_id query parameters.
func MicrosoftTenantSelectionFromQuery(values url.Values) MicrosoftTenantSelection {
	return MicrosoftTenantSelection{
		CredentialID: values.Get("credential_id"),
		TenantID:     values.Get("tenant_id"),
	}.normalized()
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
