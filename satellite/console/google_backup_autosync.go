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
	"golang.org/x/exp/slices"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

// GoogleBackupOrgUnitSchedule is a per-OU cron for policy_scope=org_unit job create.
type GoogleBackupOrgUnitSchedule struct {
	PolicyName string   `json:"policy_name,omitempty"`
	Interval   string   `json:"interval"`
	On         string   `json:"on,omitempty"`
	Services   []string `json:"services,omitempty"`
}

type CreateGoogleBackupAutoSyncJobsRequest struct {
	Services         []string
	Interval         string
	On               string
	Emails           []string
	EmailOrgUnits    map[string]string
	PolicyID         *int
	PolicyName       string
	PolicyScope      string
	OrgUnitSchedules map[string]GoogleBackupOrgUnitSchedule
}

// UpdateGoogleBackupAutoSyncJobsByProjectRequest is the UI → satellite body for
// Backup-Tools PUT /auto-sync/job/project (project_id in JSON body, not URL path).
type UpdateGoogleBackupAutoSyncJobsByProjectRequest struct {
	ProjectID    string `json:"project_id"`
	GoogleEmail  string `json:"google_email,omitempty"`
	Code         string `json:"code,omitempty"`
	StorxToken   string `json:"storx_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Active       *bool  `json:"active,omitempty"`
}

// UpdateGoogleBackupAutoSyncJobRequest is the UI body for Backup-Tools PUT /auto-sync/job/{job_id} (active only).
type UpdateGoogleBackupAutoSyncJobRequest struct {
	Active *bool `json:"active"`
}

// Validate requires project_id, google_email, and at least one account-level update field.
func (r UpdateGoogleBackupAutoSyncJobsByProjectRequest) Validate() error {
	r.ProjectID = strings.TrimSpace(r.ProjectID)
	if r.ProjectID == "" {
		return ErrValidation.New("project_id is required")
	}

	googleEmail := strings.TrimSpace(r.GoogleEmail)
	if googleEmail == "" {
		return ErrValidation.New("google_email is required (legacy email is no longer supported)")
	}
	if _, err := mail.ParseAddress(googleEmail); err != nil {
		return ErrValidation.New("invalid google_email: %s", googleEmail)
	}
	if !r.hasUpdateFields() {
		return ErrValidation.New("at least one update field is required")
	}
	return nil
}

func (r UpdateGoogleBackupAutoSyncJobsByProjectRequest) hasUpdateFields() bool {
	return strings.TrimSpace(r.Code) != "" ||
		strings.TrimSpace(r.RefreshToken) != "" ||
		strings.TrimSpace(r.StorxToken) != "" ||
		r.Active != nil
}

func (r UpdateGoogleBackupAutoSyncJobRequest) Validate() error {
	if r.Active == nil {
		return ErrValidation.New("active is required")
	}
	return nil
}

func (r UpdateGoogleBackupAutoSyncJobRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"active": *r.Active,
	})
}

// backupToolsPayload returns JSON for Backup-Tools, omitting empty optional fields.
func (r UpdateGoogleBackupAutoSyncJobsByProjectRequest) backupToolsPayload() ([]byte, error) {
	googleEmail := strings.TrimSpace(r.GoogleEmail)

	out := map[string]interface{}{
		"project_id": strings.TrimSpace(r.ProjectID),
	}
	if googleEmail != "" {
		out["google_email"] = googleEmail
	}
	if v := strings.TrimSpace(r.StorxToken); v != "" {
		out["storx_token"] = v
	}
	if v := strings.TrimSpace(r.RefreshToken); v != "" {
		out["refresh_token"] = v
	}
	if r.Active != nil {
		out["active"] = *r.Active
	}
	return json.Marshal(out)
}

var allowedGoogleBackupServices = map[string]struct{}{
	"gmail": {}, "drive": {}, "photos": {}, "contacts": {}, "calendar": {},
}

func (s *Service) CreateGoogleBackupAutoSyncJobs(ctx context.Context, req CreateGoogleBackupAutoSyncJobsRequest, tokenKey, syncType string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	req.OrgUnitSchedules, err = normalizeOrgUnitSchedules(req.OrgUnitSchedules)
	if err != nil {
		return nil, 0, err
	}
	req.Services, err = normalizeGoogleBackupServices(req.Services, req.allowsEmptyTopLevelServices())
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if syncType == "" {
		syncType = "daily"
	}

	user, err := GetUser(ctx)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	credential, err := s.store.GoogleBackupCredentials().GetByUserID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrNotFound.New("google backup credentials not found")
		}
		return nil, 0, Error.Wrap(err)
	}
	if err := credential.ValidateForBackup(); err != nil {
		return nil, 0, err
	}

	effectiveServices := collectGoogleBackupServices(req.Services, req.OrgUnitSchedules)
	gmailEmails, err := googleBackupGmailEmails(effectiveServices, req.Emails, credential)
	if err != nil {
		return nil, 0, err
	}
	emailOrgUnits := normalizeEmailOrgUnits(req.EmailOrgUnits, gmailEmails)
	if shouldEnrichJobOrgUnits(credential.AccountType, gmailEmails, emailOrgUnits) {
		if filled := s.emailOrgUnitsFromDirectory(ctx, tokenKey, credential, gmailEmails); len(filled) > 0 {
			emailOrgUnits = mergeEmailOrgUnits(emailOrgUnits, filled)
		}
	}

	// Invites only grant membership for viewing another project's details. Job create
	// always uses this user's own active project (oldest = default signup project).
	projects, err := s.store.Projects().GetOwnActive(ctx, user.ID)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if len(projects) == 0 {
		return nil, 0, ErrNotFound.New("project not found for user")
	}
	project := projects[0]
	payload := map[string]interface{}{
		"google_email":      credential.GoogleEmail,
		"account_type":      credential.AccountType,
		"project_id":        project.PublicID.String(),
		"satellite_user_id": user.ID.String(),
		"refresh_token":     credential.RefreshToken,
	}
	if len(req.Services) > 0 {
		payload["services"] = req.Services
	}
	if req.needsScheduleInBody() {
		if interval := normalizeGoogleBackupInterval(req.Interval); interval != "" {
			payload["interval"] = interval
		}
		if on := strings.TrimSpace(req.On); on != "" {
			payload["on"] = on
		}
	}
	if project.PassphraseEnc != nil {
		storxToken, tokenErr := s.CreateAccessGrantForManagedProject(ctx, project.ID)
		if tokenErr != nil {
			return nil, 0, Error.Wrap(tokenErr)
		}
		payload["storx_token"] = storxToken
	}
	if len(gmailEmails) > 0 {
		payload["emails"] = gmailEmails
	}
	if len(emailOrgUnits) > 0 {
		payload["email_org_units"] = emailOrgUnits
	}
	if req.PolicyID != nil {
		payload["policy_id"] = *req.PolicyID
	}
	if v := strings.TrimSpace(req.PolicyName); v != "" {
		payload["policy_name"] = v
	}
	if v := strings.TrimSpace(req.PolicyScope); v != "" {
		payload["policy_scope"] = v
	}
	if len(req.OrgUnitSchedules) > 0 {
		payload["org_unit_schedules"] = req.OrgUnitSchedules
	}

	btPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	path := "/auto-sync/job?sync_type=" + url.QueryEscape(syncType)
	body, status, err = s.backupToolsRequest(ctx, http.MethodPost, path, tokenKey, "", btPayload)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if status == http.StatusOK {
		s.maybeCompleteGoogleBackupOnboarding(ctx, body)
	}
	return body, status, nil
}

func (s *Service) ListGoogleBackupRestoreLogs(ctx context.Context, tokenKey, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	path := "/backup-restore/logs"
	if query != "" {
		path += "?" + query
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func (s *Service) ListGoogleBackupAutoSyncJobServices(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	return s.backupToolsRequest(ctx, http.MethodGet, "/auto-sync/job/services", tokenKey, "", nil)
}

// ListGoogleBackupAutoSyncLive proxies Backup-Tools GET /auto-sync/live (running/failed backup tasks).
func (s *Service) ListGoogleBackupAutoSyncLive(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	return s.backupToolsRequest(ctx, http.MethodGet, "/auto-sync/live", tokenKey, "", nil)
}

func (s *Service) ListGoogleBackupAutoSyncJobs(ctx context.Context, tokenKey, filter string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	path := "/auto-sync/job/"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func (s *Service) GetGoogleBackupAutoSyncJob(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}

	path := "/auto-sync/job/" + url.PathEscape(jobID)
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// UpdateGoogleBackupAutoSyncJobsByProject proxies to Backup-Tools PUT /auto-sync/job/project.
// When code is present, Satellite exchanges it for tokens, updates google_backup_credentials, then sends refresh_token only.
func (s *Service) UpdateGoogleBackupAutoSyncJobsByProject(ctx context.Context, tokenKey string, req UpdateGoogleBackupAutoSyncJobsByProjectRequest, redirectURI string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	if err := s.applyGoogleBackupProjectUpdateTokens(ctx, &req, redirectURI); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	return s.backupToolsRequest(ctx, http.MethodPut, "/auto-sync/job/project", tokenKey, "", btPayload)
}

func (s *Service) applyGoogleBackupProjectUpdateTokens(ctx context.Context, req *UpdateGoogleBackupAutoSyncJobsByProjectRequest, redirectURI string) error {
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	googleEmail := strings.TrimSpace(req.GoogleEmail)
	code := strings.TrimSpace(req.Code)
	refreshToken := strings.TrimSpace(req.RefreshToken)

	if code != "" {
		tokenRes, err := socialmedia.GetGoogleOauthTokenWithRedirect(code, "googlebackup", false, redirectURI)
		if err != nil {
			return ErrValidation.New("failed to exchange google oauth code: %v", err)
		}
		if tokenRes.Refresh_token == "" {
			return ErrValidation.New("google did not return a refresh token; re-authorize with consent")
		}
		if err := s.storeGoogleBackupCredential(ctx, user.ID, googleEmail, tokenRes.Access_token, tokenRes.Refresh_token, tokenRes.ExpiresAt, ""); err != nil {
			return Error.Wrap(err)
		}
		req.RefreshToken = tokenRes.Refresh_token
		req.Code = ""
		return nil
	}

	if refreshToken == "" {
		return nil
	}

	validAccessToken, validExpiry, err := socialmedia.ResolveAccessToken(ctx, "", refreshToken, time.Time{})
	if err != nil {
		return ErrValidation.Wrap(err)
	}
	if err := s.storeGoogleBackupCredential(ctx, user.ID, googleEmail, validAccessToken, refreshToken, validExpiry, ""); err != nil {
		return Error.Wrap(err)
	}
	req.RefreshToken = refreshToken
	return nil
}

// TriggerGoogleBackupAutoSyncBackupNow proxies Backup-Tools POST /auto-sync/task/{job_id}/backup-now.
// Queues an on-demand backup for interval autosync jobs without changing the cron schedule or last_run.
func (s *Service) TriggerGoogleBackupAutoSyncBackupNow(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}

	path := "/auto-sync/task/" + url.PathEscape(jobID) + "/backup-now"
	return s.backupToolsRequest(ctx, http.MethodPost, path, tokenKey, "", nil)
}

func (s *Service) UpdateGoogleBackupAutoSyncJob(ctx context.Context, tokenKey, jobID string, req UpdateGoogleBackupAutoSyncJobRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	path := "/auto-sync/job/" + url.PathEscape(jobID)
	return s.backupToolsRequest(ctx, http.MethodPut, path, tokenKey, "", btPayload)
}

func (s *Service) maybeCompleteGoogleBackupOnboarding(ctx context.Context, body []byte) {
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
	step := OnboardingStepGoogleBackupCompleted
	if _, err := s.SetUserSettings(ctx, UpsertUserSettingsRequest{
		OnboardingStart: &onboardingStart,
		OnboardingEnd:   &onboardingEnd,
		OnboardingStep:  &step,
	}); err != nil {
		s.log.Warn("failed to update onboarding status", zap.Error(err))
	}
}

func (r CreateGoogleBackupAutoSyncJobsRequest) isOrgUnitScope() bool {
	return strings.EqualFold(strings.TrimSpace(r.PolicyScope), "org_unit")
}

// needsScheduleInBody reports whether top-level interval/on should be forwarded to Backup-Tools.
// When policy_id is set, schedule comes from the policy. When policy_scope=org_unit, schedules are per OU.
func (r CreateGoogleBackupAutoSyncJobsRequest) needsScheduleInBody() bool {
	if r.PolicyID != nil {
		return false
	}
	return !r.isOrgUnitScope()
}

// allowsEmptyTopLevelServices is true when every OU schedule carries its own services list.
func (r CreateGoogleBackupAutoSyncJobsRequest) allowsEmptyTopLevelServices() bool {
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

func normalizeOrgUnitSchedules(in map[string]GoogleBackupOrgUnitSchedule) (map[string]GoogleBackupOrgUnitSchedule, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]GoogleBackupOrgUnitSchedule, len(in))
	for path, sched := range in {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		services, err := normalizeGoogleBackupServices(sched.Services, true)
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

func normalizeGoogleBackupServices(services []string, allowEmpty bool) ([]string, error) {
	if len(services) == 0 {
		if allowEmpty {
			return nil, nil
		}
		return nil, Error.New("at least one service is required")
	}

	seen := make(map[string]struct{}, len(services))
	out := make([]string, 0, len(services))
	for _, service := range services {
		s := strings.ToLower(strings.TrimSpace(service))
		if s == "" {
			return nil, Error.New("service name cannot be empty")
		}
		if _, ok := allowedGoogleBackupServices[s]; !ok {
			return nil, Error.New("unsupported service: %s", service)
		}
		if _, dup := seen[s]; dup {
			return nil, Error.New("duplicate service: %s", service)
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

func collectGoogleBackupServices(topLevel []string, schedules map[string]GoogleBackupOrgUnitSchedule) []string {
	seen := make(map[string]struct{}, len(topLevel))
	out := make([]string, 0, len(topLevel))
	add := func(services []string) {
		for _, s := range services {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	add(topLevel)
	for _, sched := range schedules {
		add(sched.Services)
	}
	return out
}

func normalizeGoogleBackupInterval(interval string) string {
	interval = strings.ToLower(strings.TrimSpace(interval))
	switch interval {
	case "24h", "7d", "daily":
		return "nightly"
	default:
		return interval
	}
}

func shouldEnrichJobOrgUnits(accountType string, emails []string, units map[string]string) bool {
	if !isCorporateGoogleBackupAccount(accountType) || len(emails) == 0 {
		return false
	}
	for _, email := range emails {
		if strings.TrimSpace(units[strings.ToLower(email)]) == "" {
			return true
		}
	}
	return false
}

func normalizeEmailOrgUnits(units map[string]string, emails []string) map[string]string {
	if len(units) == 0 || len(emails) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		allowed[strings.ToLower(strings.TrimSpace(email))] = struct{}{}
	}
	out := make(map[string]string, len(units))
	for email, path := range units {
		email = strings.ToLower(strings.TrimSpace(email))
		path = strings.TrimSpace(path)
		if email == "" || path == "" {
			continue
		}
		if _, ok := allowed[email]; !ok {
			continue
		}
		out[email] = path
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeEmailOrgUnits(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for email, path := range src {
		email = strings.ToLower(strings.TrimSpace(email))
		path = strings.TrimSpace(path)
		if email == "" || path == "" {
			continue
		}
		if strings.TrimSpace(dst[email]) == "" {
			dst[email] = path
		}
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func orgUnitPathMapFromDomainUsers(domainUsers GmailCorporateDomainUsersResponse) map[string]string {
	if domainUsers == nil {
		return nil
	}
	raw, ok := domainUsers["organizational_units"]
	if !ok || raw == nil {
		return nil
	}
	units, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string)
	for _, item := range units {
		unit, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		unitPath := strings.TrimSpace(fmtString(unit["org_unit_path"]))
		users, _ := unit["users"].([]interface{})
		for _, userItem := range users {
			user, ok := userItem.(map[string]interface{})
			if !ok {
				continue
			}
			email := strings.ToLower(strings.TrimSpace(fmtString(user["email"])))
			if email == "" {
				continue
			}
			path := strings.TrimSpace(fmtString(user["org_unit_path"]))
			if path == "" {
				path = unitPath
			}
			if path != "" {
				out[email] = path
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func fmtString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func (s *Service) emailOrgUnitsFromDirectory(ctx context.Context, tokenKey string, credential *GoogleBackupCredential, emails []string) map[string]string {
	accessTokenExpiry := time.Time{}
	if credential.AccessTokenExpiry != nil {
		accessTokenExpiry = *credential.AccessTokenExpiry
	}
	accessToken, _, err := socialmedia.ResolveAccessToken(ctx, credential.AccessToken, credential.RefreshToken, accessTokenExpiry)
	if err != nil {
		s.log.Warn("failed to resolve google access token for job org units", zap.Error(err))
		return nil
	}
	domainUsers, err := s.fetchGmailCorporateDomainUsers(ctx, tokenKey, accessToken)
	if err != nil {
		s.log.Warn("failed to load domain-users org units for job create", zap.Error(err))
		return nil
	}
	return normalizeEmailOrgUnits(orgUnitPathMapFromDomainUsers(domainUsers), emails)
}

func googleBackupGmailEmails(services, emails []string, credential *GoogleBackupCredential) ([]string, error) {
	if !slices.Contains(services, "gmail") {
		if len(emails) > 0 {
			return nil, ErrValidation.New("emails are only allowed when gmail is selected")
		}
		return nil, nil
	}

	seen := make(map[string]struct{}, len(emails))
	out := make([]string, 0, len(emails))
	for _, email := range emails {
		email = strings.TrimSpace(email)
		if email == "" {
			return nil, ErrValidation.New("email cannot be empty")
		}
		if _, err := mail.ParseAddress(email); err != nil {
			return nil, ErrValidation.New("invalid email: %s", email)
		}
		key := strings.ToLower(email)
		if _, dup := seen[key]; dup {
			return nil, ErrValidation.New("duplicate email: %s", email)
		}
		seen[key] = struct{}{}
		out = append(out, email)
	}

	if isCorporateGoogleBackupAccount(credential.AccountType) {
		if len(out) == 0 {
			return nil, ErrValidation.New("at least one employee email is required for corporate gmail backup")
		}
		return out, nil
	}
	if len(out) == 0 {
		return []string{credential.GoogleEmail}, nil
	}
	return out, nil
}

func isCorporateGoogleBackupAccount(accountType string) bool {
	switch strings.ToLower(strings.TrimSpace(accountType)) {
	case "admin_workspace", "employee_workspace", "corporate", "workspace":
		return true
	default:
		return false
	}
}

// ConnectGoogleBackupResult is returned after POST /google-backup/connect.
type ConnectGoogleBackupResult struct {
	GoogleEmail     string
	Created         bool
	GrantedScopes   []string
	UngrantedScopes []string
}

// ConnectGoogleBackupCredential exchanges a Google OAuth code for an already logged-in user.
// redirectURI must match the frontend origin used when starting Google OAuth (same as google-backup auth).
func (s *Service) ConnectGoogleBackupCredential(ctx context.Context, code, redirectURI string) (result ConnectGoogleBackupResult, err error) {
	defer mon.Task()(&ctx)(&err)

	code = strings.TrimSpace(code)
	if code == "" {
		return result, ErrValidation.New("code is required")
	}

	user, err := GetUser(ctx)
	if err != nil {
		return result, Error.Wrap(err)
	}

	tokenRes, err := socialmedia.GetGoogleOauthTokenWithRedirect(code, "googlebackup", false, redirectURI)
	if err != nil {
		return result, ErrValidation.New("failed to exchange google oauth code: %v", err)
	}
	if tokenRes.Refresh_token == "" {
		return result, ErrValidation.New("google did not return a refresh token; re-authorize with consent")
	}

	googleUser, err := socialmedia.GetGoogleUser(tokenRes.Access_token, tokenRes.Id_token)
	if err != nil {
		return result, Error.Wrap(err)
	}

	existing, lookupErr := s.store.GoogleBackupCredentials().GetByUserIDAndGoogleEmail(ctx, user.ID, googleUser.Email)
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		return result, Error.Wrap(lookupErr)
	}
	result.Created = existing == nil
	result.GoogleEmail = googleUser.Email

	accessToken := tokenRes.Access_token
	refreshToken := tokenRes.Refresh_token
	accessTokenExpiry := tokenRes.ExpiresAt

	validAccessToken, validExpiry, err := socialmedia.ResolveAccessToken(ctx, accessToken, refreshToken, accessTokenExpiry)
	if err != nil {
		return result, Error.Wrap(err)
	}
	if !validExpiry.IsZero() {
		accessTokenExpiry = validExpiry
	}
	accessToken = validAccessToken

	if granted, scopeErr := socialmedia.ResolveGrantedScopes(ctx, accessToken, tokenRes.Scope); scopeErr != nil {
		s.log.Warn("failed to resolve google granted scopes during connect", zap.Error(scopeErr))
	} else {
		result.GrantedScopes, result.UngrantedScopes = socialmedia.GoogleBackupScopeSummary(granted)
	}

	if err := s.storeGoogleBackupCredential(ctx, user.ID, googleUser.Email, accessToken, refreshToken, accessTokenExpiry, ""); err != nil {
		return result, Error.Wrap(err)
	}

	return result, nil
}

// GetGoogleBackupDomainUsers calls Backup-Tools domain-users using stored Google backup credentials.
// Returns the same google_backup payload shape as register-google.
func (s *Service) GetGoogleBackupDomainUsers(ctx context.Context, tokenKey, googleEmail string) (googleBackup map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, ErrUnauthorized.New("session token is required")
	}

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	googleEmail = strings.TrimSpace(googleEmail)
	var credential *GoogleBackupCredential
	if googleEmail != "" {
		credential, err = s.store.GoogleBackupCredentials().GetByUserIDAndGoogleEmail(ctx, user.ID, googleEmail)
	} else {
		credential, err = s.store.GoogleBackupCredentials().GetByUserID(ctx, user.ID)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound.New("google backup credentials not found")
		}
		return nil, Error.Wrap(err)
	}
	if err := credential.ValidateForBackup(); err != nil {
		return nil, err
	}

	accessTokenExpiry := time.Time{}
	if credential.AccessTokenExpiry != nil {
		accessTokenExpiry = *credential.AccessTokenExpiry
	}

	accessToken, validExpiry, err := socialmedia.ResolveAccessToken(ctx, credential.AccessToken, credential.RefreshToken, accessTokenExpiry)
	if err != nil {
		return nil, ErrValidation.Wrap(err)
	}

	if storeErr := s.storeGoogleBackupCredential(ctx, user.ID, credential.GoogleEmail, accessToken, credential.RefreshToken, validExpiry, credential.AccountType); storeErr != nil {
		s.log.Warn("failed to persist google tokens before domain-users", zap.Error(storeErr))
	}

	domainUsers, domainErr := s.fetchGmailCorporateDomainUsers(ctx, tokenKey, accessToken)
	var domainError string
	if domainErr != nil {
		s.log.Warn("domain-users call failed", zap.Error(domainErr))
		domainError = domainErr.Error()
	} else if accountType, ok := domainUsers["account_type"].(string); ok && accountType != "" && accountType != credential.AccountType {
		if err := s.store.GoogleBackupCredentials().UpdateAccountType(ctx, credential.ID, accountType); err != nil {
			s.log.Warn("failed to update google backup account type from domain-users", zap.Error(err))
		}
	}

	return googleBackupDomainUsersPayload(domainUsers, domainError), nil
}
