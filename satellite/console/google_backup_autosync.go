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

type CreateGoogleBackupAutoSyncJobsRequest struct {
	Services []string
	Interval string
	On       string
	Emails   []string
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

var (
	allowedGoogleBackupServices = map[string]struct{}{
		"gmail": {}, "drive": {}, "photos": {}, "contacts": {}, "calendar": {},
	}
	allowedGoogleBackupIntervals = map[string]struct{}{
		"1h": {}, "3h": {}, "6h": {}, "12h": {}, "nightly": {}, "weekly": {}, "monthly": {},
	}
)

func (s *Service) CreateGoogleBackupAutoSyncJobs(ctx context.Context, req CreateGoogleBackupAutoSyncJobsRequest, tokenKey, syncType string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	req.Services, req.Interval, err = normalizeGoogleBackupAutoSyncRequest(req.Services, req.Interval)
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

	gmailEmails, err := googleBackupGmailEmails(req.Services, req.Emails, credential)
	if err != nil {
		return nil, 0, err
	}

	projects, err := s.GetUsersProjects(ctx)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if len(projects) != 1 {
		if len(projects) == 0 {
			return nil, 0, ErrNotFound.New("project not found for user")
		}
		return nil, 0, Error.New("expected exactly one project per user, found %d", len(projects))
	}

	payload := map[string]interface{}{
		"services":          req.Services,
		"interval":          req.Interval,
		"on":                strings.TrimSpace(req.On),
		"google_email":      credential.GoogleEmail,
		"account_type":      credential.AccountType,
		"project_id":        projects[0].ID.String(),
		"satellite_user_id": user.ID.String(),
		"refresh_token":     credential.RefreshToken,
	}
	if len(gmailEmails) > 0 {
		payload["emails"] = gmailEmails
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
func (s *Service) UpdateGoogleBackupAutoSyncJobsByProject(ctx context.Context, tokenKey string, req UpdateGoogleBackupAutoSyncJobsByProjectRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	if err := s.applyGoogleBackupProjectUpdateTokens(ctx, &req); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	return s.backupToolsRequest(ctx, http.MethodPut, "/auto-sync/job/project", tokenKey, "", btPayload)
}

func (s *Service) applyGoogleBackupProjectUpdateTokens(ctx context.Context, req *UpdateGoogleBackupAutoSyncJobsByProjectRequest) error {
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	googleEmail := strings.TrimSpace(req.GoogleEmail)
	code := strings.TrimSpace(req.Code)
	refreshToken := strings.TrimSpace(req.RefreshToken)

	if code != "" {
		tokenRes, err := socialmedia.GetGoogleOauthToken(code, "signin", false)
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

func normalizeGoogleBackupAutoSyncRequest(services []string, interval string) ([]string, string, error) {
	if len(services) == 0 {
		return nil, "", Error.New("at least one service is required")
	}
	interval = normalizeGoogleBackupInterval(interval)
	if interval == "" {
		return nil, "", Error.New("interval is required")
	}
	if _, ok := allowedGoogleBackupIntervals[interval]; !ok {
		return nil, "", Error.New("unsupported interval: %s", interval)
	}

	seen := make(map[string]struct{}, len(services))
	out := make([]string, 0, len(services))
	for _, service := range services {
		s := strings.ToLower(strings.TrimSpace(service))
		if s == "" {
			return nil, "", Error.New("service name cannot be empty")
		}
		if _, ok := allowedGoogleBackupServices[s]; !ok {
			return nil, "", Error.New("unsupported service: %s", service)
		}
		if _, dup := seen[s]; dup {
			return nil, "", Error.New("duplicate service: %s", service)
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, interval, nil
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

// ConnectGoogleBackupCredential exchanges a Google OAuth code for an already logged-in user (login redirect, not register).
// The UI must request backup scopes on the Google consent screen; redirect_uri must match GOOGLE_OAUTH_REDIRECT_URL_LOGIN.
func (s *Service) ConnectGoogleBackupCredential(ctx context.Context, code string) (result ConnectGoogleBackupResult, err error) {
	defer mon.Task()(&ctx)(&err)

	code = strings.TrimSpace(code)
	if code == "" {
		return result, ErrValidation.New("code is required")
	}

	user, err := GetUser(ctx)
	if err != nil {
		return result, Error.Wrap(err)
	}

	tokenRes, err := socialmedia.GetGoogleOauthToken(code, "connect", false)
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
