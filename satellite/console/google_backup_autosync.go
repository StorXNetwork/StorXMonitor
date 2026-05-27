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

	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

type CreateGoogleBackupAutoSyncJobsRequest struct {
	Services []string
	Interval string
	Emails   []string
}

// UpdateGoogleBackupAutoSyncJobsByProjectRequest is the UI → satellite body for
// Backup-Tools PUT /auto-sync/job/project (project_id in JSON body, not URL path).
type UpdateGoogleBackupAutoSyncJobsByProjectRequest struct {
	ProjectID    string `json:"project_id"`
	GoogleEmail  string `json:"google_email,omitempty"`
	StorxToken   string `json:"storx_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Interval     string `json:"interval,omitempty"`
	On           string `json:"on,omitempty"`
	Active       *bool  `json:"active,omitempty"`
}

// Validate requires project_id and google_email; other fields are optional.
func (r UpdateGoogleBackupAutoSyncJobsByProjectRequest) Validate() error {
	r.ProjectID = strings.TrimSpace(r.ProjectID)
	if r.ProjectID == "" {
		return ErrValidation.New("project_id is required")
	}

	googleEmail := strings.TrimSpace(r.GoogleEmail)
	if googleEmail == "" {
		return ErrValidation.New("google_email is required (legacy email is no longer supported)")
	}
	if googleEmail != "" {
		if _, err := mail.ParseAddress(googleEmail); err != nil {
			return ErrValidation.New("invalid google_email: %s", googleEmail)
		}
	}
	return nil
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
	if v := strings.TrimSpace(r.Interval); v != "" {
		out["interval"] = v
	}
	if v := strings.TrimSpace(r.On); v != "" {
		out["on"] = v
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
		"1h": {}, "6h": {}, "nightly": {},
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
func (s *Service) UpdateGoogleBackupAutoSyncJobsByProject(ctx context.Context, tokenKey string, req UpdateGoogleBackupAutoSyncJobsByProjectRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	return s.backupToolsRequest(ctx, http.MethodPut, "/auto-sync/job/project", tokenKey, "", btPayload)
}

func (s *Service) UpdateGoogleBackupAutoSyncJob(ctx context.Context, tokenKey, jobID string, payload []byte) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}
	if len(payload) == 0 {
		return nil, 0, ErrValidation.New("request body is required")
	}

	path := "/auto-sync/job/" + url.PathEscape(jobID)
	return s.backupToolsRequest(ctx, http.MethodPut, path, tokenKey, "", payload)
}

func (s *Service) BulkUpdateGoogleBackupGmailJobs(ctx context.Context, tokenKey string, payload []byte) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if len(payload) == 0 {
		return nil, 0, ErrValidation.New("request body is required")
	}

	return s.backupToolsRequest(ctx, http.MethodPut, "/auto-sync/job/gmail/bulk-update", tokenKey, "", payload)
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
	onboardingEnd, step := true, "GoogleBackupServices"
	if _, err := s.SetUserSettings(ctx, UpsertUserSettingsRequest{
		OnboardingEnd: &onboardingEnd, OnboardingStep: &step,
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
