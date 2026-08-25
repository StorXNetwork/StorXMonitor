// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

// UpdateBackupAutoSyncJobsByProjectRequest is the UI body for Backup-Tools PUT /auto-sync/job/project
// (Google + Microsoft). Backup-Tools still uses google_email for the mailbox field; Satellite maps
// microsoft_email into it when google_email is omitted.
type UpdateBackupAutoSyncJobsByProjectRequest struct {
	ProjectID      string `json:"project_id"`
	GoogleEmail    string `json:"google_email,omitempty"`
	MicrosoftEmail string `json:"microsoft_email,omitempty"`
	CredentialID   *int   `json:"credential_id,omitempty"`
	Code           string `json:"code,omitempty"`
	StorxToken     string `json:"storx_token,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	Active         *bool  `json:"active,omitempty"`
}

// UpdateBackupAutoSyncJobRequest is the UI body for Backup-Tools PUT /auto-sync/job/{job_id}.
type UpdateBackupAutoSyncJobRequest struct {
	Active                        *bool  `json:"active,omitempty"`
	RefreshToken                  string `json:"refresh_token,omitempty"`
	StorxToken                    string `json:"storx_token,omitempty"`
	ApplyStorxToAllLinkedAccounts *bool  `json:"apply_storx_to_all_linked_accounts,omitempty"`
}

func (r UpdateBackupAutoSyncJobsByProjectRequest) mailboxEmail() string {
	if v := strings.TrimSpace(r.GoogleEmail); v != "" {
		return v
	}
	return strings.TrimSpace(r.MicrosoftEmail)
}

func (r UpdateBackupAutoSyncJobsByProjectRequest) Validate() error {
	r.ProjectID = strings.TrimSpace(r.ProjectID)
	if r.ProjectID == "" {
		return ErrValidation.New("project_id is required")
	}
	googleEmail := strings.TrimSpace(r.GoogleEmail)
	microsoftEmail := strings.TrimSpace(r.MicrosoftEmail)
	if googleEmail != "" {
		if _, err := mail.ParseAddress(googleEmail); err != nil {
			return ErrValidation.New("invalid google_email: %s", googleEmail)
		}
	}
	if microsoftEmail != "" {
		if _, err := mail.ParseAddress(microsoftEmail); err != nil {
			return ErrValidation.New("invalid microsoft_email: %s", microsoftEmail)
		}
	}
	code := strings.TrimSpace(r.Code)
	if code != "" && googleEmail == "" && microsoftEmail == "" {
		return ErrValidation.New("google_email or microsoft_email is required when code is set")
	}
	if code != "" && googleEmail != "" && microsoftEmail != "" {
		return ErrValidation.New("set only one of google_email or microsoft_email when code is set")
	}
	if v := strings.TrimSpace(r.RefreshToken); v != "" && looksLikeOAuthJWT(v) {
		return ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
	}
	if !r.hasUpdateFields() {
		return ErrValidation.New("at least one update field is required")
	}
	if code != "" || strings.TrimSpace(r.RefreshToken) != "" {
		if googleEmail == "" && microsoftEmail == "" && r.CredentialID == nil {
			return ErrValidation.New("google_email, microsoft_email, or credential_id is required when updating tokens")
		}
	}
	return nil
}

func (r UpdateBackupAutoSyncJobsByProjectRequest) hasUpdateFields() bool {
	return strings.TrimSpace(r.Code) != "" ||
		strings.TrimSpace(r.RefreshToken) != "" ||
		strings.TrimSpace(r.StorxToken) != "" ||
		r.Active != nil
}

func (r UpdateBackupAutoSyncJobsByProjectRequest) backupToolsPayload() ([]byte, error) {
	out := map[string]interface{}{
		"project_id": strings.TrimSpace(r.ProjectID),
	}
	if email := r.mailboxEmail(); email != "" {
		out["google_email"] = email
	}
	if r.CredentialID != nil {
		out["credential_id"] = *r.CredentialID
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

func (r UpdateBackupAutoSyncJobRequest) Validate() error {
	if r.Active == nil &&
		strings.TrimSpace(r.RefreshToken) == "" &&
		strings.TrimSpace(r.StorxToken) == "" &&
		r.ApplyStorxToAllLinkedAccounts == nil {
		return ErrValidation.New("at least one update field is required")
	}
	return nil
}

func (r UpdateBackupAutoSyncJobRequest) backupToolsPayload() ([]byte, error) {
	out := map[string]interface{}{}
	if r.Active != nil {
		out["active"] = *r.Active
	}
	if v := strings.TrimSpace(r.RefreshToken); v != "" {
		out["refresh_token"] = v
	}
	if v := strings.TrimSpace(r.StorxToken); v != "" {
		out["storx_token"] = v
	}
	if r.ApplyStorxToAllLinkedAccounts != nil {
		out["apply_storx_to_all_linked_accounts"] = *r.ApplyStorxToAllLinkedAccounts
	}
	return json.Marshal(out)
}

// ListBackupAutoSyncJobServices proxies Backup-Tools GET /auto-sync/job/services.
func (s *Service) ListBackupAutoSyncJobServices(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	return s.backupToolsRequest(ctx, http.MethodGet, "/auto-sync/job/services", tokenKey, "", nil)
}

// ListBackupAutoSyncLive proxies Backup-Tools GET /auto-sync/live.
func (s *Service) ListBackupAutoSyncLive(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	return s.backupToolsRequest(ctx, http.MethodGet, "/auto-sync/live", tokenKey, "", nil)
}

// ListBackupAutoSyncJobs proxies Backup-Tools GET /auto-sync/job/ (Google + Microsoft).
func (s *Service) ListBackupAutoSyncJobs(ctx context.Context, tokenKey, filter string) (body []byte, status int, err error) {
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

// GetBackupAutoSyncJob proxies Backup-Tools GET /auto-sync/job/{job_id}.
func (s *Service) GetBackupAutoSyncJob(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
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

// UpdateBackupAutoSyncJobsByProject proxies Backup-Tools PUT /auto-sync/job/project.
func (s *Service) UpdateBackupAutoSyncJobsByProject(ctx context.Context, tokenKey string, req UpdateBackupAutoSyncJobsByProjectRequest, redirectURI string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	if err := s.applyBackupAutoSyncProjectUpdateTokens(ctx, &req, redirectURI); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	return s.backupToolsRequest(ctx, http.MethodPut, "/auto-sync/job/project", tokenKey, "", btPayload)
}

func (s *Service) applyBackupAutoSyncProjectUpdateTokens(ctx context.Context, req *UpdateBackupAutoSyncJobsByProjectRequest, redirectURI string) error {
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	code := strings.TrimSpace(req.Code)
	refreshToken := strings.TrimSpace(req.RefreshToken)
	googleEmail := strings.TrimSpace(req.GoogleEmail)
	microsoftEmail := strings.TrimSpace(req.MicrosoftEmail)

	if code != "" {
		if microsoftEmail != "" {
			// Same guards as ConnectMicrosoftBackupCredential / Google grant path.
			if looksLikeOAuthJWT(code) {
				return ErrValidation.New("code must be a Microsoft OAuth authorization code, not an access/id token JWT")
			}
			tokenRes, err := socialmedia.GetMicrosoftOauthTokenWithRedirect(code, redirectURI)
			if err != nil {
				return ErrValidation.New("failed to exchange microsoft oauth code: %v", err)
			}
			if strings.TrimSpace(tokenRes.Refresh_token) == "" {
				return ErrValidation.New("microsoft did not return a refresh token; re-authorize with consent and offline_access")
			}
			if looksLikeOAuthJWT(tokenRes.Refresh_token) {
				return ErrValidation.New("microsoft refresh_token looks like a JWT; check OUTLOOK client and offline_access scope")
			}
			// Empty accountType/tenant → preserve existing row fields (same as Google grant passes "").
			if err := s.StoreMicrosoftBackupCredential(ctx, user.ID, microsoftEmail, tokenRes.Access_token, tokenRes.Refresh_token, tokenRes.ExpiresAt, "", "", ""); err != nil {
				return err
			}
			req.RefreshToken = tokenRes.Refresh_token
			req.Code = ""
			return nil
		}

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

	if microsoftEmail != "" {
		if err := s.StoreMicrosoftBackupCredential(ctx, user.ID, microsoftEmail, "", refreshToken, time.Time{}, "", "", ""); err != nil {
			return err
		}
		req.RefreshToken = refreshToken
		return nil
	}

	if googleEmail == "" {
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

// TriggerBackupAutoSyncBackupNow proxies Backup-Tools POST /auto-sync/task/{job_id}/backup-now.
func (s *Service) TriggerBackupAutoSyncBackupNow(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
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

// UpdateBackupAutoSyncJob proxies Backup-Tools PUT /auto-sync/job/{job_id}.
func (s *Service) UpdateBackupAutoSyncJob(ctx context.Context, tokenKey, jobID string, req UpdateBackupAutoSyncJobRequest) (body []byte, status int, err error) {
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
