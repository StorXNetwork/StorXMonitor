// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

var allowedGoogleBackupRestoreServices = []string{
	"gmail", "drive", "photos", "calendar", "contacts",
}

// GoogleBackupRestorePrepareParams are query params for Backup-Tools GET /restore/prepare.
type GoogleBackupRestorePrepareParams struct {
	ProjectID   string
	LoginID     string
	Service     string
	TargetEmail string
}

func (p *GoogleBackupRestorePrepareParams) Validate() error {
	p.ProjectID = strings.TrimSpace(p.ProjectID)
	p.LoginID = strings.TrimSpace(p.LoginID)
	p.Service = strings.TrimSpace(strings.ToLower(p.Service))

	if p.ProjectID == "" {
		return ErrValidation.New("project_id is required")
	}
	if p.LoginID == "" {
		return ErrValidation.New("login_id is required")
	}
	if p.Service == "" {
		return ErrValidation.New("service is required")
	}
	if !slices.Contains(allowedGoogleBackupRestoreServices, p.Service) {
		return ErrValidation.New("unsupported service: %s", p.Service)
	}
	return nil
}

func (p GoogleBackupRestorePrepareParams) queryString() string {
	v := url.Values{}
	v.Set("project_id", p.ProjectID)
	v.Set("login_id", p.LoginID)
	v.Set("service", p.Service)
	if target := strings.TrimSpace(p.TargetEmail); target != "" {
		v.Set("target_email", target)
	}
	return v.Encode()
}

// GoogleBackupRestoreAllRequest is the UI body for Backup-Tools POST /restore/all.
// Backup-Tools resolves StorX and Google credentials from DB using token_key; do not send grants or JWT.
type GoogleBackupRestoreAllRequest struct {
	Service     string `json:"service"`
	ProjectID   string `json:"project_id"`
	LoginID     string `json:"login_id"`
	TargetEmail string `json:"target_email,omitempty"`
}

func (r *GoogleBackupRestoreAllRequest) Validate() error {
	r.Service = strings.TrimSpace(strings.ToLower(r.Service))
	r.ProjectID = strings.TrimSpace(r.ProjectID)
	r.LoginID = strings.TrimSpace(r.LoginID)

	if r.Service == "" {
		return ErrValidation.New("service is required")
	}
	if !slices.Contains(allowedGoogleBackupRestoreServices, r.Service) {
		return ErrValidation.New("unsupported service: %s", r.Service)
	}
	if r.ProjectID == "" {
		return ErrValidation.New("project_id is required")
	}
	if r.LoginID == "" {
		return ErrValidation.New("login_id is required")
	}
	return nil
}

func (r *GoogleBackupRestoreAllRequest) backupToolsPayload() ([]byte, error) {
	out := map[string]string{
		"service":    r.Service,
		"project_id": r.ProjectID,
		"login_id":   r.LoginID,
	}
	if target := strings.TrimSpace(r.TargetEmail); target != "" {
		out["target_email"] = target
	}
	return json.Marshal(out)
}

var restoreCredentialsAllowedQuery = map[string]struct{}{
	"search":   {},
	"limit":    {},
	"offset":   {},
	"login_id": {},
}

var restoreWorkspacesAllowedQuery = map[string]struct{}{
	"domain":   {},
	"search":   {},
	"limit":    {},
	"offset":   {},
	"login_id": {},
}

func filterRestoreQuery(rawQuery string, allowed map[string]struct{}) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	filtered := url.Values{}
	for key, vals := range values {
		if _, ok := allowed[key]; ok {
			filtered[key] = vals
		}
	}
	return filtered.Encode()
}

// PrepareGoogleBackupRestore proxies GET /restore/prepare (token_key only).
func (s *Service) PrepareGoogleBackupRestore(ctx context.Context, tokenKey string, params GoogleBackupRestorePrepareParams) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if err := (&params).Validate(); err != nil {
		return nil, 0, err
	}
	path := "/restore/prepare?" + (&params).queryString()
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// StartGoogleBackupRestoreAll proxies POST /restore/all to Backup-Tools (token_key only).
func (s *Service) StartGoogleBackupRestoreAll(ctx context.Context, tokenKey string, req GoogleBackupRestoreAllRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if err := (&req).Validate(); err != nil {
		return nil, 0, err
	}
	payload, err := (&req).backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPost, "/restore/all", tokenKey, "", payload)
}

// ProxyGoogleBackupRestoreCron proxies Backup-Tools async restore routes (/restore/*) with token_key only.
func (s *Service) ProxyGoogleBackupRestoreCron(ctx context.Context, method, path, tokenKey string, payload []byte) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.backupToolsRequest(ctx, method, path, tokenKey, "", payload)
}

// ListGoogleBackupRestoreCredentials proxies GET /restore/credentials (token_key only; no project_id).
func (s *Service) ListGoogleBackupRestoreCredentials(ctx context.Context, tokenKey, rawQuery string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	path := "/restore/credentials"
	if q := filterRestoreQuery(rawQuery, restoreCredentialsAllowedQuery); q != "" {
		path += "?" + q
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// ListGoogleBackupRestoreWorkspaces proxies GET /restore/workspaces (domain tabs or mailbox list).
func (s *Service) ListGoogleBackupRestoreWorkspaces(ctx context.Context, tokenKey, rawQuery string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	path := "/restore/workspaces"
	if q := filterRestoreQuery(rawQuery, restoreWorkspacesAllowedQuery); q != "" {
		path += "?" + q
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// CancelGoogleBackupRestoreJob proxies Backup-Tools POST /restore/job/{job_id}/cancel.
func (s *Service) CancelGoogleBackupRestoreJob(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}
	path := "/restore/job/" + url.PathEscape(jobID) + "/cancel"
	return s.backupToolsRequest(ctx, http.MethodPost, path, tokenKey, "", nil)
}

// BackupToolsGoogleAuth exchanges a Google id/access token for Backup-Tools google-auth JWT (POST /google-auth).
// Used by manual /google/* restore routes only, not restore-all scheduler.
func (s *Service) BackupToolsGoogleAuth(ctx context.Context, googleKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	googleKey = strings.TrimSpace(googleKey)
	if googleKey == "" {
		return nil, 0, ErrValidation.New("google_key is required")
	}
	if s.backupToolsURL == "" {
		return nil, 0, Error.New("Backup-Tools URL not configured")
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("google-key", googleKey); err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if err := w.Close(); err != nil {
		return nil, 0, Error.Wrap(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.backupToolsURL, "/")+"/google-auth", &buf)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, Error.Wrap(err)
	}
	return body, resp.StatusCode, nil
}

// GoogleBackupManualRestoreRequest is the Satellite body for batch manual restore (≤10 base64 vault keys).
// Backup-Tools resolves the StorX access grant from the linked backup job/credential in DB.
type GoogleBackupManualRestoreRequest struct {
	GoogleAuth string   `json:"google_auth"`
	Keys       []string `json:"keys"`
}

func (r GoogleBackupManualRestoreRequest) Validate() error {
	if strings.TrimSpace(r.GoogleAuth) == "" {
		return ErrValidation.New("Authorization header is required")
	}
	if len(r.Keys) == 0 {
		return ErrValidation.New("keys or ids is required")
	}
	if len(r.Keys) > 10 {
		return ErrValidation.New("at most 10 keys per request")
	}
	return nil
}

// GoogleBackupManualRestore proxies Backup-Tools POST /google/* manual restore routes (google-auth JWT + token_key).
func (s *Service) GoogleBackupManualRestore(ctx context.Context, tokenKey, backupToolsPath string, req GoogleBackupManualRestoreRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	payload, err := json.Marshal(req.Keys)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsManualRestoreRequest(ctx, http.MethodPost, backupToolsPath, tokenKey, req.GoogleAuth, payload)
}

// backupToolsManualRestoreRequest proxies Backup-Tools manual /google/* routes (google-auth JWT + token_key).
func (s *Service) backupToolsManualRestoreRequest(ctx context.Context, method, path, tokenKey, googleAuthJWT string, payload []byte) ([]byte, int, error) {
	if s.backupToolsURL == "" {
		return nil, 0, Error.New("Backup-Tools URL not configured")
	}
	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, Error.New("token_key is required")
	}
	googleAuthJWT = strings.TrimSpace(googleAuthJWT)
	if googleAuthJWT == "" {
		return nil, 0, Error.New("google_auth is required")
	}

	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.backupToolsURL, "/")+path, bodyReader)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	req.Header.Set("token_key", tokenKey)
	req.Header.Set("Authorization", googleAuthJWT)
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, Error.Wrap(err)
	}
	return body, resp.StatusCode, nil
}
