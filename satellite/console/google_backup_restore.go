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
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

var allowedGoogleBackupRestoreServices = []string{
	"gmail", "drive", "photos", "calendar", "contacts",
}

// GoogleBackupRestoreAllRequest is the UI body for Backup-Tools POST /restore/all.
type GoogleBackupRestoreAllRequest struct {
	Service          string `json:"service"`
	LoginID          string `json:"login_id"`
	StorxAccessGrant string `json:"storx_access_grant"`
	GoogleAuth       string `json:"google_auth"`
}

func (r GoogleBackupRestoreAllRequest) Validate() error {
	r.Service = strings.TrimSpace(strings.ToLower(r.Service))
	r.LoginID = strings.TrimSpace(r.LoginID)
	r.StorxAccessGrant = strings.TrimSpace(r.StorxAccessGrant)
	r.GoogleAuth = strings.TrimSpace(r.GoogleAuth)

	if r.Service == "" {
		return ErrValidation.New("service is required")
	}
	if !slices.Contains(allowedGoogleBackupRestoreServices, r.Service) {
		return ErrValidation.New("unsupported service: %s", r.Service)
	}
	if r.LoginID == "" {
		return ErrValidation.New("login_id is required")
	}
	if r.StorxAccessGrant == "" {
		return ErrValidation.New("storx_access_grant is required")
	}
	if r.GoogleAuth == "" {
		return ErrValidation.New("google_auth is required (from POST /google-backup/google-auth)")
	}
	return nil
}

func (r GoogleBackupRestoreAllRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]string{
		"service":  r.Service,
		"login_id": r.LoginID,
	})
}

// BackupToolsGoogleAuth exchanges a Google id/access token for Backup-Tools google-auth JWT (POST /google-auth).
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

// StartGoogleBackupRestoreAll proxies POST /restore/all to Backup-Tools.
func (s *Service) StartGoogleBackupRestoreAll(ctx context.Context, tokenKey string, req GoogleBackupRestoreAllRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	payload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRestoreRequest(ctx, http.MethodPost, "/restore/all", tokenKey, req.StorxAccessGrant, req.GoogleAuth, payload)
}

// ProxyGoogleBackupRestoreCron proxies Backup-Tools async restore routes (/restore/*).
func (s *Service) ProxyGoogleBackupRestoreCron(ctx context.Context, method, path, tokenKey, googleAuth string, payload []byte) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.backupToolsRestoreRequest(ctx, method, path, tokenKey, "", googleAuth, payload)
}

// GoogleBackupManualRestoreRequest is the Satellite body for batch manual restore (≤10 base64 vault keys).
type GoogleBackupManualRestoreRequest struct {
	StorxAccessGrant string   `json:"storx_access_grant"`
	GoogleAuth       string   `json:"google_auth"`
	Keys             []string `json:"keys"`
}

func (r GoogleBackupManualRestoreRequest) Validate() error {
	if strings.TrimSpace(r.StorxAccessGrant) == "" {
		return ErrValidation.New("storx_access_grant is required")
	}
	if strings.TrimSpace(r.GoogleAuth) == "" {
		return ErrValidation.New("google_auth is required")
	}
	if len(r.Keys) == 0 {
		return ErrValidation.New("keys is required")
	}
	if len(r.Keys) > 10 {
		return ErrValidation.New("at most 10 keys per request")
	}
	return nil
}

// GoogleBackupManualRestore proxies Backup-Tools POST /google/* manual restore routes.
func (s *Service) GoogleBackupManualRestore(ctx context.Context, tokenKey, backupToolsPath string, req GoogleBackupManualRestoreRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	payload, err := json.Marshal(req.Keys)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRestoreRequest(ctx, http.MethodPost, backupToolsPath, tokenKey, req.StorxAccessGrant, req.GoogleAuth, payload)
}

// backupToolsRestoreRequest proxies Backup-Tools restore and manual routes (google-auth JWT + token_key; optional ACCESS_TOKEN).
func (s *Service) backupToolsRestoreRequest(ctx context.Context, method, path, tokenKey, storxAccessGrant, googleAuthJWT string, payload []byte) ([]byte, int, error) {
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
	if storxAccessGrant = strings.TrimSpace(storxAccessGrant); storxAccessGrant != "" {
		req.Header.Set("ACCESS_TOKEN", storxAccessGrant)
	}
	auth := googleAuthJWT
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		auth = "Bearer " + auth
	}
	req.Header.Set("Authorization", auth)
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
