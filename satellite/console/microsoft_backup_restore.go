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

// MicrosoftBackupManualRestoreRequest is the Satellite body for batch manual restore (≤10 base64 vault keys).
// Same UX as Google manual restore: UI selects vault keys and posts them here.
// MicrosoftAuth must be the Backup-Tools JWT from POST /microsoft-backup/microsoft-auth (not a raw Graph token).
type MicrosoftBackupManualRestoreRequest struct {
	Keys          []string `json:"keys"`
	MicrosoftAuth string   `json:"microsoft_auth"` // Backup-Tools microsoft-auth JWT (required)
	ProjectID     string   `json:"project_id,omitempty"`
	TeamID        string   `json:"team_id,omitempty"`
	ChannelID     string   `json:"channel_id,omitempty"`
	GroupID       string   `json:"group_id,omitempty"`
}

// Validate checks keys and microsoft_auth.
func (r *MicrosoftBackupManualRestoreRequest) Validate() error {
	if strings.TrimSpace(r.MicrosoftAuth) == "" {
		return ErrValidation.New("microsoft_auth (microsoft-auth JWT) is required — call POST /microsoft-backup/microsoft-auth first")
	}
	if len(r.Keys) == 0 {
		return ErrValidation.New("keys is required")
	}
	if len(r.Keys) > 10 {
		return ErrValidation.New("at most 10 keys per request")
	}
	return nil
}

// BackupToolsMicrosoftAuth exchanges a Microsoft Graph access token for Backup-Tools microsoft-auth JWT (POST /microsoft-auth).
// Mirrors BackupToolsGoogleAuth. Call before office365/satellite-to-* manual restore (all MS services).
func (s *Service) BackupToolsMicrosoftAuth(ctx context.Context, microsoftKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	microsoftKey = strings.TrimSpace(microsoftKey)
	if microsoftKey == "" {
		return nil, 0, ErrValidation.New("microsoft_key is required")
	}
	if s.backupToolsURL == "" {
		return nil, 0, Error.New("Backup-Tools URL not configured")
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("microsoft-key", microsoftKey); err != nil {
		return nil, 0, Error.Wrap(err)
	}
	if err := w.Close(); err != nil {
		return nil, 0, Error.Wrap(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.backupToolsURL, "/")+"/microsoft-auth", &buf)
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

// BackupToolsOutlookAuth is deprecated: use BackupToolsMicrosoftAuth.
func (s *Service) BackupToolsOutlookAuth(ctx context.Context, microsoftKey string) ([]byte, int, error) {
	return s.BackupToolsMicrosoftAuth(ctx, microsoftKey)
}

// MicrosoftBackupManualRestore proxies Backup-Tools POST /office365/satellite-to-* manual restore routes.
// ACCESS_TOKEN = StorX grant (from managed project); Authorization = Backup-Tools microsoft-auth JWT.
func (s *Service) MicrosoftBackupManualRestore(ctx context.Context, tokenKey, backupToolsPath string, req MicrosoftBackupManualRestoreRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if err := req.Validate(); err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	user, err := GetUser(ctx)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	project, err := s.resolveMicrosoftRestoreProject(ctx, user, req.ProjectID)
	if err != nil {
		return nil, 0, err
	}
	storxGrant, err := s.CreateAccessGrantForManagedProject(ctx, project.ID)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	payload, err := json.Marshal(req.Keys)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	path := backupToolsPath
	q := url.Values{}
	if v := strings.TrimSpace(req.TeamID); v != "" {
		q.Set("team_id", v)
	}
	if v := strings.TrimSpace(req.ChannelID); v != "" {
		q.Set("channel_id", v)
	}
	if v := strings.TrimSpace(req.GroupID); v != "" {
		q.Set("group_id", v)
	}
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}

	return s.backupToolsMicrosoftManualRestoreRequest(ctx, http.MethodPost, path, tokenKey, storxGrant, req.MicrosoftAuth, payload)
}

func (s *Service) resolveMicrosoftRestoreProject(ctx context.Context, user *User, projectID string) (*Project, error) {
	projects, err := s.store.Projects().GetOwnActive(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if len(projects) == 0 {
		return nil, ErrNotFound.New("project not found for user")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return &projects[0], nil
	}
	for i := range projects {
		if projects[i].PublicID.String() == projectID {
			return &projects[i], nil
		}
	}
	return nil, ErrNotFound.New("project not found")
}

func (s *Service) backupToolsMicrosoftManualRestoreRequest(ctx context.Context, method, path, tokenKey, storxGrant, outlookAuthJWT string, payload []byte) ([]byte, int, error) {
	if s.backupToolsURL == "" {
		return nil, 0, Error.New("Backup-Tools URL not configured")
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
	req.Header.Set("ACCESS_TOKEN", strings.TrimSpace(storxGrant))
	// Same as Google manual restore: Authorization = Backup-Tools JWT (no Bearer prefix required).
	auth := strings.TrimSpace(outlookAuthJWT)
	auth = strings.TrimPrefix(auth, "Bearer ")
	req.Header.Set("Authorization", auth)
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
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

var allowedMicrosoftBackupRestoreServices = []string{
	"outlook", "mail",
	"outlook_calendar", "calendar",
	"outlook_contacts", "contacts",
	"outlook_onedrive", "onedrive",
	"outlook_sharepoint", "sharepoint",
	"outlook_teams", "teams",
	"outlook_groups", "groups",
}

// normalizeMicrosoftBackupRestoreService maps UI aliases to Backup-Tools service names.
func normalizeMicrosoftBackupRestoreService(service string) string {
	switch strings.TrimSpace(strings.ToLower(service)) {
	case "mail", "outlook":
		return "outlook"
	case "calendar", "outlook_calendar":
		return "outlook_calendar"
	case "contacts", "outlook_contacts":
		return "outlook_contacts"
	case "onedrive", "outlook_onedrive":
		return "outlook_onedrive"
	case "sharepoint", "outlook_sharepoint":
		return "outlook_sharepoint"
	case "teams", "outlook_teams":
		return "outlook_teams"
	case "groups", "outlook_groups":
		return "outlook_groups"
	default:
		return strings.TrimSpace(strings.ToLower(service))
	}
}

// MicrosoftBackupRestorePrepareParams are query params for Backup-Tools GET /restore/prepare (MS services).
type MicrosoftBackupRestorePrepareParams struct {
	ProjectID   string
	LoginID     string
	Service     string
	TargetEmail string
}

func (p *MicrosoftBackupRestorePrepareParams) Validate() error {
	p.ProjectID = strings.TrimSpace(p.ProjectID)
	p.LoginID = strings.TrimSpace(p.LoginID)
	p.Service = normalizeMicrosoftBackupRestoreService(p.Service)

	if p.ProjectID == "" {
		return ErrValidation.New("project_id is required")
	}
	if p.LoginID == "" {
		return ErrValidation.New("login_id is required")
	}
	if p.Service == "" {
		return ErrValidation.New("service is required")
	}
	if !slices.Contains(allowedMicrosoftBackupRestoreServices, p.Service) &&
		!slices.Contains([]string{"outlook", "outlook_calendar", "outlook_contacts", "outlook_onedrive", "outlook_sharepoint", "outlook_teams", "outlook_groups"}, p.Service) {
		return ErrValidation.New("unsupported service: %s", p.Service)
	}
	return nil
}

func (p MicrosoftBackupRestorePrepareParams) queryString() string {
	v := url.Values{}
	v.Set("project_id", p.ProjectID)
	v.Set("login_id", p.LoginID)
	v.Set("service", p.Service)
	if target := strings.TrimSpace(p.TargetEmail); target != "" {
		v.Set("target_email", target)
	}
	return v.Encode()
}

// MicrosoftBackupRestoreAllRequest is the UI body for Backup-Tools POST /restore/all (MS).
type MicrosoftBackupRestoreAllRequest struct {
	Service     string `json:"service"`
	ProjectID   string `json:"project_id"`
	LoginID     string `json:"login_id"`
	TargetEmail string `json:"target_email,omitempty"`
}

func (r *MicrosoftBackupRestoreAllRequest) Validate() error {
	r.Service = normalizeMicrosoftBackupRestoreService(r.Service)
	r.ProjectID = strings.TrimSpace(r.ProjectID)
	r.LoginID = strings.TrimSpace(r.LoginID)

	if r.Service == "" {
		return ErrValidation.New("service is required")
	}
	if !slices.Contains([]string{"outlook", "outlook_calendar", "outlook_contacts", "outlook_onedrive", "outlook_sharepoint", "outlook_teams", "outlook_groups"}, r.Service) {
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

func (r *MicrosoftBackupRestoreAllRequest) backupToolsPayload() ([]byte, error) {
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

var microsoftRestoreCredentialsAllowedQuery = map[string]struct{}{
	"search":   {},
	"limit":    {},
	"offset":   {},
	"login_id": {},
	"provider": {},
}

var microsoftRestoreWorkspacesAllowedQuery = map[string]struct{}{
	"domain":   {},
	"search":   {},
	"limit":    {},
	"offset":   {},
	"login_id": {},
	"provider": {},
}

// PrepareMicrosoftBackupRestore proxies GET /restore/prepare for Microsoft services (token_key only).
func (s *Service) PrepareMicrosoftBackupRestore(ctx context.Context, tokenKey string, params MicrosoftBackupRestorePrepareParams) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	if err := (&params).Validate(); err != nil {
		return nil, 0, err
	}
	path := "/restore/prepare?" + (&params).queryString()
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// StartMicrosoftBackupRestoreAll proxies POST /restore/all for Microsoft services (token_key only).
func (s *Service) StartMicrosoftBackupRestoreAll(ctx context.Context, tokenKey string, req MicrosoftBackupRestoreAllRequest) (body []byte, status int, err error) {
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

// ProxyMicrosoftBackupRestoreCron proxies Backup-Tools async restore routes (/restore/*) with token_key only.
func (s *Service) ProxyMicrosoftBackupRestoreCron(ctx context.Context, method, path, tokenKey string, payload []byte) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.backupToolsRequest(ctx, method, path, tokenKey, "", payload)
}

// ListMicrosoftBackupRestoreCredentials proxies GET /restore/credentials?provider=microsoft.
func (s *Service) ListMicrosoftBackupRestoreCredentials(ctx context.Context, tokenKey, rawQuery string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	path := "/restore/credentials"
	q := filterRestoreQuery(rawQuery, microsoftRestoreCredentialsAllowedQuery)
	values, _ := url.ParseQuery(q)
	values.Set("provider", "microsoft")
	path += "?" + values.Encode()
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// ListMicrosoftBackupRestoreWorkspaces proxies GET /restore/workspaces?provider=microsoft.
func (s *Service) ListMicrosoftBackupRestoreWorkspaces(ctx context.Context, tokenKey, rawQuery string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	path := "/restore/workspaces"
	q := filterRestoreQuery(rawQuery, microsoftRestoreWorkspacesAllowedQuery)
	values, _ := url.ParseQuery(q)
	values.Set("provider", "microsoft")
	path += "?" + values.Encode()
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

// CancelMicrosoftBackupRestoreJob proxies Backup-Tools POST /restore/job/{job_id}/cancel.
func (s *Service) CancelMicrosoftBackupRestoreJob(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}
	path := "/restore/job/" + url.PathEscape(jobID) + "/cancel"
	return s.backupToolsRequest(ctx, http.MethodPost, path, tokenKey, "", nil)
}
