// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// MicrosoftBackup proxies Microsoft Backup auto-sync and browse operations to Backup-Tools /microsoft/*.
type MicrosoftBackup struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewMicrosoftBackup constructs a Microsoft Backup HTTP controller.
func NewMicrosoftBackup(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *MicrosoftBackup {
	return &MicrosoftBackup{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (m *MicrosoftBackup) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := m.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (m *MicrosoftBackup) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: m.log, service: m.service, cookieAuth: m.cookieAuth}).serveJSONError(ctx, w, err)
}

// ConnectMicrosoft exchanges an OAuth code and upserts backup_credentials for the logged-in user.
//
// @Summary      Connect Microsoft account for backup
// @Description  **Route:** `POST /api/v0/microsoft-backup/connect`. Same pattern as `POST /google-backup/connect`. Body: Microsoft OAuth `code` only (from UI-built authorize URL); `redirect_uri` is derived server-side from request Host. Requires real refresh_token. Returns `email`, `account_type`, and `has_refresh_token`. Tokens stored server-side only.
// @Tags         microsoft-backup
// @Accept       json
// @Produce      json
// @Param        body  body      MicrosoftBackupConnectSwaggerRequest  true  "OAuth authorization code"
// @Success      200   {object}  MicrosoftBackupConnectSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/connect [post]
func (m *MicrosoftBackup) ConnectMicrosoft(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	var body MicrosoftBackupConnectSwaggerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		m.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		m.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	redirectURI := socialmedia.ResolveMicrosoftBackupOrigin(r)
	connectResult, err := m.service.ConnectMicrosoftBackupCredential(ctx, body.Code, redirectURI, tokenKey)
	m.service.RecordUserAudit(ctx, "MB_CONNECT", "Microsoft account", "Microsoft account connected", err)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	microsoftBackup := console.MicrosoftBackupRegistrationPayload(console.RegisterMicrosoftBackupResult{
		MicrosoftEmail:  connectResult.MicrosoftEmail,
		AccountType:     connectResult.AccountType,
		HasRefreshToken: connectResult.HasRefreshToken,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(MicrosoftBackupConnectSwaggerResponse{
		Success:         true,
		MicrosoftEmail:  connectResult.MicrosoftEmail,
		Created:         connectResult.Created,
		HasRefreshToken: connectResult.HasRefreshToken,
		MicrosoftBackup: microsoftBackup,
	}); err != nil {
		m.log.Error("failed to encode microsoft connect response", zap.Error(err))
	}
}

// GetCorporateDomainUsers loads domain-users via stored Microsoft credentials (Google domain-users parity).
//
// @Summary      Microsoft corporate domain users
// @Description  **Route:** `GET /api/v0/microsoft-backup/domain-users` (also `.../outlook/corporate/domain-users`). Uses the refresh_token stored in `backup_credentials`. Returns Backup-Tools JSON under `microsoft_backup` and updates `account_type` when present.
// @Tags         microsoft-backup
// @Produce      json
// @Param        credential_id    query   string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        microsoft_email  query   string  false  "Microsoft mailbox email (defaults to stored credential)"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/domain-users [get]
func (m *MicrosoftBackup) GetCorporateDomainUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	microsoftEmail := strings.TrimSpace(r.URL.Query().Get("microsoft_email"))
	credentialID := microsoftTenantSelectionFromRequest(r).CredentialID
	microsoftBackup, err := m.service.GetMicrosoftBackupDomainUsers(ctx, tokenKey, "", credentialID, microsoftEmail)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"microsoft_backup": microsoftBackup,
	}); err != nil {
		m.log.Error("failed to encode microsoft domain-users response", zap.Error(err))
	}
}

// CreateAutoSyncJobs creates Microsoft Backup auto-sync jobs (Backup-Tools POST /microsoft/auto-sync/job).
//
// @Summary      Create Microsoft Backup auto-sync jobs
// @Description  **Route:** `POST /api/v0/microsoft-backup/auto-sync/job`. The body selects the Microsoft account (`credential_id`, optional with one account) and the tenant (`tenant_id`: required in both modes, the tenant connected via `POST /microsoft-backup/tenants/{tid}/connect`; the home tenant is never assumed; error 400 `tenant_id_required`). Satellite enriches the UI payload (account_type, project_id, storx_token), sends the selected `tenant_id` plus the `MICROSOFT_ACCOUNT_ID` / `MICROSOFT_HOME_TENANT_ID` / `MICROSOFT_TENANT_ID` headers, and POSTs Backup-Tools `/microsoft/auto-sync/job`. `backup_mode` decides the job's `auth_mode`: `self` (default) → `delegated`, own mailbox only, refresh_token sent; `organization` → `application`, tenant users via `all_users`/`user_ids`/`emails`, no refresh token sent. Backup-Tools authorizes organization jobs from tenant consent and capabilities, never from `account_type`. Services: outlook/mail, calendar, contacts, onedrive (`outlook_onedrive`), sharepoint (`outlook_sharepoint` + `sites[]`), teams (`outlook_teams` + `teams[]` or `backup_scope=all_tenant`). In own-nodes mode jobs are created inactive until enough nodes exist. On success (no failed jobs) sets onboarding to `MicrosoftBackupCompleted`.
// @Tags         microsoft-backup
// @Accept       json
// @Produce      json
// @Param        sync_type  query     string  false  "daily or one_time (default daily)"
// @Param        body       body      CreateMicrosoftBackupAutoSyncJobsSwaggerRequest  true  "Job create request"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/auto-sync/job [post]
func (m *MicrosoftBackup) CreateAutoSyncJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	var req console.CreateMicrosoftBackupAutoSyncJobsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		m.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	syncType := r.URL.Query().Get("sync_type")
	respBody, status, err := m.service.CreateMicrosoftBackupAutoSyncJobs(ctx, req, tokenKey, syncType)
	m.service.RecordUserAuditHTTP(ctx, "MB_JOB_CREATE", "Microsoft auto-sync job", "Microsoft auto-sync job created", status, respBody, err)
	if err == nil && status == http.StatusOK {
		var jobCreateResp struct {
			Failed []json.RawMessage `json:"failed"`
		}
		if json.Unmarshal(respBody, &jobCreateResp) == nil && len(jobCreateResp.Failed) == 0 {
			m.service.RecordUserAudit(ctx, "MB_ONBOARDING_COMPLETE", "Microsoft Backup onboarding", "Microsoft Backup onboarding completed", nil)
		}
	}
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// MicrosoftBackupManualRestoreSwaggerRequest is the UI body for manual restore (1–10 base64 vault keys).
// microsoft_auth = Backup-Tools JWT from POST /microsoft-backup/microsoft-auth (same role as Google Authorization after google-auth).
type MicrosoftBackupManualRestoreSwaggerRequest struct {
	Keys          []string `json:"keys" example:"base64VaultKey1,base64VaultKey2"`
	MicrosoftAuth string   `json:"microsoft_auth" example:"eyJhbGciOiJIUzI1NiIs..."`
	ProjectID     string   `json:"project_id,omitempty"`
	TeamID        string   `json:"team_id,omitempty"`
	ChannelID     string   `json:"channel_id,omitempty"`
}

// MicrosoftBackupAuthSwaggerRequest is the UI body for POST /microsoft-backup/microsoft-auth.
type MicrosoftBackupAuthSwaggerRequest struct {
	MicrosoftKey string `json:"microsoft_key" example:"<Microsoft Graph access_token from restore OAuth>"`
}

func (m *MicrosoftBackup) parseManualRestoreRequest(r *http.Request) (console.MicrosoftBackupManualRestoreRequest, error) {
	var body MicrosoftBackupManualRestoreSwaggerRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return console.MicrosoftBackupManualRestoreRequest{}, console.ErrValidation.New("invalid request body")
	}
	auth := strings.TrimSpace(body.MicrosoftAuth)
	if auth == "" {
		auth = strings.TrimSpace(r.Header.Get("Authorization"))
		auth = strings.TrimPrefix(auth, "Bearer ")
	}
	return console.MicrosoftBackupManualRestoreRequest{
		Keys:          body.Keys,
		MicrosoftAuth: auth,
		ProjectID:     body.ProjectID,
		TeamID:        body.TeamID,
		ChannelID:     body.ChannelID,
	}, nil
}

// MicrosoftAuth exchanges microsoft_key (Graph access token from restore OAuth) for Backup-Tools microsoft-auth JWT.
// Covers all Microsoft restore (mail, calendar, contacts, OneDrive, SharePoint, Teams) — not Outlook-only.
//
// @Summary      Exchange Microsoft Graph token for Backup-Tools restore JWT
// @Description  Proxies Backup-Tools POST /microsoft-auth. Call before office365/satellite-to-* restore. UI must OAuth with MicrosoftRestoreScopes (write), then pass the Graph access_token as microsoft_key. Same pattern as POST /google-backup/google-auth.
// @Tags         microsoft-backup-auth
// @Accept       json
// @Produce      json
// @Param        body  body      MicrosoftBackupAuthSwaggerRequest  true  "Graph access token from restore consent"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/microsoft-auth [post]
func (m *MicrosoftBackup) MicrosoftAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body MicrosoftBackupAuthSwaggerRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := m.service.BackupToolsMicrosoftAuth(ctx, body.MicrosoftKey)
	m.service.RecordUserAuditHTTP(ctx, "MB_RESTORE_AUTH", "Microsoft restore auth", "Microsoft restore authentication completed", status, respBody, err)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

func (m *MicrosoftBackup) manualRestoreBatch(w http.ResponseWriter, r *http.Request, backupToolsPath string) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	req, err := m.parseManualRestoreRequest(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.MicrosoftBackupManualRestore(ctx, tokenKey, backupToolsPath, req)
	m.service.RecordUserAuditHTTP(ctx, "MB_MANUAL_RESTORE", "Manual restore", "Microsoft manual restore completed", status, respBody, err)
	m.service.RecordInviteeAuditForOwner(ctx, req.ProjectID, "MB_MANUAL_RESTORE", "Manual restore", "Microsoft manual restore completed", status, respBody, err)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

// ManualRestoreOutlook proxies Backup-Tools POST /office365/satellite-to-outlook.
func (m *MicrosoftBackup) ManualRestoreOutlook(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-outlook")
}

// ManualRestoreOutlookCalendar proxies Backup-Tools POST /office365/satellite-to-outlook-calendar.
func (m *MicrosoftBackup) ManualRestoreOutlookCalendar(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-outlook-calendar")
}

// ManualRestoreOutlookContacts proxies Backup-Tools POST /office365/satellite-to-outlook-contacts.
func (m *MicrosoftBackup) ManualRestoreOutlookContacts(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-outlook-contacts")
}

// ManualRestoreOneDrive proxies Backup-Tools POST /office365/satellite-to-onedrive.
func (m *MicrosoftBackup) ManualRestoreOneDrive(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-onedrive")
}

// ManualRestoreSharePoint proxies Backup-Tools POST /office365/satellite-to-sharepoint.
func (m *MicrosoftBackup) ManualRestoreSharePoint(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-sharepoint")
}

// ManualRestoreTeams proxies Backup-Tools POST /office365/satellite-to-teams.
func (m *MicrosoftBackup) ManualRestoreTeams(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-teams")
}

// ManualRestoreTeamsChats proxies Backup-Tools POST /office365/satellite-to-teams-chats.
func (m *MicrosoftBackup) ManualRestoreTeamsChats(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-teams-chats")
}
