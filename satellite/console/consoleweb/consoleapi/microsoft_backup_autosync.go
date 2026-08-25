// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
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

func microsoftBackupRefreshTokenFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("REFRESH_TOKEN")); v != "" {
		return v
	}
	return strings.TrimSpace(r.URL.Query().Get("refresh_token"))
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

// CreateAutoSyncJobs creates Microsoft Backup auto-sync jobs (Backup-Tools POST /microsoft/auto-sync/job).
//
// @Summary      Create Microsoft Backup auto-sync jobs
// @Description  **Route:** `POST /api/v0/microsoft-backup/auto-sync/job` (also `POST .../backup/onboarding/jobs`). Satellite enriches the UI payload (refresh_token, account_type, tenant_id from `backup_credentials`, project_id, storx_token) and POSTs Backup-Tools `/microsoft/auto-sync/job`. Do not send `account_type` — Satellite injects it. Services: outlook/mail, calendar, contacts, onedrive (`outlook_onedrive`), sharepoint (`outlook_sharepoint` + `sites[]`), teams (`outlook_teams` + `teams[]` or `backup_scope=all_tenant`), groups (`outlook_groups` + `groups[]` or `backup_scope=all_tenant`). SharePoint, teams, and groups require `admin_workspace`. On success (no failed jobs) sets onboarding to `MicrosoftBackupCompleted`.
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

func (m *MicrosoftBackup) proxyBrowseGet(w http.ResponseWriter, r *http.Request, fn func(context.Context, string, string, string) ([]byte, int, error)) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := fn(ctx, tokenKey, microsoftBackupRefreshTokenFromRequest(r), r.URL.RawQuery)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// QueryMessages proxies Backup-Tools GET /microsoft/query-messages.
//
// @Summary      Browse Microsoft Outlook messages
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        REFRESH_TOKEN  header  string  false  "Microsoft OAuth refresh token"
// @Param        refresh_token  query   string  false  "Microsoft OAuth refresh token (fallback)"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/query-messages [get]
func (m *MicrosoftBackup) QueryMessages(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupQueryMessages)
}

// ListContacts proxies Backup-Tools GET /microsoft/contacts/list.
//
// @Summary      Browse Microsoft contacts
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        REFRESH_TOKEN  header  string  false  "Microsoft OAuth refresh token"
// @Param        refresh_token  query   string  false  "Microsoft OAuth refresh token (fallback)"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/contacts/list [get]
func (m *MicrosoftBackup) ListContacts(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupContactsList)
}

// ListCalendars proxies Backup-Tools GET /microsoft/calendar/list.
//
// @Summary      Browse Microsoft calendars
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        REFRESH_TOKEN  header  string  false  "Microsoft OAuth refresh token"
// @Param        refresh_token  query   string  false  "Microsoft OAuth refresh token (fallback)"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/calendar/list [get]
func (m *MicrosoftBackup) ListCalendars(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupCalendarList)
}

// ListCalendarEvents proxies Backup-Tools GET /microsoft/calendar/events/{calendarId}.
//
// @Summary      Browse Microsoft calendar events
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        calendarId     path    string  true   "Calendar ID"
// @Param        REFRESH_TOKEN  header  string  false  "Microsoft OAuth refresh token"
// @Param        refresh_token  query   string  false  "Microsoft OAuth refresh token (fallback)"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/calendar/events/{calendarId} [get]
func (m *MicrosoftBackup) ListCalendarEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.GetMicrosoftBackupCalendarEvents(ctx, tokenKey, microsoftBackupRefreshTokenFromRequest(r), mux.Vars(r)["calendarId"], r.URL.RawQuery)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetCorporateDomainUsers loads domain-users via stored Microsoft credentials (Google domain-users parity).
//
// @Summary      Microsoft corporate domain users
// @Description  **Route:** `GET /api/v0/microsoft-backup/domain-users` (also `.../outlook/corporate/domain-users`). Uses refresh_token from `backup_credentials` when `REFRESH_TOKEN` header is omitted. Returns Backup-Tools JSON under `microsoft_backup` and updates `account_type` when present.
// @Tags         microsoft-backup
// @Produce      json
// @Param        microsoft_email  query   string  false  "Microsoft mailbox email (defaults to stored credential)"
// @Param        REFRESH_TOKEN    header  string  false  "Optional override; prefer DB injection"
// @Param        refresh_token    query   string  false  "Optional override"
// @Success      200  {object}  MicrosoftBackupDomainUsersSwaggerResponse
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
	refresh := microsoftBackupRefreshTokenFromRequest(r)
	microsoftBackup, err := m.service.GetMicrosoftBackupDomainUsers(ctx, tokenKey, refresh, microsoftEmail)
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

// ListSharePointSites proxies Backup-Tools GET /microsoft/sharepoint/sites (admin_workspace only).
//
// @Summary      List SharePoint sites (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/sharepoint/sites`. Admin org picker. Uses stored refresh_token when `REFRESH_TOKEN` header omitted. Query: `search`, `top`. Requires `Sites.Read.All` (reconnect after scope add).
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        search  query  string  false  "Filter sites by name"
// @Param        top     query  int     false  "Page size (default 50)"
// @Success      200     {object}  BackupToolsJSONResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      403     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/sharepoint/sites [get]
func (m *MicrosoftBackup) ListSharePointSites(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupSharePointSites)
}

// ListSharePointFlatFiles proxies Backup-Tools GET /microsoft/sharepoint/flat-files (admin only).
//
// @Summary      Browse SharePoint files (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/sharepoint/flat-files`. Requires `drive_id`. Query: `skip`, `top`.
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        drive_id  query  string  true  "SharePoint document library drive id"
// @Param        skip      query  int     false  "Rows to skip"
// @Param        top       query  int     false  "Page size (default 50)"
// @Success      200       {object}  BackupToolsJSONResponse
// @Failure      400       {object}  SwaggerErrorResponse
// @Failure      401       {object}  SwaggerErrorResponse
// @Failure      403       {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/sharepoint/flat-files [get]
func (m *MicrosoftBackup) ListSharePointFlatFiles(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupSharePointFlatFiles)
}

// ListTeams proxies Backup-Tools GET /microsoft/teams/list.
//
// @Summary      List Microsoft Teams (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/teams/list`. Admin team picker for `outlook_teams` jobs. Uses stored refresh_token when `REFRESH_TOKEN` header omitted. Query: `search`, `top`. Requires Teams Graph scopes (reconnect after scope add).
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        search  query  string  false  "Filter teams by name"
// @Param        top     query  int     false  "Page size (default 50)"
// @Success      200     {object}  BackupToolsJSONResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      403     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/teams/list [get]
func (m *MicrosoftBackup) ListTeams(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupTeamsList)
}

// ListTeamChannels proxies Backup-Tools GET /microsoft/teams/channels.
//
// @Summary      List Teams channels (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/teams/channels`. Requires `team_id` query param.
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        team_id  query  string  true  "Microsoft Teams team ID"
// @Success      200      {object}  BackupToolsJSONResponse
// @Failure      400      {object}  SwaggerErrorResponse
// @Failure      401      {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/teams/channels [get]
func (m *MicrosoftBackup) ListTeamChannels(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupTeamChannels)
}

// ListTeamsFlatMessages proxies Backup-Tools GET /microsoft/teams/flat-messages.
//
// @Summary      Browse Teams channel messages (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/teams/flat-messages`. Requires `team_id` and `channel_id`. Query: `skip`, `top`.
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        team_id     query  string  true  "Microsoft Teams team ID"
// @Param        channel_id  query  string  true  "Channel ID within the team"
// @Param        skip        query  int     false  "Rows to skip"
// @Param        top         query  int     false  "Page size (default 50)"
// @Success      200         {object}  BackupToolsJSONResponse
// @Failure      400         {object}  SwaggerErrorResponse
// @Failure      401         {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/teams/flat-messages [get]
func (m *MicrosoftBackup) ListTeamsFlatMessages(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupTeamsFlatMessages)
}

// ListGroups proxies Backup-Tools GET /microsoft/groups/list.
//
// @Summary      List Microsoft 365 Groups (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/groups/list`. Admin group picker for `outlook_groups` jobs. Uses stored refresh_token when `REFRESH_TOKEN` header omitted. Query: `search`, `top`.
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        search  query  string  false  "Filter groups by name"
// @Param        top     query  int     false  "Page size (default 50)"
// @Success      200     {object}  BackupToolsJSONResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      403     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/groups/list [get]
func (m *MicrosoftBackup) ListGroups(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupGroupsList)
}

// ListGroupsFlatConversations proxies Backup-Tools GET /microsoft/groups/flat-conversations.
//
// @Summary      Browse M365 Group conversations (admin)
// @Description  **Route:** `GET /api/v0/microsoft-backup/groups/flat-conversations`. Requires `group_id`. Query: `skip`, `top`.
// @Tags         microsoft-backup-browse
// @Produce      json
// @Param        group_id  query  string  true  "Microsoft 365 group ID"
// @Param        skip      query  int     false  "Rows to skip"
// @Param        top       query  int     false  "Page size (default 50)"
// @Success      200       {object}  BackupToolsJSONResponse
// @Failure      400       {object}  SwaggerErrorResponse
// @Failure      401       {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/groups/flat-conversations [get]
func (m *MicrosoftBackup) ListGroupsFlatConversations(w http.ResponseWriter, r *http.Request) {
	m.proxyBrowseGet(w, r, m.service.GetMicrosoftBackupGroupsFlatConversations)
}

// MicrosoftBackupManualRestoreSwaggerRequest is the UI body for manual restore (1–10 base64 vault keys).
// microsoft_auth = Backup-Tools JWT from POST /microsoft-backup/microsoft-auth (same role as Google Authorization after google-auth).
type MicrosoftBackupManualRestoreSwaggerRequest struct {
	Keys          []string `json:"keys" example:"base64VaultKey1,base64VaultKey2"`
	MicrosoftAuth string   `json:"microsoft_auth" example:"eyJhbGciOiJIUzI1NiIs..."`
	ProjectID     string   `json:"project_id,omitempty"`
	TeamID        string   `json:"team_id,omitempty"`
	ChannelID     string   `json:"channel_id,omitempty"`
	GroupID       string   `json:"group_id,omitempty"`
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
		GroupID:       body.GroupID,
	}, nil
}

// MicrosoftAuth exchanges microsoft_key (Graph access token from restore OAuth) for Backup-Tools microsoft-auth JWT.
// Covers all Microsoft restore (mail, calendar, contacts, OneDrive, SharePoint, Teams, Groups) — not Outlook-only.
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

// ManualRestoreGroups proxies Backup-Tools POST /office365/satellite-to-groups.
func (m *MicrosoftBackup) ManualRestoreGroups(w http.ResponseWriter, r *http.Request) {
	m.manualRestoreBatch(w, r, "/office365/satellite-to-groups")
}
