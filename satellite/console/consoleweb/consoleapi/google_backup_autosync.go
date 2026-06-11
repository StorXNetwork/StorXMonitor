// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// GoogleBackup proxies Google Backup auto-sync job operations to Backup-Tools.
type GoogleBackup struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewGoogleBackup constructs a Google Backup HTTP controller.
func NewGoogleBackup(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *GoogleBackup {
	return &GoogleBackup{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func writeBackupToolsJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func (g *GoogleBackup) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := g.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (g *GoogleBackup) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: g.log, service: g.service, cookieAuth: g.cookieAuth}).serveJSONError(ctx, w, err)
}

// CreateAutoSyncJobs creates Backup-Tools auto-sync jobs from a minimal UI payload.
//
// @Summary      Create Google Backup auto-sync jobs
// @Description  **Route:** `POST /api/v0/google-backup/auto-sync/jobs`. On success (no failed jobs) sets `user_settings` step to `GoogleBackupCompleted`. Satellite adds `refresh_token` + `project_id`, POSTs Backup-Tools `/auto-sync/job`.
// @Tags         google-backup
// @Accept       json
// @Produce      json
// @Param        sync_type  query     string                                      false  "Backup-Tools sync type (default daily)"
// @Param        body       body      CreateGoogleBackupAutoSyncJobsSwaggerRequest  true   "Job create request"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/jobs [post]
func (g *GoogleBackup) CreateAutoSyncJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var body struct {
		Services []string `json:"services"`
		Interval string   `json:"interval"`
		On       string   `json:"on"`
		Emails   []string `json:"emails"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	syncType := r.URL.Query().Get("sync_type")
	respBody, status, err := g.service.CreateGoogleBackupAutoSyncJobs(ctx, console.CreateGoogleBackupAutoSyncJobsRequest{
		Services: body.Services,
		Interval: body.Interval,
		On:       body.On,
		Emails:   body.Emails,
	}, tokenKey, syncType)
	g.service.RecordUserAuditHTTP(ctx, "GB_JOB_CREATE", "Auto-sync job", "Auto-sync job created", status, respBody, err)
	if err == nil && status == http.StatusOK {
		var jobCreateResp struct {
			Failed []json.RawMessage `json:"failed"`
		}
		if json.Unmarshal(respBody, &jobCreateResp) == nil && len(jobCreateResp.Failed) == 0 {
			g.service.RecordUserAudit(ctx, "GB_ONBOARDING_COMPLETE", "Google Backup onboarding", "Google Backup onboarding completed", nil)
		}
	}
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetUsersGroupsDomains lists connected account domains for the Users & Groups filter (Backup-Tools GET /auto-sync/users-groups/domains).
//
// @Summary      List Google Backup Users & Groups domains
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/users-groups/domains`
//
// Corporate Users & Groups page — "All Accounts/Domains" dropdown. Call on page load; refresh after reconnect.
// @Tags         google-backup-users-groups
// @Produce      json
// @Success      200  {object}  GoogleBackupUsersGroupsDomainsSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/users-groups/domains [get]
func (g *GoogleBackup) GetUsersGroupsDomains(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupUsersGroupsDomains(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListUsersGroups lists email rows for the Users & Groups table (Backup-Tools GET /auto-sync/users-groups).
//
// @Summary      List Google Backup Users & Groups
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/users-groups`
//
// Corporate Users & Groups table. All filters are optional and combinable on this single route.
//
// **Query params:** `domain` — Accounts/domains dropdown (from GET .../users-groups/domains). `search` — email substring search. `method` — Services dropdown (All Services or one Google service). `limit` — emails per page (default 10). `offset` — emails to skip (default 0); pager formula `offset = (page - 1) * limit`.
//
// **method (Services filter):** omit, `all`, or `all_services` = All Services (every mailbox row, subject to domain/search). `gmail`, `google_drive`, `google_photos`, `google_contacts`, `google_calendar` = only emails with a job for that service. Invalid value → 400 `"invalid service filter"`. Filtered rows still return all `services[]` icons for each email.
//
// **Example:** `GET .../users-groups?domain=acme.com&method=google_contacts&limit=10&offset=0`
// @Tags         google-backup-users-groups
// @Produce      json
// @Param        domain  query     string  false  "Accounts/domains dropdown — filter by domain (e.g. acme.com). From GET .../users-groups/domains."
// @Param        search  query     string  false  "Email search — substring match on mailbox email."
// @Param        method  query     string  false  "Services dropdown. All Services: omit, all, or all_services. Specific: gmail, google_drive, google_photos, google_contacts, google_calendar. Invalid → 400."
// @Param        limit   query     int     false  "Pagination — emails per request (default 10)."
// @Param        offset  query     int     false  "Pagination — emails to skip (default 0). Page 2 with limit 10 → offset=10."
// @Success      200     {object}  GoogleBackupUsersGroupsSwaggerResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/users-groups [get]
func (g *GoogleBackup) ListUsersGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupUsersGroups(ctx, tokenKey, r.URL.RawQuery)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListBackupRestoreLogs proxies Backup-Tools GET /backup-restore/logs.
//
// @Summary      List backup and restore logs
// @Tags         google-backup-logs
// @Produce      json
// @Param        types           query  string  false  "Comma-separated: backup, restore, or both (default backup,restore)."
// @Param        search          query  string  false  "Partial match on subject or message."
// @Param        method          query  string  false  "Exact service filter: gmail, google_drive, google_photos, google_contacts, google_calendar."
// @Param        message_status  query  string  false  "info, warning, or error."
// @Param        limit           query  int     false  "Page size on merged list (default 10, max 100)."
// @Param        offset          query  int     false  "Rows to skip (default 0)."
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/backup-restore/logs [get]
func (g *GoogleBackup) ListBackupRestoreLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupRestoreLogs(ctx, tokenKey, r.URL.RawQuery)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListAutoSyncJobServices returns per-service job counts for the Services Update page (Backup-Tools GET /auto-sync/job/services).
//
// @Summary      List Google Backup auto-sync service stats
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/jobs/services`
//
// Services Update page only — not Users & Groups. All five Google services are always returned.
// @Tags         google-backup-users-groups
// @Produce      json
// @Success      200  {object}  GoogleBackupAutoSyncJobServicesSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/jobs/services [get]
func (g *GoogleBackup) ListAutoSyncJobServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupAutoSyncJobServices(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListAutoSyncJobs lists Backup-Tools auto-sync jobs for the session user.
//
// @Summary      List Google Backup auto-sync jobs
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/jobs`. Proxies Backup-Tools `GET /auto-sync/job` with session `token_key`. Single `filter` query param = URL-encoded `AutosyncJobListFilter` JSON. UI mapping: Service dropdown → `method` (gmail, google_drive, google_photos, google_calendar, google_contacts); Active/Inactive → `active` (true/false, user toggle); Success/Failed/Running → `status` (success, failed, in_progress, in_queue, created — last run, not same as active); Search bar → `name` (partial email). No `search` param on job list — use `filter.name`. Mailbox/domain search → `GET .../auto-sync/users-groups?search=...`. See `GET .../auto-sync/jobs/filter-schema` for examples.
// @Tags         google-backup
// @Produce      json
// @Param        filter  query     string  false  "URL-encoded AutosyncJobListFilter JSON. See definitions and GET .../auto-sync/jobs/filter-schema for four examples."  example(%7B%22method%22%3A%22gmail%22%2C%22active%22%3Atrue%2C%22status%22%3A%22failed%22%7D)
// @Success      200     {object}  AutosyncJobListResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/jobs [get]
func (g *GoogleBackup) ListAutoSyncJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupAutoSyncJobs(ctx, tokenKey, r.URL.Query().Get("filter"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetAutoSyncJob returns one Backup-Tools auto-sync job by id.
//
// @Summary      Get Google Backup auto-sync job
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/job/{job_id}`. Proxies Backup-Tools `GET /auto-sync/job/{job_id}` with session `token_key`. Job is in `success[0]`.
// @Tags         google-backup
// @Produce      json
// @Param        job_id  path      string  true  "Job ID"
// @Success      200     {object}  AutosyncJobDetailResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      404     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/job/{job_id} [get]
func (g *GoogleBackup) GetAutoSyncJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	jobID := mux.Vars(r)["job_id"]
	respBody, status, err := g.service.GetGoogleBackupAutoSyncJob(ctx, tokenKey, jobID)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncJobsByProject updates all jobs for a project via Backup-Tools PUT /auto-sync/job/project.
//
// @Summary      Update Google Backup jobs by project
// @Description  **Full route:** `PUT /api/v0/google-backup/auto-sync/jobs/project`
//
// Account-level update (refresh_token, storx_token, active). Schedule and retention use PUT .../auto-sync/policy/{policy_id}. Send `code` to re-auth: Satellite exchanges OAuth code, updates google_backup_credentials, then forwards refresh_token to Backup-Tools (never forwards code).
// @Tags         google-backup
// @Accept       json
// @Produce      json
// @Param        body  body      UpdateGoogleBackupAutoSyncJobsByProjectSwaggerRequest  true  "Project-scoped update"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/jobs/project [put]
func (g *GoogleBackup) UpdateAutoSyncJobsByProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.UpdateGoogleBackupAutoSyncJobsByProjectRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	respBody, status, err := g.service.UpdateGoogleBackupAutoSyncJobsByProject(ctx, tokenKey, req)
	g.service.RecordUserAuditHTTP(ctx, "GB_JOB_UPDATE", "Auto-sync project", "Auto-sync project updated", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncJob toggles a single job active flag (Backup-Tools PUT /auto-sync/job/{job_id}).
//
// @Summary      Toggle Google Backup auto-sync job active
// @Description  **Full route:** `PUT /api/v0/google-backup/auto-sync/job/{job_id}`. Proxies Backup-Tools `PUT /auto-sync/job/{job_id}` with body `{ "active": true|false }` only.
// @Tags         google-backup
// @Accept       json
// @Produce      json
// @Param        job_id  path      string                                       true  "Job ID"
// @Param        body    body      UpdateGoogleBackupAutoSyncJobSwaggerRequest  true  "Active toggle"
// @Success      200     {object}  AutosyncJobDetailResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      404     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/job/{job_id} [put]
func (g *GoogleBackup) UpdateAutoSyncJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.UpdateGoogleBackupAutoSyncJobRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	respBody, status, err := g.service.UpdateGoogleBackupAutoSyncJob(ctx, tokenKey, mux.Vars(r)["job_id"], req)
	g.service.RecordUserAuditHTTP(ctx, "GB_JOB_UPDATE", "Auto-sync job", "Auto-sync job updated", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetDomainUsers proxies Backup-Tools GET /google/gmail/corporate/domain-users (same payload as register-google).
//
// @Summary      Gmail corporate domain-users
// @Description  **Route:** `GET /api/v0/google-backup/domain-users`. Workspace mailboxes for corporate Gmail. Optional `google_email` query.
// @Tags         google-backup
// @Produce      json
// @Param        google_email  query     string  false  "Google account email (default: latest credential for user)"
// @Success      200           {object}  GoogleBackupDomainUsersSwaggerResponse
// @Failure      401           {object}  SwaggerErrorResponse
// @Failure      404           {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/domain-users [get]
func (g *GoogleBackup) GetDomainUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	googleBackup, err := g.service.GetGoogleBackupDomainUsers(ctx, tokenKey, r.URL.Query().Get("google_email"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	payload := GoogleBackupDomainUsersSwaggerResponse{Success: true}
	if googleBackup != nil {
		payload.GoogleBackup = googleBackup
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		g.log.Error("failed to encode domain-users response", zap.Error(err))
	}
}

// ConnectGoogle exchanges an OAuth code and upserts google_backup_credentials for the logged-in user.
//
// @Summary      Connect Google account for backup
// @Description  **Route:** `POST /api/v0/google-backup/connect`. Body: Google OAuth `code` (login redirect_uri). Returns scopes metadata. Tokens stored server-side only.
// @Tags         google-backup
// @Accept       json
// @Produce      json
// @Param        body  body      GoogleBackupConnectSwaggerRequest  true  "OAuth authorization code"
// @Success      200   {object}  GoogleBackupConnectSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/connect [post]
func (g *GoogleBackup) ConnectGoogle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if _, err := g.sessionTokenKey(r); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var body GoogleBackupConnectSwaggerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	connectResult, err := g.service.ConnectGoogleBackupCredential(ctx, body.Code)
	g.service.RecordUserAudit(ctx, "GB_CONNECT", "Google account", "Google account connected", err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var googleBackup map[string]interface{}
	if connectResult.GrantedScopes != nil || connectResult.UngrantedScopes != nil {
		googleBackup = console.GoogleBackupScopesPayload(connectResult.GrantedScopes, connectResult.UngrantedScopes)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(GoogleBackupConnectSwaggerResponse{
		Success:      true,
		GoogleEmail:  connectResult.GoogleEmail,
		Created:        connectResult.Created,
		GoogleBackup:   googleBackup,
	}); err != nil {
		g.log.Error("failed to encode google connect response", zap.Error(err))
	}
}
