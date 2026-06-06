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

// ListAutoSyncJobs lists Backup-Tools auto-sync jobs for the session user.
//
// @Summary      List Google Backup auto-sync jobs
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/jobs`
// @Tags         google-backup
// @Produce      json
// @Param        filter  query     string  false  "Optional Backup-Tools filter"
// @Success      200     {object}  BackupToolsJSONResponse
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
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/jobs/{job_id}`
// @Tags         google-backup
// @Produce      json
// @Param        job_id  path      string  true  "Job ID"
// @Success      200     {object}  BackupToolsJSONResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/jobs/{job_id} [get]
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

// UpdateAutoSyncJob toggles a single job active flag (Backup-Tools PUT /auto-sync/job/{job_id}). Not exposed in Swagger.
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
