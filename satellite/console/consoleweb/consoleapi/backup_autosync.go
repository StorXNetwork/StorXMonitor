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

func writeBackupToolsJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// BackupAutoSync proxies shared Backup-Tools auto-sync job APIs (/auto-sync/*) for Google and Microsoft.
type BackupAutoSync struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewBackupAutoSync constructs the common backup auto-sync HTTP controller.
func NewBackupAutoSync(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *BackupAutoSync {
	return &BackupAutoSync{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (b *BackupAutoSync) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := b.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (b *BackupAutoSync) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: b.log, service: b.service, cookieAuth: b.cookieAuth}).serveJSONError(ctx, w, err)
}

// ListAutoSyncJobServices returns per-service job counts (Backup-Tools GET /auto-sync/job/services).
//
// @Summary      List backup auto-sync service stats
// @Description  **Route:** `GET /api/v0/backup/auto-sync/jobs/services`. Google + Microsoft services update page.
// @Tags         backup
// @Produce      json
// @Success      200  {object}  BackupAutoSyncJobServicesSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/jobs/services [get]
func (b *BackupAutoSync) ListAutoSyncJobServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.ListBackupAutoSyncJobServices(ctx, tokenKey)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// AutoSyncLive lists jobs with running or failed backup tasks (Backup-Tools GET /auto-sync/live).
//
// @Summary      Live auto-sync backup progress
// @Description  **Route:** `GET /api/v0/backup/auto-sync/live`. Poll every 3–5s for in-progress backup UI.
// @Tags         backup
// @Produce      json
// @Success      200  {object}  BackupAutoSyncLiveSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/live [get]
func (b *BackupAutoSync) AutoSyncLive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.ListBackupAutoSyncLive(ctx, tokenKey)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListAutoSyncJobs lists Backup-Tools auto-sync jobs for the session user.
//
// @Summary      List backup auto-sync jobs
// @Description  **Route:** `GET /api/v0/backup/auto-sync/jobs`. Proxies Backup-Tools `GET /auto-sync/job/`. Filter `method`: gmail, google_drive, outlook, outlook_onedrive, etc.
// @Tags         backup
// @Produce      json
// @Param        filter  query     string  false  "URL-encoded AutosyncJobListFilter JSON"
// @Success      200     {object}  AutosyncJobListResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/jobs [get]
func (b *BackupAutoSync) ListAutoSyncJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.ListBackupAutoSyncJobs(ctx, tokenKey, r.URL.Query().Get("filter"))
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetAutoSyncJob returns one Backup-Tools auto-sync job by id.
//
// @Summary      Get backup auto-sync job
// @Description  **Route:** `GET /api/v0/backup/auto-sync/jobs/{job_id}`. Proxies Backup-Tools `GET /auto-sync/job/{job_id}`.
// @Tags         backup
// @Produce      json
// @Param        job_id  path      string  true  "Job ID"
// @Success      200     {object}  AutosyncJobDetailResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      404     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/jobs/{job_id} [get]
func (b *BackupAutoSync) GetAutoSyncJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	jobID := mux.Vars(r)["job_id"]
	respBody, status, err := b.service.GetBackupAutoSyncJob(ctx, tokenKey, jobID)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncJobsByProject updates all jobs for a project via Backup-Tools PUT /auto-sync/job/project.
//
// @Summary      Update backup jobs by project (Grant Access / reconnect)
// @Description  **Route:** `PUT /api/v0/backup/auto-sync/jobs/project`. Same Grant Access pattern for Google and Microsoft: exchange OAuth `code`, upsert Satellite `backup_credentials`, forward `refresh_token` to Backup-Tools. Google: `google_email` + `code`. Microsoft: `microsoft_email` + `code` (redirect_uri uses Microsoft backup origin, same as connect/auth).
// @Tags         backup
// @Accept       json
// @Produce      json
// @Param        body  body      UpdateBackupAutoSyncJobsByProjectSwaggerRequest  true  "Project-scoped update"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/jobs/project [put]
func (b *BackupAutoSync) UpdateAutoSyncJobsByProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	var req console.UpdateBackupAutoSyncJobsByProjectRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		b.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		b.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	// Same as provider connect/auth: Google → ResolveRequestOrigin, Microsoft → ResolveMicrosoftBackupOrigin.
	redirectURI := backupProjectUpdateRedirectURI(r, req)
	respBody, status, err := b.service.UpdateBackupAutoSyncJobsByProject(ctx, tokenKey, req, redirectURI)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_JOB_UPDATE", "Auto-sync project", "Auto-sync project updated", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// backupProjectUpdateRedirectURI picks the OAuth redirect origin like Google vs Microsoft connect.
func backupProjectUpdateRedirectURI(r *http.Request, req console.UpdateBackupAutoSyncJobsByProjectRequest) string {
	if strings.TrimSpace(req.MicrosoftEmail) != "" {
		return socialmedia.ResolveMicrosoftBackupOrigin(r)
	}
	return socialmedia.ResolveRequestOrigin(r)
}

// BackupNowAutoSyncJob queues an on-demand backup (Backup-Tools POST /auto-sync/task/{job_id}/backup-now).
//
// @Summary      Trigger on-demand auto-sync backup
// @Description  **Route:** `POST /api/v0/backup/auto-sync/task/{job_id}/backup-now`.
// @Tags         backup
// @Produce      json
// @Param        job_id  path      string  true  "Auto-sync job ID"
// @Success      200     {object}  BackupAutoSyncBackupNowSwaggerResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      404     {object}  SwaggerErrorResponse
// @Failure      500     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/task/{job_id}/backup-now [post]
func (b *BackupAutoSync) BackupNowAutoSyncJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	jobID := mux.Vars(r)["job_id"]
	respBody, status, err := b.service.TriggerBackupAutoSyncBackupNow(ctx, tokenKey, jobID)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_NOW", "Auto-sync job", "On-demand backup queued", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncJob toggles or updates a single job (Backup-Tools PUT /auto-sync/job/{job_id}).
//
// @Summary      Update backup auto-sync job
// @Description  **Route:** `PUT /api/v0/backup/auto-sync/jobs/{job_id}`. Typically `{ "active": true|false }`; Microsoft may also send storx_token / refresh_token.
// @Tags         backup
// @Accept       json
// @Produce      json
// @Param        job_id  path      string                                    true  "Job ID"
// @Param        body    body      UpdateBackupAutoSyncJobSwaggerRequest     true  "Job update"
// @Success      200     {object}  AutosyncJobDetailResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      404     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/jobs/{job_id} [put]
func (b *BackupAutoSync) UpdateAutoSyncJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	var req console.UpdateBackupAutoSyncJobRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		b.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}
	if dec.More() {
		b.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	respBody, status, err := b.service.UpdateBackupAutoSyncJob(ctx, tokenKey, mux.Vars(r)["job_id"], req)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_JOB_UPDATE", "Auto-sync job", "Auto-sync job updated", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
