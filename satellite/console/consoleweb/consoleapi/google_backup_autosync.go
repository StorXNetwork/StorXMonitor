// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"io"
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

func readBackupToolsRequestBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, console.ErrValidation.New("request body is required")
	}
	if !json.Valid(body) {
		return nil, console.ErrValidation.New("invalid request body")
	}
	return body, nil
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
// @Description  Satellite enriches the body with credentials and project_id, then POSTs to Backup-Tools. Example body: `{"services":["gmail","drive"],"interval":"1h","emails":["billing@salestalker.com","support@salestalker.com"]}`
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
		Emails:   body.Emails,
	}, tokenKey, syncType)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListAutoSyncJobs lists Backup-Tools auto-sync jobs for the session user.
//
// @Summary      List Google Backup auto-sync jobs
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
// @Description  Requires project_id and google_email in the body; other fields are optional.
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
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncJob updates a single auto-sync job (passthrough to Backup-Tools). Not exposed in Swagger.
func (g *GoogleBackup) UpdateAutoSyncJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	payload, err := readBackupToolsRequestBody(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.UpdateGoogleBackupAutoSyncJob(ctx, tokenKey, mux.Vars(r)["job_id"], payload)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// BulkUpdateGmailAutoSyncJobs bulk-updates corporate Gmail auto-sync jobs (passthrough to Backup-Tools). Not exposed in Swagger.
func (g *GoogleBackup) BulkUpdateGmailAutoSyncJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	payload, err := readBackupToolsRequestBody(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.BulkUpdateGoogleBackupGmailJobs(ctx, tokenKey, payload)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
