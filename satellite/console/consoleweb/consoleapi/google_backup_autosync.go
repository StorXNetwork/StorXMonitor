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

// GetAutoSyncJobPolicy returns the policy for one job (Backup-Tools GET /auto-sync/job/{job_id}/policy).
//
// @Summary      Get Google Backup policy for job
// @Tags         google-backup
// @Produce      json
// @Param        job_id  path      string  true  "Job ID"
// @Success      200     {object}  BackupToolsJSONResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/jobs/{job_id}/policy [get]
func (g *GoogleBackup) GetAutoSyncJobPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupAutoSyncJobPolicy(ctx, tokenKey, mux.Vars(r)["job_id"])
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListAutoSyncPolicies lists policies for a connected account (Backup-Tools GET /auto-sync/policy).
//
// @Summary      List Google Backup auto-sync policies
// @Tags         google-backup
// @Produce      json
// @Param        credential_id  query     string  false  "Backup-Tools credential ID"
// @Param        project_id     query     string  false  "Storj project ID (with google_email)"
// @Param        google_email   query     string  false  "Google account email (with project_id)"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      400            {object}  SwaggerErrorResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy [get]
func (g *GoogleBackup) ListAutoSyncPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	q := console.ListGoogleBackupAutoSyncPoliciesQuery{
		CredentialID: r.URL.Query().Get("credential_id"),
		ProjectID:    r.URL.Query().Get("project_id"),
		GoogleEmail:  r.URL.Query().Get("google_email"),
	}
	respBody, status, err := g.service.ListGoogleBackupAutoSyncPolicies(ctx, tokenKey, q)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetAutoSyncPolicy returns one policy by ID (Backup-Tools GET /auto-sync/policy/{policy_id}).
//
// @Summary      Get Google Backup auto-sync policy
// @Tags         google-backup
// @Produce      json
// @Param        policy_id  path      string  true  "Policy ID"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/{policy_id} [get]
func (g *GoogleBackup) GetAutoSyncPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"])
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncJobsByProject updates all jobs for a project via Backup-Tools PUT /auto-sync/job/project.
//
// @Summary      Update Google Backup jobs by project
// @Description  Account-level update (refresh_token, storx_token, active, interval, on). Send `code` to re-auth: Satellite exchanges OAuth code, updates google_backup_credentials, then forwards refresh_token to Backup-Tools (never forwards code).
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
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateAutoSyncPolicy updates schedule on a policy (Backup-Tools PUT /auto-sync/policy/{policy_id}).
//
// @Summary      Update Google Backup auto-sync policy schedule
// @Description  Updates interval and on for a single policy (both required; use on:"" for hourly). Use PUT .../jobs/project for refresh_token, storx_token, or bulk schedule/active.
// @Tags         google-backup
// @Accept       json
// @Produce      json
// @Param        policy_id  path      string                                         true  "Policy ID"
// @Param        body       body      UpdateGoogleBackupAutoSyncPolicySwaggerRequest  true  "Policy schedule update"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/{policy_id} [put]
func (g *GoogleBackup) UpdateAutoSyncPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.UpdateGoogleBackupAutoSyncPolicyRequest
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

	respBody, status, err := g.service.UpdateGoogleBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"], req)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
