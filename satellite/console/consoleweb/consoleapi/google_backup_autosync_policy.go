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

// GoogleBackupAutoSyncPolicy proxies Backup-Tools shared backup policy APIs (/auto-sync/policy/*).
type GoogleBackupAutoSyncPolicy struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewGoogleBackupAutoSyncPolicy constructs a backup policy HTTP controller.
func NewGoogleBackupAutoSyncPolicy(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *GoogleBackupAutoSyncPolicy {
	return &GoogleBackupAutoSyncPolicy{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (g *GoogleBackupAutoSyncPolicy) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := g.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (g *GoogleBackupAutoSyncPolicy) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: g.log, service: g.service, cookieAuth: g.cookieAuth}).serveJSONError(ctx, w, err)
}

// ListPolicies lists all backup policies for the session user (Backup-Tools GET /auto-sync/policy).
//
// @Summary      List Google Backup auto-sync policies
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/policy`
// @Tags         google-backup-policy
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy [get]
func (g *GoogleBackupAutoSyncPolicy) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupAutoSyncPolicies(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetPolicy returns one policy and linked jobs (Backup-Tools GET /auto-sync/policy/{policy_id}).
//
// @Summary      Get Google Backup auto-sync policy
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/policy/{policy_id}`
// @Tags         google-backup-policy
// @Produce      json
// @Param        policy_id  path      string  true  "Policy ID"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/{policy_id} [get]
func (g *GoogleBackupAutoSyncPolicy) GetPolicy(w http.ResponseWriter, r *http.Request) {
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

// GetPolicyByJob resolves the policy for one job (Backup-Tools GET /auto-sync/policy/by-job/{job_id}).
//
// @Summary      Get Google Backup policy for job
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/policy/by-job/{job_id}`
// @Tags         google-backup-policy
// @Produce      json
// @Param        job_id  path      string  true  "Job ID"
// @Success      200     {object}  BackupToolsJSONResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/by-job/{job_id} [get]
func (g *GoogleBackupAutoSyncPolicy) GetPolicyByJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupAutoSyncPolicyByJob(ctx, tokenKey, mux.Vars(r)["job_id"])
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdatePolicy updates schedule and retention on a policy (Backup-Tools PUT /auto-sync/policy/{policy_id}).
//
// @Summary      Update Google Backup auto-sync policy
// @Description  **Full route:** `PUT /api/v0/google-backup/auto-sync/policy/{policy_id}`
//
// Updates schedule and retention for all linked jobs (`apply_all: true`) or selected jobs (`apply_all: false` + `selected_job_ids`). Job active toggles use PUT .../auto-sync/jobs/{job_id}.
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        policy_id  path      string                                         true  "Policy ID"
// @Param        body       body      UpdateGoogleBackupAutoSyncPolicySwaggerRequest  true  "Policy update"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/{policy_id} [put]
func (g *GoogleBackupAutoSyncPolicy) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
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

// MergePolicies consolidates duplicate policy rows (Backup-Tools POST /auto-sync/policy/merge).
//
// @Summary      Merge duplicate Google Backup policies
// @Description  **Full route:** `POST /api/v0/google-backup/auto-sync/policy/merge`
//
// Body `{"dry_run": false}` merges all duplicate groups for the logged-in user. Use `dry_run: true` to preview.
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body      MergeGoogleBackupAutoSyncPoliciesSwaggerRequest  true  "Merge request"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/merge [post]
func (g *GoogleBackupAutoSyncPolicy) MergePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.MergeGoogleBackupAutoSyncPoliciesRequest
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

	respBody, status, err := g.service.MergeGoogleBackupAutoSyncPolicies(ctx, tokenKey, req)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
