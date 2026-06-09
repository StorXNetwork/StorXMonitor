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
//
// No query parameters. Each policy includes `needs_google_reconnect` and `needs_storx_reconnect`.
// @Tags         google-backup-policy
// @Produce      json
// @Success      200  {object}  GoogleBackupPolicyListSwaggerResponse
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

	respBody, status, err := g.service.ListGoogleBackupAutoSyncPolicies(ctx, tokenKey, r.URL.RawQuery)
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
//
// Returns `policy` (with `needs_google_reconnect`, `needs_storx_reconnect`), `account` for Copy/Edit/Reconnect, and `linked_jobs`. Reconnect save uses PUT .../auto-sync/jobs/project with `account.oauth_holder_email`.
// @Tags         google-backup-policy
// @Produce      json
// @Param        policy_id  path      string  true  "Policy ID"
// @Success      200        {object}  GoogleBackupPolicyDetailSwaggerResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      404        {object}  SwaggerErrorResponse
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
// @Description  **Full route:** `PUT /api/v0/google-backup/auto-sync/policy/{policy_id}`. Copy: apply_all false + selected_job_ids. Edit: apply_all true. On 409 duplicate schedule use GET .../merge/preview then POST .../merge.
// @Description  **interval:** 3h, 12h, daily, weekly, monthly (aliases nightly/24h/7d normalize to daily).
// @Description  **on:** 3h/12h empty ""; daily time e.g. 12am; weekly weekday e.g. Monday; monthly day e.g. 1.
// @Description  **retention_type:** never, 30_days, 1_year, 7_years (optional).
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        policy_id  path      string                                         true  "Policy ID"
// @Param        body       body      UpdateGoogleBackupAutoSyncPolicySwaggerRequest  true  "Policy update"
// @Success      200        {object}  GoogleBackupPolicyUpdateSwaggerResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      409        {object}  SwaggerErrorResponse
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

// PreviewMergePolicies previews duplicate policy groups (Backup-Tools GET /auto-sync/policy/merge/preview).
//
// @Summary      Preview Google Backup policy merge
// @Description  **Full route:** `GET /api/v0/google-backup/auto-sync/policy/merge/preview`
//
// Returns duplicate schedule groups with `policy_ids` to POST to .../merge. Use before POST .../merge.
// @Tags         google-backup-policy
// @Produce      json
// @Success      200  {object}  GoogleBackupPolicyMergePreviewSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/merge/preview [get]
func (g *GoogleBackupAutoSyncPolicy) PreviewMergePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.PreviewMergeGoogleBackupAutoSyncPolicies(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// MergePolicies merges one duplicate policy group (Backup-Tools POST /auto-sync/policy/merge).
//
// @Summary      Merge duplicate Google Backup policies
// @Description  **Full route:** `POST /api/v0/google-backup/auto-sync/policy/merge`
//
// Body `{"policy_ids": [12, 18, 22]}` merges one preview group. Include all policy IDs from the group's `policy_ids` array (minimum 2).
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body      MergeGoogleBackupAutoSyncPoliciesSwaggerRequest  true  "Merge request"
// @Success      200   {object}  GoogleBackupPolicyMergeExecuteSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      404   {object}  SwaggerErrorResponse
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
