// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
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

// ListPolicies proxies Backup-Tools GET /auto-sync/policy.
//
// @Summary      List backup policies
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

// CreatePolicy proxies Backup-Tools POST /auto-sync/policy.
//
// @Summary      Create backup policy
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body  CreateGoogleBackupAutoSyncPolicySwaggerRequest  true  "Omit job_ids for empty policy; set job_ids for split or move-to-new"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy [post]
func (g *GoogleBackupAutoSyncPolicy) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.CreateGoogleBackupAutoSyncPolicyRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.CreateGoogleBackupAutoSyncPolicy(ctx, tokenKey, req)
	g.service.RecordUserAuditHTTP(ctx, "GB_POLICY_CREATE", "Auto-sync policy", "Auto-sync policy created", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetPolicyOptions proxies Backup-Tools GET /auto-sync/policy/options.
//
// @Summary      List policy options for move picker
// @Tags         google-backup-policy
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/options [get]
func (g *GoogleBackupAutoSyncPolicy) GetPolicyOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupAutoSyncPolicyOptions(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetAvailableAssignments proxies Backup-Tools GET /auto-sync/policy/available-assignments.
//
// @Summary      List available assignments for Add Email modal
// @Tags         google-backup-policy
// @Produce      json
// @Param        policy_id  query  string  true   "Target policy ID."
// @Param        search     query  string  false  "Step 1 — filter mailbox name or email."
// @Param        email      query  string  false  "Step 2 — return services for this mailbox."
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/available-assignments [get]
func (g *GoogleBackupAutoSyncPolicy) GetAvailableAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	q := r.URL.Query()
	respBody, status, err := g.service.GetGoogleBackupAutoSyncPolicyAvailableAssignments(ctx, tokenKey, q.Get("policy_id"), q.Get("search"), q.Get("email"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// MoveAssignments proxies Backup-Tools POST /auto-sync/policy/move.
//
// @Summary      Move job assignments to a policy
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body  MoveGoogleBackupAutoSyncPolicyAssignmentsSwaggerRequest  true  "target_policy_id and job_ids"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      404   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/move [post]
func (g *GoogleBackupAutoSyncPolicy) MoveAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.MoveGoogleBackupAutoSyncPolicyAssignmentsRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.MoveGoogleBackupAutoSyncPolicyAssignments(ctx, tokenKey, req)
	g.service.RecordUserAuditHTTP(ctx, "GB_POLICY_MOVE", "Auto-sync policy", "Auto-sync policy assignments moved", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// PreviewMergePolicies proxies Backup-Tools GET /auto-sync/policy/merge/preview.
//
// @Summary      Preview duplicate policy merge
// @Tags         google-backup-policy
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
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

// MergePolicies proxies Backup-Tools POST /auto-sync/policy/merge.
//
// @Summary      Merge duplicate policies into a new policy
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body  MergeGoogleBackupAutoSyncPoliciesSwaggerRequest  true  "Complete policy_ids from one preview group plus new policy name"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      404   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
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
	if err := decodeStrictJSON(r, &req); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.MergeGoogleBackupAutoSyncPolicies(ctx, tokenKey, req)
	g.service.RecordUserAuditHTTP(ctx, "GB_POLICY_MERGE", "Auto-sync policy", "Auto-sync policies merged", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetPolicy proxies Backup-Tools GET /auto-sync/policy/{policy_id}.
//
// @Summary      Get backup policy details
// @Tags         google-backup-policy
// @Produce      json
// @Param        policy_id  path    string  true   "Policy ID"
// @Param        search     query   string  false  "Filter linked_jobs by email, name, method, or service label."
// @Success      200        {object}  BackupToolsJSONResponse
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

	respBody, status, err := g.service.GetGoogleBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"], r.URL.RawQuery)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdatePolicy proxies Backup-Tools PUT /auto-sync/policy/{policy_id}.
//
// @Summary      Update backup policy schedule
// @Tags         google-backup-policy
// @Accept       json
// @Produce      json
// @Param        policy_id  path  string                                         true  "Policy ID"
// @Param        body       body  UpdateGoogleBackupAutoSyncPolicySwaggerRequest  true  "interval, on, retention_type"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      404        {object}  SwaggerErrorResponse
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
	if err := decodeStrictJSON(r, &req); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.UpdateGoogleBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"], req)
	g.service.RecordUserAuditHTTP(ctx, "GB_POLICY_UPDATE", "Auto-sync policy", "Auto-sync policy updated", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// DeletePolicy proxies Backup-Tools DELETE /auto-sync/policy/{policy_id}.
//
// @Summary      Delete empty backup policy
// @Tags         google-backup-policy
// @Produce      json
// @Param        policy_id  path  string  true  "Policy ID (linked_job_count must be 0)"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      404        {object}  SwaggerErrorResponse
// @Failure      409        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/auto-sync/policy/{policy_id} [delete]
func (g *GoogleBackupAutoSyncPolicy) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.DeleteGoogleBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"])
	g.service.RecordUserAuditHTTP(ctx, "GB_POLICY_DELETE", "Auto-sync policy", "Auto-sync policy deleted", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
