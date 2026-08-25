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

// BackupAutoSyncPolicy proxies shared Backup-Tools policy APIs (/auto-sync/policy/*).
type BackupAutoSyncPolicy struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewBackupAutoSyncPolicy constructs the common backup policy HTTP controller.
func NewBackupAutoSyncPolicy(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *BackupAutoSyncPolicy {
	return &BackupAutoSyncPolicy{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (b *BackupAutoSyncPolicy) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := b.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (b *BackupAutoSyncPolicy) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: b.log, service: b.service, cookieAuth: b.cookieAuth}).serveJSONError(ctx, w, err)
}

// ListPolicies proxies Backup-Tools GET /auto-sync/policy.
//
// @Summary      List backup policies
// @Tags         backup-policy
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy [get]
func (b *BackupAutoSyncPolicy) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.ListBackupAutoSyncPolicies(ctx, tokenKey)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// CreatePolicy proxies Backup-Tools POST /auto-sync/policy.
//
// @Summary      Create backup policy
// @Tags         backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body  CreateBackupAutoSyncPolicySwaggerRequest  true  "Policy create request"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy [post]
func (b *BackupAutoSyncPolicy) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	var req console.CreateBackupAutoSyncPolicyRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.CreateBackupAutoSyncPolicy(ctx, tokenKey, req)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_POLICY_CREATE", "Auto-sync policy", "Auto-sync policy created", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetPolicyOptions proxies Backup-Tools GET /auto-sync/policy/options.
//
// @Summary      List policy options for move picker
// @Tags         backup-policy
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/options [get]
func (b *BackupAutoSyncPolicy) GetPolicyOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.GetBackupAutoSyncPolicyOptions(ctx, tokenKey)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetAvailableAssignments proxies Backup-Tools GET /auto-sync/policy/available-assignments.
//
// @Summary      List available assignments for Add Email modal
// @Tags         backup-policy
// @Produce      json
// @Param        policy_id  query  string  true   "Target policy ID"
// @Param        search     query  string  false  "Filter mailbox name or email"
// @Param        email      query  string  false  "Return services for this mailbox"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/available-assignments [get]
func (b *BackupAutoSyncPolicy) GetAvailableAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	q := r.URL.Query()
	respBody, status, err := b.service.GetBackupAutoSyncPolicyAvailableAssignments(ctx, tokenKey, q.Get("policy_id"), q.Get("search"), q.Get("email"))
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// MoveAssignments proxies Backup-Tools POST /auto-sync/policy/move.
//
// @Summary      Move job assignments to a policy
// @Tags         backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body  MoveBackupAutoSyncPolicyAssignmentsSwaggerRequest  true  "target_policy_id and job_ids"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      404   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/move [post]
func (b *BackupAutoSyncPolicy) MoveAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	var req console.MoveBackupAutoSyncPolicyAssignmentsRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.MoveBackupAutoSyncPolicyAssignments(ctx, tokenKey, req)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_POLICY_MOVE", "Auto-sync policy", "Auto-sync policy assignments moved", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// PreviewMergePolicies proxies Backup-Tools GET /auto-sync/policy/merge/preview.
//
// @Summary      Preview duplicate policy merge
// @Tags         backup-policy
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/merge/preview [get]
func (b *BackupAutoSyncPolicy) PreviewMergePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.PreviewMergeBackupAutoSyncPolicies(ctx, tokenKey)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// MergePolicies proxies Backup-Tools POST /auto-sync/policy/merge.
//
// @Summary      Merge duplicate policies into a new policy
// @Tags         backup-policy
// @Accept       json
// @Produce      json
// @Param        body  body  MergeBackupAutoSyncPoliciesSwaggerRequest  true  "policy_ids and new policy name"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      404   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/merge [post]
func (b *BackupAutoSyncPolicy) MergePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	var req console.MergeBackupAutoSyncPoliciesRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.MergeBackupAutoSyncPolicies(ctx, tokenKey, req)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_POLICY_MERGE", "Auto-sync policy", "Auto-sync policies merged", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetPolicy proxies Backup-Tools GET /auto-sync/policy/{policy_id}.
//
// @Summary      Get backup policy details
// @Tags         backup-policy
// @Produce      json
// @Param        policy_id  path    string  true   "Policy ID"
// @Param        search     query   string  false  "Filter linked_jobs"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      404        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/{policy_id} [get]
func (b *BackupAutoSyncPolicy) GetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.GetBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"], r.URL.RawQuery)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdatePolicy proxies Backup-Tools PUT /auto-sync/policy/{policy_id}.
//
// @Summary      Update backup policy schedule
// @Tags         backup-policy
// @Accept       json
// @Produce      json
// @Param        policy_id  path  string                                    true  "Policy ID"
// @Param        body       body  UpdateBackupAutoSyncPolicySwaggerRequest  true  "interval, on, retention_type"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      404        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/{policy_id} [put]
func (b *BackupAutoSyncPolicy) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	var req console.UpdateBackupAutoSyncPolicyRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.UpdateBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"], req)
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_POLICY_UPDATE", "Auto-sync policy", "Auto-sync policy updated", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// DeletePolicy proxies Backup-Tools DELETE /auto-sync/policy/{policy_id}.
//
// @Summary      Delete empty backup policy
// @Tags         backup-policy
// @Produce      json
// @Param        policy_id  path  string  true  "Policy ID (linked_job_count must be 0)"
// @Success      200        {object}  BackupToolsJSONResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      404        {object}  SwaggerErrorResponse
// @Failure      409        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /backup/auto-sync/policy/{policy_id} [delete]
func (b *BackupAutoSyncPolicy) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := b.sessionTokenKey(r)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := b.service.DeleteBackupAutoSyncPolicy(ctx, tokenKey, mux.Vars(r)["policy_id"])
	b.service.RecordUserAuditHTTP(ctx, "BACKUP_POLICY_DELETE", "Auto-sync policy", "Auto-sync policy deleted", status, respBody, err)
	if err != nil {
		b.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
