// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// GoogleBackup proxies Google-only Backup-Tools operations (connect, domain-users, job create).
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
// @Description  **Route:** `POST /api/v0/google-backup/auto-sync/jobs`. Satellite enriches the UI payload (tokens, project_id) and POSTs Backup-Tools `/auto-sync/job`. Create still uses `emails[]`. Optional `email_org_units` (email → Google Admin `org_unit_path`) is forwarded onto each mailbox job as `input_data.org_unit_path`. Optional `policy_scope=org_unit` plus `org_unit_schedules` apply schedule/services per OU (top-level `interval`/`on`/`services` optional when every OU has `services`). For `admin_workspace`, Satellite fills missing paths from domain-users OUs; Backup-Tools Directory lookup is the fallback. Individual Gmail has no path. Omits `interval`/`on` when `policy_id` is set. On success (no failed jobs) sets onboarding to `GoogleBackupCompleted`. Create response is Backup-Tools JSON as-is, including `org_units` and `policies` when present.
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
		Services         []string                                       `json:"services"`
		Interval         string                                         `json:"interval"`
		On               string                                         `json:"on"`
		Emails           []string                                       `json:"emails"`
		EmailOrgUnits    map[string]string                              `json:"email_org_units"`
		PolicyID         *int                                           `json:"policy_id"`
		PolicyName       string                                         `json:"policy_name"`
		PolicyScope      string                                         `json:"policy_scope"`
		OrgUnitSchedules map[string]console.GoogleBackupOrgUnitSchedule `json:"org_unit_schedules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		g.serveJSONError(ctx, w, console.ErrValidation.New("invalid request body"))
		return
	}

	syncType := r.URL.Query().Get("sync_type")
	respBody, status, err := g.service.CreateGoogleBackupAutoSyncJobs(ctx, console.CreateGoogleBackupAutoSyncJobsRequest{
		Services:         body.Services,
		Interval:         body.Interval,
		On:               body.On,
		Emails:           body.Emails,
		EmailOrgUnits:    body.EmailOrgUnits,
		PolicyID:         body.PolicyID,
		PolicyName:       body.PolicyName,
		PolicyScope:      body.PolicyScope,
		OrgUnitSchedules: body.OrgUnitSchedules,
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

// GetDomainUsers proxies Backup-Tools GET /google/gmail/corporate/domain-users (same payload as register-google).
//
// @Summary      Gmail corporate domain-users
// @Description  **Route:** `GET /api/v0/google-backup/domain-users`. Workspace mailboxes for corporate Gmail. Optional `google_email` query. Backup-Tools JSON is forwarded as-is under `google_backup`, including `organizational_units[]` and `org_units` (`["/","/SAles"]` for policy-by-group). Wizard Step 2 should render `google_backup.organizational_units[]` (org_unit_path, name, user_count, users[].email/role). Keep `grouped_emails` for old clients only; do not build the OU tree from `connected_emails`. OU paths come from Google Admin Directory (`orgUnitPath`); Satellite does not invent OUs.
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

	payload := map[string]interface{}{"success": true}
	if googleBackup != nil {
		payload["google_backup"] = googleBackup
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		g.log.Error("failed to encode domain-users response", zap.Error(err))
	}
}

// ConnectGoogle exchanges an OAuth code and upserts google_backup_credentials for the logged-in user.
//
// @Summary      Connect Google account for backup
// @Description  **Route:** `POST /api/v0/google-backup/connect`. Body: Google OAuth `code` only; `redirect_uri` is derived server-side from request Host. Returns scopes metadata. Tokens stored server-side only.
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

	redirectURI := socialmedia.ResolveRequestOrigin(r)
	connectResult, err := g.service.ConnectGoogleBackupCredential(ctx, body.Code, redirectURI)
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
		Created:      connectResult.Created,
		GoogleBackup: googleBackup,
	}); err != nil {
		g.log.Error("failed to encode google connect response", zap.Error(err))
	}
}
