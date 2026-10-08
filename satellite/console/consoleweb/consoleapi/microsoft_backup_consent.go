// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

// MicrosoftAdminConsentURLResponse is returned by GET /microsoft-backup/admin-consent-url.
type MicrosoftAdminConsentURLResponse struct {
	Success     bool   `json:"success"`
	ConsentURL  string `json:"consent_url"`
	RedirectURI string `json:"redirect_uri"`
}

// AdminConsentURL returns the tenant admin-consent URL for organization onboarding.
//
// @Summary      Microsoft tenant admin-consent URL
// @Description  **Route:** `GET /api/v0/microsoft-backup/admin-consent-url`. For the selected tenant (`tenant_id`, required) of the selected work or school account (`credential_id`), only when Backup-Tools detection reports the account as an Entra administrator there (`is_admin`, any Entra Administrator role). `admin_workspace` is not required. Returns `https://login.microsoftonline.com/{tenant}/adminconsent?client_id&redirect_uri&state` with an HMAC-signed callback `state` (user, account, tenant, client, expiry, nonce) that only protects the redirect. `redirect_uri` is the frontend origin plus `microsoft-admin-consent-redirect-path` and must be registered on the Azure app (Web platform).
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        tenant_id      query  string  true   "Entra tenant ID to consent for"
// @Success      200  {object}  MicrosoftAdminConsentURLResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/admin-consent-url [get]
func (m *MicrosoftBackup) AdminConsentURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	redirectURI := socialmedia.ResolveMicrosoftAdminConsentRedirectURI(r)
	consentURL, err := m.service.GetMicrosoftAdminConsentURL(ctx, tokenKey, redirectURI, microsoftTenantSelectionFromRequest(r))
	if err != nil {
		m.serveMicrosoftWorkspaceError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(MicrosoftAdminConsentURLResponse{
		Success:     true,
		ConsentURL:  consentURL,
		RedirectURI: redirectURI,
	}); err != nil {
		m.log.Error("failed to encode microsoft admin consent url response", zap.Error(err))
	}
}

// AdminConsentCallback completes tenant admin consent.
//
// @Summary      Complete Microsoft tenant admin consent
// @Description  **Route:** `GET /api/v0/microsoft-backup/admin-consent/callback`. The frontend callback page forwards Microsoft's query (`state`, `tenant`, `admin_consent`, `error`, `error_description`). Satellite verifies the signed `state` (the account and tenant come from it), then calls Backup-Tools `POST /microsoft/tenants/{tid}/consent` with `consented_by`. Backup-Tools decides consent (`granted`, `insufficient`, `revoked`, `auth_error`) from the app-only token; its contract is returned unchanged. Satellite stores only `account_type`, and only when Backup-Tools returns `admin_workspace`. Backup-Tools 4xx responses are passed through.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        state              query  string  true   "Signed callback state from admin-consent-url"
// @Param        tenant             query  string  false  "Tenant ID returned by Microsoft"
// @Param        admin_consent      query  string  false  "True when Microsoft reports consent was granted"
// @Param        error              query  string  false  "Microsoft error code"
// @Param        error_description  query  string  false  "Microsoft error description"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/admin-consent/callback [get]
func (m *MicrosoftBackup) AdminConsentCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	query := r.URL.Query()
	contract, err := m.service.CompleteMicrosoftAdminConsent(ctx, tokenKey, console.MicrosoftAdminConsentCallback{
		State:            query.Get("state"),
		Tenant:           query.Get("tenant"),
		AdminConsent:     query.Get("admin_consent"),
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
	})
	m.service.RecordUserAudit(ctx, "MB_ADMIN_CONSENT", "Microsoft tenant admin consent", "Microsoft tenant admin consent callback", err)
	if err != nil {
		m.serveMicrosoftWorkspaceError(ctx, w, err)
		return
	}
	m.writeMicrosoftWorkspaceJSON(w, contract)
}

// serveMicrosoftWorkspaceError passes Backup-Tools 4xx responses through unchanged and maps
// other Backup-Tools failures to 502. Remaining errors use the standard console error mapping.
func (m *MicrosoftBackup) serveMicrosoftWorkspaceError(ctx context.Context, w http.ResponseWriter, err error) {
	var statusErr *console.BackupToolsStatusError
	if errors.As(err, &statusErr) {
		status := statusErr.Status
		if status < 400 || status >= 500 {
			status = http.StatusBadGateway
		}
		if json.Valid(statusErr.Body) {
			writeBackupToolsJSON(w, status, statusErr.Body)
			return
		}
		web.ServeCustomJSONError(ctx, m.log, w, status, err, string(statusErr.Body))
		return
	}
	if console.ErrNotFound.Has(err) {
		web.ServeCustomJSONError(ctx, m.log, w, http.StatusNotFound, err, err.Error())
		return
	}
	m.serveJSONError(ctx, w, err)
}

func (m *MicrosoftBackup) writeMicrosoftWorkspaceJSON(w http.ResponseWriter, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		m.log.Error("failed to encode microsoft workspace response", zap.Error(err))
	}
}
