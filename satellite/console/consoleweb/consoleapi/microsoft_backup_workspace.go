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
)

// MicrosoftBackupAccountsResponse is returned by GET /microsoft-backup/accounts.
type MicrosoftBackupAccountsResponse struct {
	Accounts []console.MicrosoftBackupAccount `json:"accounts"`
}

// MicrosoftBackupTenantConnectRequest is the body of POST /microsoft-backup/tenants/{tid}/connect.
type MicrosoftBackupTenantConnectRequest struct {
	// BackupMode is personal or organization.
	BackupMode   string `json:"backup_mode" example:"organization"`
	CredentialID string `json:"credential_id,omitempty" example:"6f1c2a1e-4c1b-4d2a-9c3e-2f6a7b8c9d0e"`
}

func microsoftTenantSelectionFromRequest(r *http.Request) console.MicrosoftTenantSelection {
	return console.MicrosoftTenantSelectionFromQuery(r.URL.Query())
}

// microsoftTenantSelectionFromPath uses the {tid} path variable as the selected tenant.
func microsoftTenantSelectionFromPath(r *http.Request) console.MicrosoftTenantSelection {
	sel := microsoftTenantSelectionFromRequest(r)
	sel.TenantID = strings.TrimSpace(mux.Vars(r)["tid"])
	return sel
}

func (m *MicrosoftBackup) proxyWorkspace(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, tokenKey string) (map[string]interface{}, error)) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	result, err := fn(ctx, tokenKey)
	if err != nil {
		m.serveMicrosoftWorkspaceError(ctx, w, err)
		return
	}
	m.writeMicrosoftWorkspaceJSON(w, result)
}

// Status returns the Microsoft workspace contract.
//
// @Summary      Microsoft workspace status
// @Description  **Route:** `GET /api/v0/microsoft-backup/status`. Proxies Backup-Tools `GET /microsoft/workspace` for the selected Microsoft account (`credential_id`, optional with one account) and tenant (`tenant_id`, required for work or school accounts; the home tenant is never assumed) and returns its contract unchanged plus `has_refresh_token` and `credential_id`: `account_type`, `workspace_kind`, `tenant_id`, `tenant_name`, `is_admin`, `admin_roles`, `consent` (`not_requested|granted|insufficient|revoked|auth_error`), `capabilities`, `capability_errors`, `directory`. Personal accounts are answered locally. Errors: 400 `microsoft_credential_required`, 400 `tenant_id_required`, 404 `microsoft_credential_not_found`.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        tenant_id      query  string  false  "Selected Entra tenant ID (required for work or school accounts)"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      404  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/status [get]
func (m *MicrosoftBackup) Status(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		return m.service.GetMicrosoftBackupStatus(ctx, tokenKey, microsoftTenantSelectionFromRequest(r))
	})
}

// RefreshCapabilities re-runs the Backup-Tools capability engine for the selected tenant.
//
// @Summary      Refresh Microsoft tenant capabilities
// @Description  **Route:** `POST /api/v0/microsoft-backup/capabilities/refresh`. Proxies Backup-Tools `POST /microsoft/tenants/{tid}/capabilities/refresh` for the selected account and tenant.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        tenant_id      query  string  true   "Selected Entra tenant ID"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/capabilities/refresh [post]
func (m *MicrosoftBackup) RefreshCapabilities(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		return m.service.RefreshMicrosoftBackupCapabilities(ctx, tokenKey, microsoftTenantSelectionFromRequest(r))
	})
}

// DirectoryUsers lists tenant users live from Microsoft Graph via Backup-Tools.
//
// @Summary      List Microsoft tenant directory users
// @Description  **Route:** `GET /api/v0/microsoft-backup/directory/users`. Proxies Backup-Tools `GET /microsoft/tenants/{tid}/directory/users` for the selected account and tenant (listed live from Microsoft Graph; nothing is stored).
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        tenant_id      query  string  true   "Selected Entra tenant ID"
// @Param        search      query  string  false  "Search by name or email"
// @Param        department  query  string  false  "Filter by department"
// @Param        page        query  int     false  "Page number"
// @Param        page_size   query  int     false  "Page size"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/directory/users [get]
func (m *MicrosoftBackup) DirectoryUsers(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		return m.service.ListMicrosoftBackupDirectoryUsers(ctx, tokenKey, microsoftTenantSelectionFromRequest(r), r.URL.Query())
	})
}

// GetOrgStructure returns the StorX organization structure for the selected tenant.
//
// @Summary      Get Microsoft organization structure
// @Description  **Route:** `GET /api/v0/microsoft-backup/organization/structure`. Proxies Backup-Tools `GET /microsoft/tenants/{tid}/org-structure` for the selected account and tenant (org-unit tree with user counts; `org_unit_path` defaults to `/` plus department).
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        tenant_id      query  string  true   "Selected Entra tenant ID"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/organization/structure [get]
func (m *MicrosoftBackup) GetOrgStructure(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		return m.service.GetMicrosoftBackupOrgStructure(ctx, tokenKey, microsoftTenantSelectionFromRequest(r))
	})
}

// ListAccounts lists the Microsoft accounts the user connected.
//
// @Summary      List connected Microsoft accounts
// @Description  **Route:** `GET /api/v0/microsoft-backup/accounts`. Answered by Satellite. Each Microsoft sign-in is one account identified by its home object ID (`external_account_id`) and home tenant; it can reach several tenants (see `GET /microsoft-backup/tenants`). Use `id` as `credential_id` on every other Microsoft route.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Success      200  {object}  MicrosoftBackupAccountsResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/accounts [get]
func (m *MicrosoftBackup) ListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if _, err = m.sessionTokenKey(r); err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	accounts, err := m.service.ListMicrosoftBackupAccounts(ctx)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(MicrosoftBackupAccountsResponse{Accounts: accounts}); err != nil {
		m.log.Error("failed to encode microsoft accounts response", zap.Error(err))
	}
}

// ListTenants lists the tenants a Microsoft account can reach, with their access state.
//
// @Summary      List tenants of a Microsoft account
// @Description  **Route:** `GET /api/v0/microsoft-backup/tenants`. Proxies Backup-Tools `GET /microsoft/accounts/tenants` for the selected account: tenant discovery plus the tenant access state of each tenant (role, consent, token, capabilities, connection). Account-level: no tenant is selected. Backup-Tools responses, including 4xx errors, are passed through.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      404  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/tenants [get]
func (m *MicrosoftBackup) ListTenants(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		return m.service.ListMicrosoftBackupTenants(ctx, tokenKey, microsoftTenantSelectionFromRequest(r).CredentialID)
	})
}

// ConnectTenant connects a Microsoft account to one of its tenants.
//
// @Summary      Connect a Microsoft tenant
// @Description  **Route:** `POST /api/v0/microsoft-backup/tenants/{tid}/connect`. Proxies Backup-Tools `POST /microsoft/accounts/tenants/{tid}/connect` with body `{backup_mode}` (`personal` or `organization`). The account comes from `credential_id` (query or body).
// @Tags         microsoft-backup-organization
// @Accept       json
// @Produce      json
// @Param        tid            path   string  true   "Entra tenant ID"
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Param        body           body   MicrosoftBackupTenantConnectRequest  true  "Backup mode"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      404  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/tenants/{tid}/connect [post]
func (m *MicrosoftBackup) ConnectTenant(w http.ResponseWriter, r *http.Request) {
	if _, err := m.sessionTokenKey(r); err != nil {
		m.serveJSONError(r.Context(), w, err)
		return
	}
	var body MicrosoftBackupTenantConnectRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		m.serveJSONError(r.Context(), w, err)
		return
	}
	sel := microsoftTenantSelectionFromPath(r)
	if sel.CredentialID == "" {
		sel.CredentialID = strings.TrimSpace(body.CredentialID)
	}
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		result, err := m.service.ConnectMicrosoftBackupTenant(ctx, tokenKey, sel, body.BackupMode)
		m.service.RecordUserAudit(ctx, "MB_TENANT_CONNECT", "Microsoft tenant", "Microsoft tenant connected", err)
		return result, err
	})
}

// DisconnectTenant disconnects a Microsoft account from one of its tenants.
//
// @Summary      Disconnect a Microsoft tenant
// @Description  **Route:** `POST /api/v0/microsoft-backup/tenants/{tid}/disconnect`. Proxies Backup-Tools `POST /microsoft/accounts/tenants/{tid}/disconnect`. Backups are kept; backup, browse and restore for the tenant are blocked until it is connected again.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        tid            path   string  true   "Entra tenant ID"
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      404  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/tenants/{tid}/disconnect [post]
func (m *MicrosoftBackup) DisconnectTenant(w http.ResponseWriter, r *http.Request) {
	sel := microsoftTenantSelectionFromPath(r)
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		result, err := m.service.DisconnectMicrosoftBackupTenant(ctx, tokenKey, sel)
		m.service.RecordUserAudit(ctx, "MB_TENANT_DISCONNECT", "Microsoft tenant", "Microsoft tenant disconnected", err)
		return result, err
	})
}

// RefreshTenantRoles re-reads the account's directory roles in a tenant.
//
// @Summary      Refresh Microsoft tenant roles
// @Description  **Route:** `POST /api/v0/microsoft-backup/tenants/{tid}/roles/refresh`. Proxies Backup-Tools `POST /microsoft/accounts/tenants/{tid}/roles/refresh` and returns the updated tenant access state.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Param        tid            path   string  true   "Entra tenant ID"
// @Param        credential_id  query  string  false  "Microsoft account (backup credential ID); required when several accounts are connected"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      404  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/tenants/{tid}/roles/refresh [post]
func (m *MicrosoftBackup) RefreshTenantRoles(w http.ResponseWriter, r *http.Request) {
	sel := microsoftTenantSelectionFromPath(r)
	m.proxyWorkspace(w, r, func(ctx context.Context, tokenKey string) (map[string]interface{}, error) {
		return m.service.RefreshMicrosoftBackupTenantRoles(ctx, tokenKey, sel)
	})
}
