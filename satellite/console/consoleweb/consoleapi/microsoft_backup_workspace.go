// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"net/http"
)

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
// @Description  **Route:** `GET /api/v0/microsoft-backup/status`. Proxies Backup-Tools `GET /microsoft/workspace` for the stored Microsoft credential and returns its contract unchanged plus `has_refresh_token`: `account_type`, `workspace_kind`, `tenant_id`, `tenant_name`, `is_admin`, `admin_roles`, `consent` (`not_requested|granted|insufficient|revoked|auth_error`), `capabilities`, `capability_errors`, `directory`. Personal accounts are answered locally. The wizard derives its step from this response.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      404  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/status [get]
func (m *MicrosoftBackup) Status(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, m.service.GetMicrosoftBackupStatus)
}

// RefreshCapabilities re-runs the Backup-Tools capability engine for the caller's tenant.
//
// @Summary      Refresh Microsoft tenant capabilities
// @Description  **Route:** `POST /api/v0/microsoft-backup/capabilities/refresh`. Proxies Backup-Tools `POST /microsoft/tenants/{tid}/capabilities/refresh`; the tenant comes from the stored credential.
// @Tags         microsoft-backup-organization
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/capabilities/refresh [post]
func (m *MicrosoftBackup) RefreshCapabilities(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, m.service.RefreshMicrosoftBackupCapabilities)
}

// DirectoryUsers lists tenant users live from Microsoft Graph via Backup-Tools.
//
// @Summary      List Microsoft tenant directory users
// @Description  **Route:** `GET /api/v0/microsoft-backup/directory/users`. Proxies Backup-Tools `GET /microsoft/tenants/{tid}/directory/users` (listed live from Microsoft Graph; nothing is stored).
// @Tags         microsoft-backup-organization
// @Produce      json
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
		return m.service.ListMicrosoftBackupDirectoryUsers(ctx, tokenKey, r.URL.Query())
	})
}

// GetOrgStructure returns the StorX organization structure for the tenant.
//
// @Summary      Get Microsoft organization structure
// @Description  **Route:** `GET /api/v0/microsoft-backup/organization/structure`. Proxies Backup-Tools `GET /microsoft/tenants/{tid}/org-structure` (org-unit tree with user counts; `org_unit_path` defaults to `/` plus department).
// @Tags         microsoft-backup-organization
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/organization/structure [get]
func (m *MicrosoftBackup) GetOrgStructure(w http.ResponseWriter, r *http.Request) {
	m.proxyWorkspace(w, r, m.service.GetMicrosoftBackupOrgStructure)
}
