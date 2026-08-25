// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// MicrosoftBackupUsersGroups proxies Backup-Tools Microsoft Users & Groups routes.
type MicrosoftBackupUsersGroups struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewMicrosoftBackupUsersGroups constructs a Microsoft Users & Groups HTTP controller.
func NewMicrosoftBackupUsersGroups(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *MicrosoftBackupUsersGroups {
	return &MicrosoftBackupUsersGroups{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (m *MicrosoftBackupUsersGroups) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := m.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (m *MicrosoftBackupUsersGroups) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: m.log, service: m.service, cookieAuth: m.cookieAuth}).serveJSONError(ctx, w, err)
}

// GetDomains proxies Backup-Tools GET /microsoft/users-groups/domains.
//
// @Summary      List Microsoft Users & Groups domains
// @Tags         microsoft-backup-users-groups
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups/domains [get]
func (m *MicrosoftBackupUsersGroups) GetDomains(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.GetMicrosoftBackupUsersGroupsDomains(ctx, tokenKey)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// List proxies Backup-Tools GET /microsoft/users-groups.
//
// @Summary      List Microsoft Users & Groups mailboxes
// @Description  Filter method: outlook, outlook_calendar, outlook_contacts, outlook_onedrive, outlook_sharepoint, outlook_teams, outlook_groups, or all. Response includes `organization_resources` with `sharepoint_sites`, `teams`, and `groups` (admin_workspace).
// @Tags         microsoft-backup-users-groups
// @Produce      json
// @Param        domain            query  string  false  "Filter by domain"
// @Param        search            query  string  false  "Partial email match"
// @Param        method            query  string  false  "outlook, outlook_calendar, outlook_contacts, outlook_onedrive, outlook_sharepoint, outlook_teams, outlook_groups, all"
// @Param        account_type      query  string  false  "corporate, individual, all"
// @Param        credential_status query  string  false  "Same as Google credential_status"
// @Param        active            query  bool    false  "Filter by active"
// @Param        limit             query  int     false  "Page size"
// @Param        offset            query  int     false  "Offset"
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups [get]
func (m *MicrosoftBackupUsersGroups) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.ListMicrosoftBackupUsersGroups(ctx, tokenKey, r.URL.RawQuery)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxOverview proxies Backup-Tools GET /microsoft/users-groups/mailbox/overview.
//
// @Summary      Microsoft mailbox overview tab
// @Tags         microsoft-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email"
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups/mailbox/overview [get]
func (m *MicrosoftBackupUsersGroups) GetMailboxOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.GetMicrosoftBackupUsersGroupsMailboxOverview(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxServices proxies Backup-Tools GET /microsoft/users-groups/mailbox/services.
//
// @Summary      Microsoft mailbox services tab
// @Tags         microsoft-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email"
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups/mailbox/services [get]
func (m *MicrosoftBackupUsersGroups) GetMailboxServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.GetMicrosoftBackupUsersGroupsMailboxServices(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxSchedule proxies Backup-Tools GET /microsoft/users-groups/mailbox/schedule.
//
// @Summary      Microsoft mailbox schedule tab
// @Tags         microsoft-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email"
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups/mailbox/schedule [get]
func (m *MicrosoftBackupUsersGroups) GetMailboxSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.GetMicrosoftBackupUsersGroupsMailboxSchedule(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxCredentials proxies Backup-Tools GET /microsoft/users-groups/mailbox/credentials.
//
// @Summary      Microsoft mailbox credentials tab
// @Tags         microsoft-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email"
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups/mailbox/credentials [get]
func (m *MicrosoftBackupUsersGroups) GetMailboxCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.GetMicrosoftBackupUsersGroupsMailboxCredentials(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// UpdateJobsActive proxies Backup-Tools PUT /microsoft/users-groups/jobs/active.
//
// @Summary      Bulk pause or resume Microsoft jobs
// @Tags         microsoft-backup-users-groups
// @Accept       json
// @Produce      json
// @Param        body  body  MicrosoftBackupUsersGroupsJobsActiveSwaggerRequest  true  "job_ids and active"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /microsoft-backup/users-groups/jobs/active [put]
func (m *MicrosoftBackupUsersGroups) UpdateJobsActive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	var req console.MicrosoftBackupUsersGroupsJobsActiveRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := m.service.UpdateMicrosoftBackupUsersGroupsJobsActive(ctx, tokenKey, req)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
