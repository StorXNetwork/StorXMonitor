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

// GoogleBackupUsersGroups proxies Backup-Tools Users & Groups routes (/users-groups/*).
type GoogleBackupUsersGroups struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewGoogleBackupUsersGroups constructs a Users & Groups HTTP controller.
func NewGoogleBackupUsersGroups(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *GoogleBackupUsersGroups {
	return &GoogleBackupUsersGroups{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (g *GoogleBackupUsersGroups) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := g.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (g *GoogleBackupUsersGroups) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: g.log, service: g.service, cookieAuth: g.cookieAuth}).serveJSONError(ctx, w, err)
}

// GetDashboardAlerts proxies Backup-Tools GET /autosync/dashboard-alerts.
//
// @Summary      Dashboard alert cards
// @Description  **Full route:** `GET /api/v0/google-backup/users-groups/dashboard-alerts`. Proxies Backup-Tools `GET /autosync/dashboard-alerts` with session `token_key`. UI mapping: Auth Errors → `re_auth_required`; Paused Backups → `paused_backups`; New Mailboxes (24h) → `new_connected_accounts_24h`. Review links: re-auth → `GET .../users-groups?credential_status=re_auth_required`; paused → `GET .../users-groups?active=false`; new → sort by `connected_at` on users-groups list.
// @Tags         google-backup-users-groups
// @Produce      json
// @Success      200  {object}  GoogleBackupDashboardAlertsSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/dashboard-alerts [get]
func (g *GoogleBackupUsersGroups) GetDashboardAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupDashboardAlerts(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetDomains proxies Backup-Tools GET /users-groups/domains.
//
// @Summary      List Users & Groups domains
// @Tags         google-backup-users-groups
// @Produce      json
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/domains [get]
func (g *GoogleBackupUsersGroups) GetDomains(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupUsersGroupsDomains(ctx, tokenKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// List proxies Backup-Tools GET /users-groups.
//
// @Summary      List Users & Groups mailboxes
// @Tags         google-backup-users-groups
// @Produce      json
// @Param        domain            query  string  false  "Filter by domain."
// @Param        search            query  string  false  "Partial match on mailbox email."
// @Param        method            query  string  false  "gmail, google_drive, google_photos, google_contacts, google_calendar, all, all_services."
// @Param        account_type      query  string  false  "corporate, individual, all, all_types."
// @Param        credential_status query  string  false  "healthy, re_auth_required, all, all_statuses."
// @Param        limit             query  int     false  "Page size (default 10)."
// @Param        offset            query  int     false  "Rows to skip (default 0)."
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups [get]
func (g *GoogleBackupUsersGroups) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.ListGoogleBackupUsersGroups(ctx, tokenKey, r.URL.RawQuery)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxOverview proxies Backup-Tools GET /users-groups/mailbox/overview.
//
// @Summary      Mailbox overview tab
// @Tags         google-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email."
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/mailbox/overview [get]
func (g *GoogleBackupUsersGroups) GetMailboxOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupUsersGroupsMailboxOverview(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxServices proxies Backup-Tools GET /users-groups/mailbox/services.
//
// @Summary      Mailbox services tab
// @Tags         google-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email."
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/mailbox/services [get]
func (g *GoogleBackupUsersGroups) GetMailboxServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupUsersGroupsMailboxServices(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxSchedule proxies Backup-Tools GET /users-groups/mailbox/schedule.
//
// @Summary      Mailbox schedule tab
// @Tags         google-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email."
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/mailbox/schedule [get]
func (g *GoogleBackupUsersGroups) GetMailboxSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupUsersGroupsMailboxSchedule(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GetMailboxCredentials proxies Backup-Tools GET /users-groups/mailbox/credentials.
//
// @Summary      Mailbox credentials tab
// @Tags         google-backup-users-groups
// @Produce      json
// @Param        email  query  string  true  "Mailbox email."
// @Success      200    {object}  BackupToolsJSONResponse
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/mailbox/credentials [get]
func (g *GoogleBackupUsersGroups) GetMailboxCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.GetGoogleBackupUsersGroupsMailboxCredentials(ctx, tokenKey, r.URL.Query().Get("email"))
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GoogleBackupUsersGroupsJobsActiveSwaggerRequest is the UI body for bulk pause/resume.
type GoogleBackupUsersGroupsJobsActiveSwaggerRequest struct {
	JobIDs []int `json:"job_ids" binding:"required" example:"12,13,14"`
	Active bool  `json:"active" binding:"required" example:"false"`
}

// UpdateJobsActive proxies Backup-Tools PUT /users-groups/jobs/active.
//
// @Summary      Bulk pause or resume jobs
// @Tags         google-backup-users-groups
// @Accept       json
// @Produce      json
// @Param        body  body  GoogleBackupUsersGroupsJobsActiveSwaggerRequest  true  "job_ids from list entities[].services[].job_id"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/users-groups/jobs/active [put]
func (g *GoogleBackupUsersGroups) UpdateJobsActive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var req console.GoogleBackupUsersGroupsJobsActiveRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.UpdateGoogleBackupUsersGroupsJobsActive(ctx, tokenKey, req)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}
