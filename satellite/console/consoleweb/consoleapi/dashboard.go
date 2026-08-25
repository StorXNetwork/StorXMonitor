// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

var (
	// ErrDashboardAPI - console dashboard api error type.
	ErrDashboardAPI = errs.Class("console api dashboard")
)

// Dashboard is an api controller that exposes all dashboard related functionality.
type Dashboard struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewDashboard is a constructor for api dashboard controller.
func NewDashboard(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *Dashboard {
	return &Dashboard{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

// GetDashboardStats returns Protected Services overview cards (protectedUsers, storageQuota,
// bandwidthQuota, lastSnapshot, billing). Legacy autoSync/vault/access cards are commented out in the service.
//
// @Summary      Dashboard stats cards
// @Description  **Full route:** `GET /api/v0/dashboard/stats`
//
// Returns 5 cards in this order: protectedUsers, storageQuota, bandwidthQuota, lastSnapshot, billing.
// @Tags         dashboard
// @Produce      json
// @Success      200  {array}   DashboardStatsCardSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /dashboard/stats [get]
func (d *Dashboard) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	user, err := console.GetUser(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			d.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		} else {
			d.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		}
		return
	}

	// Service handles all business logic
	// Pass token getter function so service can get token when needed for external API calls
	cards, err := d.service.GetDashboardStats(ctx, user.ID, func() (string, error) {
		tokenInfo, err := d.cookieAuth.GetToken(r)
		if err != nil {
			return "", ErrDashboardAPI.Wrap(err)
		}
		return tokenInfo.Token.String(), nil
	})
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			d.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		} else {
			d.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		}
		return
	}

	// Controller only handles HTTP response encoding
	if err := json.NewEncoder(w).Encode(cards); err != nil {
		d.log.Error("failed to encode dashboard cards json response", zap.Error(ErrDashboardAPI.Wrap(err)))
	}
}

// GetDashboardAlerts returns auth / paused / new-mailbox alert cards for Protected Services.
// Common for Google Backup and Microsoft Backup (not under /google-backup or /microsoft-backup).
//
// @Summary      Dashboard alert cards (common)
// @Description  **Full route:** `GET /api/v0/dashboard/alerts`. Proxies Backup-Tools `GET /autosync/dashboard-alerts`. Same payload for Google and Microsoft.
// @Tags         dashboard
// @Produce      json
// @Success      200  {object}  DashboardAlertsSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /dashboard/alerts [get]
func (d *Dashboard) GetDashboardAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenInfo, err := d.cookieAuth.GetToken(r)
	if err != nil {
		d.serveJSONError(ctx, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	respBody, status, err := d.service.GetDashboardAlerts(ctx, tokenInfo.Token.String())
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			d.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		d.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListBackupRestoreLogs returns backup/restore activity logs (Google + Microsoft / Outlook).
//
// @Summary      Backup and restore logs
// @Description  **Full route:** `GET /api/v0/dashboard/backup-restore/logs`. Proxies Backup-Tools `GET /backup-restore/logs`. Shared for Google and Microsoft.
// @Tags         dashboard
// @Produce      json
// @Param        types           query  string  false  "Comma-separated: backup, restore, or both (default backup,restore)."
// @Param        search          query  string  false  "Partial match on subject or message."
// @Param        method          query  string  false  "Service filter: gmail, google_drive, google_photos, google_contacts, google_calendar, outlook, outlook_calendar, outlook_contacts, outlook_onedrive, outlook_sharepoint, outlook_teams, outlook_groups."
// @Param        message_status  query  string  false  "info, warning, or error."
// @Param        limit           query  int     false  "Page size (default 10, max 100)."
// @Param        offset          query  int     false  "Rows to skip (default 0)."
// @Success      200  {object}  BackupToolsJSONResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /dashboard/backup-restore/logs [get]
func (d *Dashboard) ListBackupRestoreLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenInfo, err := d.cookieAuth.GetToken(r)
	if err != nil {
		d.serveJSONError(ctx, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	respBody, status, err := d.service.ListBackupRestoreLogs(ctx, tokenInfo.Token.String(), r.URL.RawQuery)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			d.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		d.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// serveJSONError writes JSON error to response output stream.
func (d *Dashboard) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, d.log, w, status, err)
}
