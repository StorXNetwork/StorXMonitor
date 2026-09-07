// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/auditlog"
)

var ErrAuditLogsAPI = errs.Class("console api audit logs")

// AuditLogs exposes user audit log read and export APIs.
type AuditLogs struct {
	log     *zap.Logger
	service *console.Service
}

// NewAuditLogs creates an audit logs controller.
func NewAuditLogs(log *zap.Logger, service *console.Service) *AuditLogs {
	return &AuditLogs{log: log, service: service}
}

// ListAuditLogs returns audit events for the authenticated user.
//
// @Summary      List audit logs
// @Description  **Full route:** `GET /api/v0/audit-logs`
//
// Returns paginated activity for the authenticated user. Use `cursor` from the previous response for the next page.
// Filter by `action` (e.g. `AUTH_LOGIN`), `status` (`success` or `failed`), free-text `search`, and RFC3339 `from` / `to`.
// @Tags         audit-logs
// @Produce      json
// @Param        action  query  string  false  "Filter by action code (e.g. AUTH_LOGIN)"
// @Param        status  query  string  false  "Filter by status"  Enums(success, failed)
// @Param        search  query  string  false  "Search action, resource, message, or record id"
// @Param        from    query  string  false  "Range start (RFC3339)"  example(2026-06-01T00:00:00Z)
// @Param        to      query  string  false  "Range end (RFC3339)"  example(2026-06-02T23:59:59Z)
// @Param        limit   query  int     false  "Page size (default 50)"  default(50)
// @Param        cursor  query  string  false  "Pagination cursor from previous response NextCursor"
// @Success      200     {object}  AuditLogListSwaggerResponse
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      500     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /audit-logs [get]
func (a *AuditLogs) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, svc, err := a.sessionUser(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	params, err := auditlog.ListParamsFromQuery(r.URL.Query(), user.ID.String())
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	result, err := svc.List(ctx, params)
	if err != nil {
		a.serveJSONError(ctx, w, ErrAuditLogsAPI.Wrap(err))
		return
	}
	auditlog.ApplyActorDisplay(result.Items, auditlog.ActorDisplay{
		Name:  user.FullName,
		Email: user.Email,
	})
	result.TotalCount, err = svc.Count(ctx, params)
	if err != nil {
		a.serveJSONError(ctx, w, ErrAuditLogsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// ListAuditLogActions returns distinct actions from the user's audit history.
//
// @Summary      List audit log action codes
// @Description  **Full route:** `GET /api/v0/audit-logs/actions`
//
// Returns distinct `action` values for the authenticated user (for filter dropdowns).
// @Tags         audit-logs
// @Produce      json
// @Success      200  {object}  AuditLogActionsSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /audit-logs/actions [get]
func (a *AuditLogs) ListAuditLogActions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, svc, err := a.sessionUser(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	actions, err := svc.ListUserActions(ctx, user.ID.String())
	if err != nil {
		a.serveJSONError(ctx, w, ErrAuditLogsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"actions": actions})
}

// ExportAuditLogs streams a CSV export for the authenticated user.
//
// @Summary      Export audit logs as CSV
// @Description  **Full route:** `GET /api/v0/audit-logs/export`
//
// Streams `audit-logs.csv` with the same query filters as list. If `from` / `to` are omitted, defaults to the last 7 days.
// Maximum export range is configured server-side (`audit-max-export-days`, default 90).
// @Tags         audit-logs
// @Produce      text/csv
// @Param        action  query  string  false  "Filter by action code"
// @Param        status  query  string  false  "Filter by status"  Enums(success, failed)
// @Param        search  query  string  false  "Search action, resource, message, or record id"
// @Param        from    query  string  false  "Range start (RFC3339)"  example(2026-06-01T00:00:00Z)
// @Param        to      query  string  false  "Range end (RFC3339)"  example(2026-06-02T23:59:59Z)
// @Param        limit   query  int     false  "Max rows per batch (internal pagination)"
// @Param        cursor  query  string  false  "Pagination cursor"
// @Success      200  {string}  string  "CSV file (Content-Disposition: audit-logs.csv)"
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /audit-logs/export [get]
func (a *AuditLogs) ExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, svc, err := a.sessionUser(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	params, err := auditlog.ListParamsFromQuery(r.URL.Query(), user.ID.String())
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if params.From == nil || params.To == nil {
		now := time.Now().UTC()
		from := now.Add(-7 * 24 * time.Hour)
		params.From = &from
		params.To = &now
	}
	maxDays := svc.Config().MaxExportDays
	if params.To.Sub(*params.From) > time.Duration(maxDays)*24*time.Hour {
		a.serveJSONError(ctx, w, ErrAuditLogsAPI.New("export date range exceeds maximum of %d days", maxDays))
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-logs.csv"`)
	_ = svc.ExportCSV(ctx, params, auditlog.ActorDisplay{
		Name:  user.FullName,
		Email: user.Email,
	}, w)
}

func (a *AuditLogs) sessionUser(ctx context.Context) (*console.User, *auditlog.Service, error) {
	user, err := console.GetUser(ctx)
	if err != nil {
		return nil, nil, err
	}
	svc := a.service.AuditLog()
	if svc == nil {
		return nil, nil, ErrAuditLogsAPI.New("audit log service unavailable")
	}
	return user, svc, nil
}

func (a *AuditLogs) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case console.ErrUnauthorized.Has(err):
		status = http.StatusUnauthorized
	case console.ErrValidation.Has(err), ErrAuditLogsAPI.Has(err), auditlog.Error.Has(err):
		status = http.StatusBadRequest
	}
	web.ServeJSONError(ctx, a.log, w, status, err)
}
