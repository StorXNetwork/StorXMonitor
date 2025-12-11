// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consolewebauth"
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

// GetDashboardStats returns dashboard cards data (autoSync, vault, access, billing) for the authenticated user.
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

// serveJSONError writes JSON error to response output stream.
func (d *Dashboard) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, d.log, w, status, err)
}
