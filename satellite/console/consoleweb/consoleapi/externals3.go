// Copyright (C) 2026 StorX Network, Inc.
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
)

// ErrExternalS3API - console external S3 api error type.
var ErrExternalS3API = errs.Class("console external s3")

// ExternalS3 is an api controller for encrypted external S3 backends.
type ExternalS3 struct {
	log     *zap.Logger
	service *console.Service
}

// NewExternalS3 is a constructor for ExternalS3 controller.
func NewExternalS3(log *zap.Logger, service *console.Service) *ExternalS3 {
	return &ExternalS3{log: log, service: service}
}

// Get returns external S3 status (no secrets).
func (c *ExternalS3) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	resp, err := c.service.GetExternalS3(ctx)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Put saves raw S3 credentials (encrypted on satellite) and registers with auth.
func (c *ExternalS3) Put(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var payload console.UpsertExternalS3Request
	if err = json.NewDecoder(r.Body).Decode(&payload); err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}
	resp, err := c.service.UpsertExternalS3(ctx, payload)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Delete removes the external S3 backend.
func (c *ExternalS3) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if err = c.service.DeleteExternalS3(ctx); err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EnsureGateway re-registers with auth if needed and returns gateway credentials for vault.
func (c *ExternalS3) EnsureGateway(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	resp, err := c.service.EnsureExternalS3GatewayForCurrentUser(ctx)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *ExternalS3) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if status == 0 {
		status = http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err):
			status = http.StatusUnauthorized
		case console.ErrValidation.Has(err), console.ErrExternalS3Invalid.Has(err):
			status = http.StatusBadRequest
		case console.ErrExternalS3NotFound.Has(err):
			status = http.StatusNotFound
		case console.ErrExternalS3NeedsReauth.Has(err):
			status = http.StatusConflict
		}
	}
	web.ServeJSONError(ctx, c.log, w, status, err)
}
