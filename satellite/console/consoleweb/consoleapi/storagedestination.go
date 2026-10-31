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

// ErrStorageDestinationAPI - console storage destination api error type.
var ErrStorageDestinationAPI = errs.Class("console storage destination")

// StorageDestination is an api controller for storage destination settings.
type StorageDestination struct {
	log     *zap.Logger
	service *console.Service
}

// NewStorageDestination is a constructor for StorageDestination controller.
func NewStorageDestination(log *zap.Logger, service *console.Service) *StorageDestination {
	return &StorageDestination{log: log, service: service}
}

// GetStorageDestination returns the current user's storage destination.
func (c *StorageDestination) GetStorageDestination(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	resp, err := c.service.GetStorageDestination(ctx)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		c.log.Error("failed to write storage destination response", zap.Error(ErrStorageDestinationAPI.Wrap(err)))
	}
}

// SetStorageDestination upserts the current user's storage destination.
func (c *StorageDestination) SetStorageDestination(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var payload console.UpsertStorageDestinationRequest
	if err = json.NewDecoder(r.Body).Decode(&payload); err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	resp, err := c.service.SetStorageDestination(ctx, payload)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		c.log.Error("failed to write storage destination update response", zap.Error(ErrStorageDestinationAPI.Wrap(err)))
	}
}

func (c *StorageDestination) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if status == 0 {
		status = http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err):
			status = http.StatusUnauthorized
		case console.ErrValidation.Has(err), console.ErrStorageDestinationInvalid.Has(err):
			status = http.StatusBadRequest
		}
	}
	web.ServeJSONError(ctx, c.log, w, status, err)
}
