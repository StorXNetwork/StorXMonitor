// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

// InternalStorxToken serves Backup-Tools internal service-to-service routes.
type InternalStorxToken struct {
	log               *zap.Logger
	service           *console.Service
	backupToolsAPIKey string
}

// NewInternalStorxToken constructs the internal StorX token HTTP controller.
func NewInternalStorxToken(log *zap.Logger, service *console.Service, backupToolsAPIKey string) *InternalStorxToken {
	return &InternalStorxToken{
		log:               log,
		service:           service,
		backupToolsAPIKey: backupToolsAPIKey,
	}
}

type refreshStorxTokenSwaggerRequest struct {
	UserID    string `json:"user_id"`
	ProjectID string `json:"project_id"`
	Email     string `json:"email,omitempty"`
}

type refreshStorxTokenSwaggerResponse struct {
	AccessGrant string `json:"access_grant,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (h *InternalStorxToken) validateBackupToolsAPIKey(r *http.Request) bool {
	expected := strings.TrimSpace(h.backupToolsAPIKey)
	if expected == "" {
		return false
	}
	provided := strings.TrimSpace(r.Header.Get("X-API-Key"))
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (h *InternalStorxToken) writeJSON(w http.ResponseWriter, status int, payload refreshStorxTokenSwaggerResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.log.Error("failed to encode internal storx token response", zap.Error(err))
	}
}

func (h *InternalStorxToken) writeError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if console.ErrUnauthorized.Has(err) {
		status = http.StatusUnauthorized
	} else if console.ErrValidation.Has(err) {
		status = http.StatusBadRequest
	} else if status < 400 {
		status = http.StatusInternalServerError
	}
	h.log.Debug("internal storx token refresh failed", zap.Error(err))
	h.writeJSON(w, status, refreshStorxTokenSwaggerResponse{Error: err.Error()})
	_ = ctx
}

// RefreshStorxToken handles POST /api/v0/internal/storx-token/refresh for Backup-Tools.
func (h *InternalStorxToken) RefreshStorxToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBackupToolsAPIKey(r) {
		h.writeJSON(w, http.StatusUnauthorized, refreshStorxTokenSwaggerResponse{Error: "unauthorized"})
		return
	}

	var body refreshStorxTokenSwaggerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		h.writeJSON(w, http.StatusBadRequest, refreshStorxTokenSwaggerResponse{Error: "invalid request body"})
		return
	}
	if dec.More() {
		h.writeJSON(w, http.StatusBadRequest, refreshStorxTokenSwaggerResponse{Error: "invalid request body"})
		return
	}

	result, err := h.service.RefreshStorxTokenForBackupTools(ctx, console.RefreshStorxTokenRequest{
		UserID:    body.UserID,
		ProjectID: body.ProjectID,
		Email:     body.Email,
	})
	if err != nil {
		h.writeError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	h.writeJSON(w, http.StatusOK, refreshStorxTokenSwaggerResponse{
		AccessGrant: result.AccessGrant,
		ProjectID:   result.ProjectID,
	})
}

type clearGoogleTokenSwaggerRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type clearGoogleTokenSwaggerResponse struct {
	Error string `json:"error,omitempty"`
}

func (h *InternalStorxToken) writeClearGoogleTokenJSON(w http.ResponseWriter, status int, payload clearGoogleTokenSwaggerResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.log.Error("failed to encode internal google token clear response", zap.Error(err))
	}
}

// ClearGoogleToken handles POST /api/v0/internal/google-token/clear for Backup-Tools.
func (h *InternalStorxToken) ClearGoogleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBackupToolsAPIKey(r) {
		h.writeClearGoogleTokenJSON(w, http.StatusUnauthorized, clearGoogleTokenSwaggerResponse{Error: "unauthorized"})
		return
	}

	var body clearGoogleTokenSwaggerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		h.writeClearGoogleTokenJSON(w, http.StatusBadRequest, clearGoogleTokenSwaggerResponse{Error: "invalid request body"})
		return
	}
	if dec.More() {
		h.writeClearGoogleTokenJSON(w, http.StatusBadRequest, clearGoogleTokenSwaggerResponse{Error: "invalid request body"})
		return
	}

	if err := h.service.ClearGoogleBackupTokensForBackupTools(ctx, console.ClearGoogleBackupTokensRequest{
		UserID: body.UserID,
		Email:  body.Email,
	}); err != nil {
		status := http.StatusInternalServerError
		if console.ErrUnauthorized.Has(err) {
			status = http.StatusUnauthorized
		} else if console.ErrValidation.Has(err) {
			status = http.StatusBadRequest
		}
		h.log.Debug("internal google token clear failed", zap.Error(err))
		h.writeClearGoogleTokenJSON(w, status, clearGoogleTokenSwaggerResponse{Error: err.Error()})
		return
	}

	h.writeClearGoogleTokenJSON(w, http.StatusOK, clearGoogleTokenSwaggerResponse{})
}
