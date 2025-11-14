// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/pushnotifications"
)

var (
	// ErrPushNotificationsAPI - console push notifications api error type.
	ErrPushNotificationsAPI = errs.Class("consoleapi pushnotifications")
)

// PushNotifications is an API controller for FCM token management.
type PushNotifications struct {
	log     *zap.Logger
	service *console.Service
}

// NewPushNotifications creates a new push notifications controller.
func NewPushNotifications(log *zap.Logger, service *console.Service) *PushNotifications {
	return &PushNotifications{
		log:     log,
		service: service,
	}
}

// RegisterTokenRequest for POST /api/v0/push-notifications/tokens.
type RegisterTokenRequest struct {
	Token       string  `json:"token"`        // Required: FCM token
	DeviceID    *string `json:"deviceId"`    // Optional: device identifier
	DeviceType  *string `json:"deviceType"`   // Optional: "android", "ios", "web"
	AppVersion  *string `json:"appVersion"`   // Optional: app version
	OSVersion   *string `json:"osVersion"`    // Optional: OS version
	DeviceModel *string `json:"deviceModel"`  // Optional: device model
	BrowserName *string `json:"browserName"`  // Optional: browser name (web only)
	UserAgent   *string `json:"userAgent"`    // Optional: full user agent string
	// Note: ip_address is extracted from request on server side, not from client
}

// RegisterToken handles POST /api/v0/push-notifications/tokens.
// Saves/registers a new FCM token for the authenticated user.
func (p *PushNotifications) RegisterToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	var req RegisterTokenRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	if req.Token == "" {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.New("token is required"))
		return
	}

	// Extract IP address from request
	ipAddress := extractIPAddress(r)

	// Check if token already exists
	existingToken, err := p.service.GetFCMTokens().GetTokenByToken(ctx, req.Token)
	if err == nil && existingToken.ID != (uuid.UUID{}) {
		// Token exists, update it
		updateReq := pushnotifications.UpdateTokenRequest{
			DeviceID:    req.DeviceID,
			DeviceType:  req.DeviceType,
			AppVersion:  req.AppVersion,
			OSVersion:   req.OSVersion,
			DeviceModel: req.DeviceModel,
			BrowserName: req.BrowserName,
			UserAgent:   req.UserAgent,
		}
		if err = p.service.GetFCMTokens().UpdateToken(ctx, existingToken.ID, updateReq); err != nil {
			web.ServeJSONError(ctx, p.log, w, http.StatusInternalServerError, ErrPushNotificationsAPI.Wrap(err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(existingToken); err != nil {
			p.log.Error("failed to encode response", zap.Error(err))
		}
		return
	}

	// Create new token
	tokenID, err := uuid.New()
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusInternalServerError, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	fcmToken := pushnotifications.FCMToken{
		ID:         tokenID,
		UserID:     user.ID,
		Token:      req.Token,
		DeviceID:   req.DeviceID,
		DeviceType: req.DeviceType,
		AppVersion: req.AppVersion,
		OSVersion:  req.OSVersion,
		DeviceModel: req.DeviceModel,
		BrowserName: req.BrowserName,
		UserAgent:   req.UserAgent,
		IPAddress:   &ipAddress,
		IsActive:   true,
	}

	createdToken, err := p.service.GetFCMTokens().InsertToken(ctx, fcmToken)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusInternalServerError, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err = json.NewEncoder(w).Encode(createdToken); err != nil {
		p.log.Error("failed to encode response", zap.Error(err))
	}
}

// UpdateTokenRequest for PUT /api/v0/push-notifications/tokens/:tokenId.
type UpdateTokenRequest struct {
	Token       *string `json:"token"`
	DeviceID    *string `json:"deviceId"`
	DeviceType  *string `json:"deviceType"`
	AppVersion  *string `json:"appVersion"`
	OSVersion   *string `json:"osVersion"`
	DeviceModel *string `json:"deviceModel"`
	BrowserName *string `json:"browserName"`
	UserAgent   *string `json:"userAgent"`
	IsActive    *bool   `json:"isActive"`
}

// UpdateToken handles PUT /api/v0/push-notifications/tokens/:tokenId.
// Updates an existing FCM token.
func (p *PushNotifications) UpdateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	tokenIDStr, ok := vars["tokenId"]
	if !ok {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.New("tokenId is required"))
		return
	}

	tokenID, err := uuid.FromString(tokenIDStr)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	// Verify token belongs to user
	existingToken, err := p.service.GetFCMTokens().GetTokenByID(ctx, tokenID)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusNotFound, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	if existingToken.UserID != user.ID {
		web.ServeJSONError(ctx, p.log, w, http.StatusForbidden, ErrPushNotificationsAPI.New("token does not belong to user"))
		return
	}

	var req UpdateTokenRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	updateReq := pushnotifications.UpdateTokenRequest{
		DeviceID:    req.DeviceID,
		DeviceType:  req.DeviceType,
		AppVersion:  req.AppVersion,
		OSVersion:   req.OSVersion,
		DeviceModel: req.DeviceModel,
		BrowserName: req.BrowserName,
		UserAgent:   req.UserAgent,
		IsActive:    req.IsActive,
	}

	if err = p.service.GetFCMTokens().UpdateToken(ctx, tokenID, updateReq); err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusInternalServerError, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(map[string]string{"message": "token updated successfully"}); err != nil {
		p.log.Error("failed to encode response", zap.Error(err))
	}
}

// GetTokens handles GET /api/v0/push-notifications/tokens.
// Retrieves all tokens for the authenticated user.
func (p *PushNotifications) GetTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	tokens, err := p.service.GetFCMTokens().GetTokensByUserID(ctx, user.ID)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusInternalServerError, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(tokens); err != nil {
		p.log.Error("failed to encode response", zap.Error(err))
	}
}

// DeleteToken handles DELETE /api/v0/push-notifications/tokens/:tokenId.
// Deletes a token (soft delete by setting is_active = false).
func (p *PushNotifications) DeleteToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	tokenIDStr, ok := vars["tokenId"]
	if !ok {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.New("tokenId is required"))
		return
	}

	tokenID, err := uuid.FromString(tokenIDStr)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusBadRequest, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	// Verify token belongs to user
	existingToken, err := p.service.GetFCMTokens().GetTokenByID(ctx, tokenID)
	if err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusNotFound, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	if existingToken.UserID != user.ID {
		web.ServeJSONError(ctx, p.log, w, http.StatusForbidden, ErrPushNotificationsAPI.New("token does not belong to user"))
		return
	}

	if err = p.service.GetFCMTokens().DeleteToken(ctx, tokenID); err != nil {
		web.ServeJSONError(ctx, p.log, w, http.StatusInternalServerError, ErrPushNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(map[string]string{"message": "token deleted successfully"}); err != nil {
		p.log.Error("failed to encode response", zap.Error(err))
	}
}

// extractIPAddress extracts the client IP address from HTTP request headers.
// It checks X-Forwarded-For, X-Real-IP, and falls back to RemoteAddr.
func extractIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header (first IP in the chain)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present (format: "IP:port")
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

