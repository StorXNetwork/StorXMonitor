// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"net/http"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/configs"
)

var (
	// ErrUserNotificationPreferencesAPI - console user notification preferences api error type.
	ErrUserNotificationPreferencesAPI = errs.Class("consoleapi usernotificationpreferences")
)

// UserNotificationPreferences is an API controller for user notification preferences.
type UserNotificationPreferences struct {
	log     *zap.Logger
	service *console.Service
}

// NewUserNotificationPreferences creates a new user notification preferences controller.
func NewUserNotificationPreferences(log *zap.Logger, service *console.Service) *UserNotificationPreferences {
	return &UserNotificationPreferences{
		log:     log,
		service: service,
	}
}

// GetUserPreferences handles GET /api/v0/user/notification-preferences - Get current user's preferences.
// Query parameters:
//   - category: Filter by category (optional)
func (u *UserNotificationPreferences) GetUserPreferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())

	// Parse query parameters
	category := r.URL.Query().Get("category")

	// Validate category if provided
	if category != "" {
		if !configs.IsValidPreferenceCategory(category) {
			web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("invalid category. Valid categories are: billing, backup, account, vault"))
			return
		}
	}

	// If category is provided, get single preference by category
	if category != "" {
		preference, err := preferenceService.GetUserPreferenceByCategory(ctx, user.ID, category)
		if err != nil {
			web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(preference); err != nil {
			u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
		}
		return
	}

	// If no filters, get all preferences
	preferences, err := preferenceService.GetUserPreferences(ctx, user.ID)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(preferences); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// UpsertUserPreference handles PUT /api/v0/user/notification-preferences - Create or update user preferences.
func (u *UserNotificationPreferences) UpsertUserPreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	var req struct {
		Category    string                 `json:"category"`
		Preferences map[string]interface{} `json:"preferences"`
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	// Validate category (required)
	if req.Category == "" {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("category is required"))
		return
	}

	if !configs.IsValidPreferenceCategory(req.Category) {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("invalid category. Valid categories are: billing, backup, account, vault"))
		return
	}

	// Validate and normalize preferences
	// Only allows keys: push, email, sms
	// Values must be numbers 1-4 (or strings: marketing=1, info=2, warning=3, critical=4)
	if req.Preferences == nil {
		req.Preferences = make(map[string]interface{})
	}

	normalizedPreferences, err := configs.ValidateAndNormalizePreferences(req.Preferences)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	preference, isUpdate, err := preferenceService.UpsertUserPreference(ctx, user.ID, req.Category, normalizedPreferences)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if isUpdate {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	if err = json.NewEncoder(w).Encode(preference); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}
