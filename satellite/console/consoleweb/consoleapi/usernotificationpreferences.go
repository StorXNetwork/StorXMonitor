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

// GetUserPreferences handles GET /api/v0/user/notification-preferences - Get current user's global preferences.
//
// @Summary      Get notification preferences
// @Description  **Full route:** `GET /api/v0/user/notification-preferences`. Settings → Notification preferences. Returns a JSON **array** with zero or one global preference row. Each row `Preferences` map uses keys `push`, `email`, `sms` with minimum priority levels 1–4 (marketing, info, warning, critical).
// @Tags         settings-notification-preferences
// @Produce      json
// @Success      200  {array}   UserNotificationPreferenceSwagger
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /user/notification-preferences [get]
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
	preference, err := preferenceService.GetUserPreference(ctx, user.ID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode([]configs.UserNotificationPreference{}); err != nil {
			u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode([]configs.UserNotificationPreference{preference}); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// UpsertUserPreference handles PUT /api/v0/user/notification-preferences - Create or update global user preferences.
//
// @Summary      Create or update notification preference
// @Description  **Full route:** `PUT /api/v0/user/notification-preferences`. Settings → Notification preferences. Upserts global channel thresholds applied to all notifications. `preferences` may include any of `push`, `email`, `sms` — each value is minimum priority to receive: 1=marketing, 2=info, 3=warning, 4=critical (string names `marketing`/`info`/`warning`/`critical` also accepted). Returns `201` on create, `200` on update.
// @Tags         settings-notification-preferences
// @Accept       json
// @Produce      json
// @Param        body  body  UpsertUserNotificationPreferenceSwaggerRequest  true  "Global channel preferences"
// @Success      200   {object}  UserNotificationPreferenceSwagger
// @Success      201   {object}  UserNotificationPreferenceSwagger
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /user/notification-preferences [put]
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
		Preferences map[string]interface{} `json:"preferences"`
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	if req.Preferences == nil {
		req.Preferences = make(map[string]interface{})
	}

	normalizedPreferences, err := configs.ValidateAndNormalizePreferences(req.Preferences)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	preference, isUpdate, err := preferenceService.UpsertUserPreference(ctx, user.ID, normalizedPreferences)
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
