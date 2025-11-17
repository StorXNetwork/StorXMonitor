// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/configs"
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

// SetUserPreference handles POST /api/v0/user/notification-preferences - Set user preferences.
func (u *UserNotificationPreferences) SetUserPreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	var req struct {
		ConfigType     string                 `json:"config_type"`
		ConfigID       *string                `json:"config_id"`
		Category       *string                `json:"category"`
		Preferences    map[string]interface{} `json:"preferences"`
		CustomVariables map[string]interface{} `json:"custom_variables"`
		IsActive       bool                   `json:"is_active"`
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	if req.ConfigType == "" {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("config_type is required"))
		return
	}

	if req.Preferences == nil {
		req.Preferences = make(map[string]interface{})
	}

	var configID *uuid.UUID
	if req.ConfigID != nil {
		id, err := uuid.FromString(*req.ConfigID)
		if err != nil {
			web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
			return
		}
		configID = &id
	}

	createReq := configs.CreateUserPreferenceRequest{
		UserID:          user.ID,
		ConfigType:      req.ConfigType,
		ConfigID:        configID,
		Category:        req.Category,
		Preferences:     req.Preferences,
		CustomVariables: req.CustomVariables,
		IsActive:        req.IsActive,
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	preference, err := preferenceService.SetUserPreference(ctx, createReq)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err = json.NewEncoder(w).Encode(preference); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// GetUserPreferencesByType handles GET /api/v0/user/notification-preferences/type/{type} - Get preferences for a config type.
func (u *UserNotificationPreferences) GetUserPreferencesByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	configType, ok := vars["type"]
	if !ok {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("type missing"))
		return
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	preferences, err := preferenceService.GetUserPreferencesByType(ctx, user.ID, configType)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(preferences); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// GetUserPreferenceByConfig handles GET /api/v0/user/notification-preferences/config/{configId} - Get preference for specific config.
func (u *UserNotificationPreferences) GetUserPreferenceByConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	configIDString, ok := vars["configId"]
	if !ok {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("configId missing"))
		return
	}

	configID, err := uuid.FromString(configIDString)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	preference, err := preferenceService.GetUserPreferenceByConfig(ctx, user.ID, configID)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(preference); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// GetUserPreferenceByCategory handles GET /api/v0/user/notification-preferences/category/{category} - Get preference for category.
func (u *UserNotificationPreferences) GetUserPreferenceByCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	category, ok := vars["category"]
	if !ok {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("category missing"))
		return
	}

	configType := r.URL.Query().Get("type")
	if configType == "" {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("type query parameter is required"))
		return
	}

	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	preference, err := preferenceService.GetUserPreferenceByCategory(ctx, user.ID, category, configType)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(preference); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// UpdateUserPreference handles PUT /api/v0/user/notification-preferences/{id} - Update user preference.
func (u *UserNotificationPreferences) UpdateUserPreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("id missing"))
		return
	}

	preferenceID, err := uuid.FromString(idString)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	// Verify the preference belongs to the user
	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	existingPreference, err := preferenceService.GetUserPreferenceByID(ctx, preferenceID)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusNotFound, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}
	if existingPreference.UserID != user.ID {
		web.ServeJSONError(ctx, u.log, w, http.StatusForbidden, ErrUserNotificationPreferencesAPI.New("preference does not belong to user"))
		return
	}

	var req struct {
		Preferences    *map[string]interface{} `json:"preferences"`
		CustomVariables *map[string]interface{} `json:"custom_variables"`
		IsActive       *bool                   `json:"is_active"`
	}

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	update := configs.UpdateUserPreferenceRequest{
		Preferences:     req.Preferences,
		CustomVariables: req.CustomVariables,
		IsActive:        req.IsActive,
	}

	preference, err := preferenceService.UpdateUserPreference(ctx, preferenceID, update)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(preference); err != nil {
		u.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// DeleteUserPreference handles DELETE /api/v0/user/notification-preferences/{id} - Delete user preference.
func (u *UserNotificationPreferences) DeleteUserPreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.New("id missing"))
		return
	}

	preferenceID, err := uuid.FromString(idString)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusBadRequest, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	// Verify the preference belongs to the user
	preferenceService := configs.NewPreferenceService(u.service.GetUserNotificationPreferences())
	existingPreference, err := preferenceService.GetUserPreferenceByID(ctx, preferenceID)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusNotFound, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}
	if existingPreference.UserID != user.ID {
		web.ServeJSONError(ctx, u.log, w, http.StatusForbidden, ErrUserNotificationPreferencesAPI.New("preference does not belong to user"))
		return
	}

	err = preferenceService.DeleteUserPreference(ctx, preferenceID)
	if err != nil {
		web.ServeJSONError(ctx, u.log, w, http.StatusInternalServerError, ErrUserNotificationPreferencesAPI.Wrap(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

