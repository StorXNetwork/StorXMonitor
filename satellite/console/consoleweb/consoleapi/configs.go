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
	// ErrConfigsAPI - console configs api error type.
	ErrConfigsAPI = errs.Class("consoleapi configs")
)

// Configs is an API controller for configuration read operations.
type Configs struct {
	log     *zap.Logger
	service *console.Service
}

// NewConfigs creates a new configs controller.
func NewConfigs(log *zap.Logger, service *console.Service) *Configs {
	return &Configs{
		log:     log,
		service: service,
	}
}

// GetConfig handles GET /api/v0/configs/{id} - Get configuration by ID (User-authenticated, read-only).
// Users can only see active configs.
func (c *Configs) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		web.ServeJSONError(ctx, c.log, w, http.StatusBadRequest, ErrConfigsAPI.New("id missing"))
		return
	}

	configID, err := uuid.FromString(idString)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusBadRequest, ErrConfigsAPI.Wrap(err))
		return
	}

	configService := configs.NewService(c.service.GetConfigs())
	config, err := configService.GetConfigByID(ctx, configID)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusInternalServerError, ErrConfigsAPI.Wrap(err))
		return
	}

	// Users can only see active configs
	if !config.IsActive {
		web.ServeJSONError(ctx, c.log, w, http.StatusNotFound, ErrConfigsAPI.New("config not found"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(config); err != nil {
		c.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// ListConfigs handles GET /api/v0/configs - List configurations (User-authenticated, read-only).
// Users can only see active configs (is_active=true is hardcoded).
func (c *Configs) ListConfigs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	// Parse query parameters
	configType := r.URL.Query().Get("type")
	category := r.URL.Query().Get("category")
	// Note: Users can only see active configs, so is_active filter is ignored and hardcoded to true

	filters := configs.ListConfigFilters{}

	if configType != "" {
		ct := configs.ConfigType(configType)
		filters.ConfigType = &ct
	}
	if category != "" {
		filters.Category = &category
	}
	// Hardcode is_active=true for users (they can only see active configs)
	isActive := true
	filters.IsActive = &isActive

	configService := configs.NewService(c.service.GetConfigs())
	configsList, err := configService.ListConfigs(ctx, filters)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusInternalServerError, ErrConfigsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(configsList); err != nil {
		c.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// GetConfigByTypeAndName handles GET /api/v0/configs/type/{type}/name/{name} - Get configuration by type and name (User-authenticated, read-only).
// Users can only see active configs.
func (c *Configs) GetConfigByTypeAndName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	configType, ok := vars["type"]
	if !ok {
		web.ServeJSONError(ctx, c.log, w, http.StatusBadRequest, ErrConfigsAPI.New("type missing"))
		return
	}

	name, ok := vars["name"]
	if !ok {
		web.ServeJSONError(ctx, c.log, w, http.StatusBadRequest, ErrConfigsAPI.New("name missing"))
		return
	}

	configService := configs.NewService(c.service.GetConfigs())
	config, err := configService.GetConfigByName(ctx, configs.ConfigType(configType), name)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusInternalServerError, ErrConfigsAPI.Wrap(err))
		return
	}

	// Users can only see active configs
	if !config.IsActive {
		web.ServeJSONError(ctx, c.log, w, http.StatusNotFound, ErrConfigsAPI.New("config not found"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(config); err != nil {
		c.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// ListConfigsByType handles GET /api/v0/configs/type/{type} - List all configs of a specific type (User-authenticated, read-only).
// Users can only see active configs.
func (c *Configs) ListConfigsByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	configType, ok := vars["type"]
	if !ok {
		web.ServeJSONError(ctx, c.log, w, http.StatusBadRequest, ErrConfigsAPI.New("type missing"))
		return
	}

	configService := configs.NewService(c.service.GetConfigs())
	configsList, err := configService.GetConfigsByType(ctx, configs.ConfigType(configType))
	if err != nil {
		web.ServeJSONError(ctx, c.log, w, http.StatusInternalServerError, ErrConfigsAPI.Wrap(err))
		return
	}

	// Filter to only active configs for users
	activeConfigs := make([]configs.Config, 0, len(configsList))
	for _, config := range configsList {
		if config.IsActive {
			activeConfigs = append(activeConfigs, config)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(activeConfigs); err != nil {
		c.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}
