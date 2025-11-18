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
	// ErrNotificationTemplatesAPI - console notification templates api error type.
	ErrNotificationTemplatesAPI = errs.Class("consoleapi notificationtemplates")
)

// NotificationTemplates is an API controller for notification template read operations.
type NotificationTemplates struct {
	log     *zap.Logger
	service *console.Service
}

// NewNotificationTemplates creates a new notification templates controller.
func NewNotificationTemplates(log *zap.Logger, service *console.Service) *NotificationTemplates {
	return &NotificationTemplates{
		log:     log,
		service: service,
	}
}

// ListTemplates handles GET /api/v0/notification-templates - List templates (User-authenticated, read-only).
func (n *NotificationTemplates) ListTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	// Get all template types
	templateTypes := []configs.ConfigType{
		configs.ConfigTypeEmailTemplate,
		configs.ConfigTypePushTemplate,
		configs.ConfigTypeNotificationTemplate,
	}

	configService := configs.NewService(n.service.GetConfigs())
	templateService := configs.NewTemplateService(configService, configs.NewRenderer())

	templates, err := templateService.ListTemplates(ctx, templateTypes)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNotificationTemplatesAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(templates); err != nil {
		n.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// GetTemplate handles GET /api/v0/notification-templates/{id} - Get template by ID (User-authenticated, read-only).
func (n *NotificationTemplates) GetTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationTemplatesAPI.New("id missing"))
		return
	}

	configID, err := uuid.FromString(idString)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationTemplatesAPI.Wrap(err))
		return
	}

	configService := configs.NewService(n.service.GetConfigs())
	templateService := configs.NewTemplateService(configService, configs.NewRenderer())

	config, templateData, err := templateService.GetTemplateByID(ctx, configID)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNotificationTemplatesAPI.Wrap(err))
		return
	}

	response := map[string]interface{}{
		"config":        config,
		"template_data": templateData,
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(response); err != nil {
		n.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

// GetTemplateByName handles GET /api/v0/notification-templates/name/{name} - Get template by name (User-authenticated, read-only).
func (n *NotificationTemplates) GetTemplateByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	vars := mux.Vars(r)
	name, ok := vars["name"]
	if !ok {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationTemplatesAPI.New("name missing"))
		return
	}

	// Try to find template in different types
	templateTypes := []configs.ConfigType{
		configs.ConfigTypeEmailTemplate,
		configs.ConfigTypePushTemplate,
		configs.ConfigTypeNotificationTemplate,
	}

	configService := configs.NewService(n.service.GetConfigs())
	templateService := configs.NewTemplateService(configService, configs.NewRenderer())

	var config configs.Config
	var templateData configs.TemplateData
	var found bool

	for _, templateType := range templateTypes {
		config, templateData, err = templateService.GetTemplateByName(ctx, templateType, name)
		if err == nil {
			found = true
			break
		}
	}

	if !found {
		web.ServeJSONError(ctx, n.log, w, http.StatusNotFound, ErrNotificationTemplatesAPI.New("template not found"))
		return
	}

	response := map[string]interface{}{
		"config":        config,
		"template_data": templateData,
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(response); err != nil {
		n.log.Error("failed to encode response", zap.Error(err), zap.Stringer("user_id", user.ID))
	}
}

