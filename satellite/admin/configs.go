// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console/configs"
)

// createConfig handles POST /api/configs - Create configuration (Admin-only).
func (server *Server) createConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		ConfigType string                 `json:"config_type"`
		Name       string                 `json:"name"`
		Category   *string                `json:"category"`
		ConfigData map[string]interface{} `json:"config_data"`
		IsActive   bool                   `json:"is_active"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if input.ConfigType == "" {
		sendJSONError(w, "config_type is required", "", http.StatusBadRequest)
		return
	}
	if input.Name == "" {
		sendJSONError(w, "name is required", "", http.StatusBadRequest)
		return
	}
	if input.ConfigData == nil {
		sendJSONError(w, "config_data is required", "", http.StatusBadRequest)
		return
	}

	// Get admin user from context
	adminUser, err := GetAdminUser(ctx)
	if err != nil {
		sendJSONError(w, "unauthorized", "admin user not found in context", http.StatusUnauthorized)
		return
	}

	// Check if config already exists
	existingConfig, err := server.db.Console().Configs().GetConfigByName(ctx, configs.ConfigType(input.ConfigType), input.Name)
	if err == nil && existingConfig.ID != (uuid.UUID{}) {
		sendJSONError(w, "config already exists",
			"", http.StatusConflict)
		return
	}

	// Create new config
	configID, err := uuid.New()
	if err != nil {
		sendJSONError(w, "unable to create UUID",
			err.Error(), http.StatusInternalServerError)
		return
	}

	newConfig, err := server.db.Console().Configs().InsertConfig(ctx, configs.Config{
		ID:         configID,
		ConfigType: configs.ConfigType(input.ConfigType),
		Name:       input.Name,
		Category:   input.Category,
		ConfigData: input.ConfigData,
		IsActive:   input.IsActive,
		CreatedBy:  &adminUser.ID,
	})
	if err != nil {
		sendJSONError(w, "failed to insert config",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(newConfig)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusCreated, data)
}

// getConfig handles GET /api/configs/{id} - Get configuration by ID (Admin-only).
func (server *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		sendJSONError(w, "id missing", "", http.StatusBadRequest)
		return
	}

	configID, err := uuidFromString(idString)
	if err != nil {
		sendJSONError(w, "invalid id format", err.Error(), http.StatusBadRequest)
		return
	}

	config, err := server.db.Console().Configs().GetConfigByID(ctx, configID)
	if err != nil {
		sendJSONError(w, "failed to get config",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(config)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// listConfigs handles GET /api/configs - List configurations (Admin-only).
func (server *Server) listConfigs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Parse query parameters
	configType := r.URL.Query().Get("type")
	category := r.URL.Query().Get("category")
	isActiveStr := r.URL.Query().Get("is_active")

	filters := configs.ListConfigFilters{}

	if configType != "" {
		ct := configs.ConfigType(configType)
		filters.ConfigType = &ct
	}
	if category != "" {
		filters.Category = &category
	}
	if isActiveStr != "" {
		isActive := isActiveStr == "true"
		filters.IsActive = &isActive
	}

	configsList, err := server.db.Console().Configs().ListConfigs(ctx, filters)
	if err != nil {
		sendJSONError(w, "failed to list configs",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(configsList)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// updateConfig handles PUT /api/configs/{id} - Update configuration (Admin-only).
func (server *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		sendJSONError(w, "id missing", "", http.StatusBadRequest)
		return
	}

	configID, err := uuidFromString(idString)
	if err != nil {
		sendJSONError(w, "invalid id format", err.Error(), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		ConfigData *map[string]interface{} `json:"config_data"`
		IsActive   *bool                   `json:"is_active"`
		Category   *string                 `json:"category"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	update := configs.UpdateConfigRequest{
		ConfigData: input.ConfigData,
		IsActive:   input.IsActive,
		Category:   input.Category,
	}

	updatedConfig, err := server.db.Console().Configs().UpdateConfig(ctx, configID, update)
	if err != nil {
		sendJSONError(w, "failed to update config",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(updatedConfig)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// deleteConfig handles DELETE /api/configs/{id} - Delete configuration (Admin-only).
func (server *Server) deleteConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		sendJSONError(w, "id missing", "", http.StatusBadRequest)
		return
	}

	configID, err := uuidFromString(idString)
	if err != nil {
		sendJSONError(w, "invalid id format", err.Error(), http.StatusBadRequest)
		return
	}

	err = server.db.Console().Configs().DeleteConfig(ctx, configID)
	if err != nil {
		sendJSONError(w, "failed to delete config",
			err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getConfigByTypeAndName handles GET /api/configs/type/{type}/name/{name} - Get configuration by type and name (Admin-only).
func (server *Server) getConfigByTypeAndName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	configType, ok := vars["type"]
	if !ok {
		sendJSONError(w, "type missing", "", http.StatusBadRequest)
		return
	}

	name, ok := vars["name"]
	if !ok {
		sendJSONError(w, "name missing", "", http.StatusBadRequest)
		return
	}

	config, err := server.db.Console().Configs().GetConfigByName(ctx, configs.ConfigType(configType), name)
	if err != nil {
		sendJSONError(w, "failed to get config",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(config)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// listConfigsByType handles GET /api/configs/type/{type} - List all configs of a specific type (Admin-only).
func (server *Server) listConfigsByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	configType, ok := vars["type"]
	if !ok {
		sendJSONError(w, "type missing", "", http.StatusBadRequest)
		return
	}

	configsList, err := server.db.Console().Configs().GetConfigsByType(ctx, configs.ConfigType(configType))
	if err != nil {
		sendJSONError(w, "failed to list configs",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(configsList)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// createTemplate handles POST /api/notification-templates - Create template (Admin-only).
func (server *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Type             string                 `json:"type"` // "email" or "push"
		Name             string                 `json:"name"`
		Category         *string                `json:"category"`
		Subject          string                 `json:"subject"`        // For email
		TitleTemplate    string                 `json:"title_template"` // For push
		BodyTemplate     string                 `json:"body_template"`
		Variables        map[string]interface{} `json:"variables"`
		DefaultVariables map[string]interface{} `json:"default_variables"`
		IsActive         bool                   `json:"is_active"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if input.Type == "" {
		sendJSONError(w, "type is required", "", http.StatusBadRequest)
		return
	}
	if input.Name == "" {
		sendJSONError(w, "name is required", "", http.StatusBadRequest)
		return
	}
	if input.BodyTemplate == "" {
		sendJSONError(w, "body_template is required", "", http.StatusBadRequest)
		return
	}

	// Determine config_type based on template type
	var configType configs.ConfigType
	switch input.Type {
	case "email":
		configType = configs.ConfigTypeEmailTemplate
	case "push":
		configType = configs.ConfigTypePushTemplate
	default:
		sendJSONError(w, "invalid type", "type must be 'email' or 'push'", http.StatusBadRequest)
		return
	}

	// Get admin user from context
	adminUser, err := GetAdminUser(ctx)
	if err != nil {
		sendJSONError(w, "unauthorized", "admin user not found in context", http.StatusUnauthorized)
		return
	}

	// Check if template already exists
	existingConfig, err := server.db.Console().Configs().GetConfigByName(ctx, configType, input.Name)
	if err == nil && existingConfig.ID != (uuid.UUID{}) {
		sendJSONError(w, "template already exists",
			"", http.StatusConflict)
		return
	}

	// Build config_data
	configData := map[string]interface{}{
		"type":              input.Type,
		"body_template":     input.BodyTemplate,
		"variables":         input.Variables,
		"default_variables": input.DefaultVariables,
	}
	if input.Type == "email" {
		configData["subject"] = input.Subject
	} else {
		configData["title_template"] = input.TitleTemplate
	}

	// Create new template config
	configID, err := uuid.New()
	if err != nil {
		sendJSONError(w, "unable to create UUID",
			err.Error(), http.StatusInternalServerError)
		return
	}

	newConfig, err := server.db.Console().Configs().InsertConfig(ctx, configs.Config{
		ID:         configID,
		ConfigType: configType,
		Name:       input.Name,
		Category:   input.Category,
		ConfigData: configData,
		IsActive:   input.IsActive,
		CreatedBy:  &adminUser.ID,
	})
	if err != nil {
		sendJSONError(w, "failed to insert template",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(newConfig)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusCreated, data)
}

// renderTemplate handles POST /api/notification-templates/{id}/render - Preview rendered template (Admin-only).
func (server *Server) renderTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	idString, ok := vars["id"]
	if !ok {
		sendJSONError(w, "id missing", "", http.StatusBadRequest)
		return
	}

	configID, err := uuidFromString(idString)
	if err != nil {
		sendJSONError(w, "invalid id format", err.Error(), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Variables map[string]interface{} `json:"variables"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Get config
	config, err := server.db.Console().Configs().GetConfigByID(ctx, configID)
	if err != nil {
		sendJSONError(w, "failed to get config",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse template data
	var templateData configs.TemplateData
	configDataJSON, err := json.Marshal(config.ConfigData)
	if err != nil {
		sendJSONError(w, "failed to parse config data",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(configDataJSON, &templateData); err != nil {
		sendJSONError(w, "failed to parse template data",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Render template
	renderer := configs.NewRenderer()
	title, bodyText, subject, err := renderer.RenderTemplate(templateData, input.Variables)
	if err != nil {
		sendJSONError(w, "failed to render template",
			err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"title":   title,
		"body":    bodyText,
		"subject": subject,
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}
