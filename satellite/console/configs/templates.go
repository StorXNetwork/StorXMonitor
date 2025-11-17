// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"context"
	"encoding/json"

	"storj.io/common/uuid"
)

// TemplateService provides template-specific operations.
type TemplateService struct {
	service *Service
	renderer *Renderer
}

// NewTemplateService creates a new template service.
func NewTemplateService(service *Service, renderer *Renderer) *TemplateService {
	return &TemplateService{
		service:  service,
		renderer: renderer,
	}
}

// GetTemplateByName retrieves a template by name.
func (t *TemplateService) GetTemplateByName(ctx context.Context, templateType ConfigType, name string) (Config, TemplateData, error) {
	config, err := t.service.GetConfigByName(ctx, templateType, name)
	if err != nil {
		return Config{}, TemplateData{}, ErrService.Wrap(err)
	}

	templateData, err := t.parseTemplateData(config.ConfigData)
	if err != nil {
		return Config{}, TemplateData{}, ErrService.Wrap(err)
	}

	return config, templateData, nil
}

// GetTemplateByID retrieves a template by ID.
func (t *TemplateService) GetTemplateByID(ctx context.Context, id uuid.UUID) (Config, TemplateData, error) {
	config, err := t.service.GetConfigByID(ctx, id)
	if err != nil {
		return Config{}, TemplateData{}, ErrService.Wrap(err)
	}

	templateData, err := t.parseTemplateData(config.ConfigData)
	if err != nil {
		return Config{}, TemplateData{}, ErrService.Wrap(err)
	}

	return config, templateData, nil
}

// ListTemplates lists all templates of the specified types.
func (t *TemplateService) ListTemplates(ctx context.Context, templateTypes []ConfigType) ([]Config, error) {
	var allTemplates []Config

	for _, templateType := range templateTypes {
		templates, err := t.service.GetConfigsByType(ctx, templateType)
		if err != nil {
			return nil, ErrService.Wrap(err)
		}
		allTemplates = append(allTemplates, templates...)
	}

	return allTemplates, nil
}

// RenderTemplate renders a template with the given variables and user preferences.
func (t *TemplateService) RenderTemplate(ctx context.Context, configID uuid.UUID, variables map[string]interface{}, userID *uuid.UUID, preferenceDB UserPreferenceDB) (title string, body string, subject string, err error) {
	config, err := t.service.GetConfigByID(ctx, configID)
	if err != nil {
		return "", "", "", ErrService.Wrap(err)
	}

	templateData, err := t.parseTemplateData(config.ConfigData)
	if err != nil {
		return "", "", "", ErrService.Wrap(err)
	}

	// Get user preferences if userID is provided
	var userCustomVars map[string]interface{}
	if userID != nil && preferenceDB != nil {
		preference, err := preferenceDB.GetUserPreferenceByConfig(ctx, *userID, configID)
		if err == nil {
			userCustomVars = preference.CustomVariables
		}
		// Ignore error if preference doesn't exist
	}

	// Merge variables with user preferences
	mergedVars := MergeUserPreferences(templateData.DefaultVariables, userCustomVars, variables)

	// Validate required variables
	if err := ValidateVariables(templateData, mergedVars); err != nil {
		return "", "", "", ErrService.Wrap(err)
	}

	// Render template
	title, body, subject, err = t.renderer.RenderTemplate(templateData, mergedVars)
	if err != nil {
		return "", "", "", ErrService.Wrap(err)
	}

	return title, body, subject, nil
}

// parseTemplateData parses template data from config_data JSON.
func (t *TemplateService) parseTemplateData(configData map[string]interface{}) (TemplateData, error) {
	dataJSON, err := json.Marshal(configData)
	if err != nil {
		return TemplateData{}, ErrService.Wrap(err)
	}

	var templateData TemplateData
	if err := json.Unmarshal(dataJSON, &templateData); err != nil {
		return TemplateData{}, ErrService.Wrap(err)
	}

	return templateData, nil
}

