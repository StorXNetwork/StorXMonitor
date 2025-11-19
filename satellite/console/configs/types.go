// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"time"

	"storj.io/common/uuid"
)

// ConfigType represents the type of configuration.
type ConfigType string

const (
	// ConfigTypeNotificationTemplate represents notification templates.
	ConfigTypeNotificationTemplate ConfigType = "notification_template"
	// ConfigTypeEmailTemplate represents email templates.
	ConfigTypeEmailTemplate ConfigType = "email_template"
	// ConfigTypePushTemplate represents push notification templates.
	ConfigTypePushTemplate ConfigType = "push_template"
	// ConfigTypeEmailSettings represents email settings.
	ConfigTypeEmailSettings ConfigType = "email_settings"
	// ConfigTypeNotificationSettings represents notification settings.
	ConfigTypeNotificationSettings ConfigType = "notification_settings"
	// ConfigTypeSystemSettings represents system settings.
	ConfigTypeSystemSettings ConfigType = "system_settings"
)

// Config represents a configuration entry in the database.
type Config struct {
	ID         uuid.UUID
	ConfigType ConfigType
	Name       string
	Category   *string
	ConfigData map[string]interface{} // JSON data
	IsActive   bool
	CreatedBy  *uuid.UUID
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TemplateData represents template-specific configuration data.
type TemplateData struct {
	Type             string                 `json:"type"`              // "email" or "push"
	Subject          string                 `json:"subject"`           // For email templates
	TitleTemplate    string                 `json:"title_template"`    // For push templates
	BodyTemplate     string                 `json:"body_template"`     // For both
	Variables        map[string]interface{} `json:"variables"`         // Variable definitions
	DefaultVariables map[string]interface{} `json:"default_variables"` // Default variable values
}

// UserNotificationPreference represents a user's notification preference.
type UserNotificationPreference struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	ConfigType      string
	Category        *string // NULL for config-specific preferences
	Preferences     map[string]interface{}
	CustomVariables map[string]interface{} // User-specific variable overrides
	IsActive        bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CreateConfigRequest represents a request to create a new configuration.
type CreateConfigRequest struct {
	ConfigType ConfigType
	Name       string
	Category   *string
	ConfigData map[string]interface{}
	IsActive   bool
	CreatedBy  *uuid.UUID
}

// UpdateConfigRequest represents a request to update a configuration.
type UpdateConfigRequest struct {
	ConfigData *map[string]interface{}
	IsActive   *bool
	Category   *string
}

// CreateUserPreferenceRequest represents a request to create user preferences.
type CreateUserPreferenceRequest struct {
	UserID          uuid.UUID
	ConfigType      string
	Category        *string
	Preferences     map[string]interface{}
	CustomVariables map[string]interface{}
	IsActive        bool
}

// UpdateUserPreferenceRequest represents a request to update user preferences.
type UpdateUserPreferenceRequest struct {
	Preferences     *map[string]interface{}
	CustomVariables *map[string]interface{}
	IsActive        *bool
}
