// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"context"

	"storj.io/common/uuid"
)

// DB defines database operations for configurations.
type DB interface {
	// InsertConfig creates a new configuration.
	InsertConfig(ctx context.Context, config Config) (Config, error)

	// GetConfigByID retrieves a configuration by ID.
	GetConfigByID(ctx context.Context, id uuid.UUID) (Config, error)

	// GetConfigByName retrieves a configuration by type and name.
	GetConfigByName(ctx context.Context, configType ConfigType, name string) (Config, error)

	// ListConfigs lists configurations with optional filters.
	ListConfigs(ctx context.Context, filters ListConfigFilters) ([]Config, error)

	// UpdateConfig updates a configuration.
	UpdateConfig(ctx context.Context, id uuid.UUID, update UpdateConfigRequest) (Config, error)

	// DeleteConfig permanently deletes a configuration.
	DeleteConfig(ctx context.Context, id uuid.UUID) error

	// GetConfigsByType retrieves all configs of a specific type.
	GetConfigsByType(ctx context.Context, configType ConfigType) ([]Config, error)
}

// UserPreferenceDB defines database operations for user notification preferences.
type UserPreferenceDB interface {
	// InsertUserPreference creates a new user preference.
	InsertUserPreference(ctx context.Context, preference UserNotificationPreference) (UserNotificationPreference, error)

	// GetUserPreferences retrieves all preferences for a user.
	GetUserPreferences(ctx context.Context, userID uuid.UUID) ([]UserNotificationPreference, error)

	// GetUserPreferenceByCategory retrieves a category-level preference.
	GetUserPreferenceByCategory(ctx context.Context, userID uuid.UUID, category string) (UserNotificationPreference, error)

	// UpdateUserPreference updates a user preference.
	UpdateUserPreference(ctx context.Context, id uuid.UUID, update UpdateUserPreferenceRequest) (UserNotificationPreference, error)
}

// ListConfigFilters contains filters for listing configurations.
type ListConfigFilters struct {
	ConfigType *ConfigType
	Category   *string
	IsActive   *bool
}
