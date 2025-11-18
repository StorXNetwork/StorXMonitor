// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"context"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
)

var (
	// ErrPreferences represents errors from the preferences service.
	ErrPreferences = errs.Class("preferences")
)

// PreferenceService provides user preference management operations.
type PreferenceService struct {
	db UserPreferenceDB
}

// NewPreferenceService creates a new preference service.
func NewPreferenceService(db UserPreferenceDB) *PreferenceService {
	return &PreferenceService{
		db: db,
	}
}

// GetUserPreferences retrieves all preferences for a user.
func (p *PreferenceService) GetUserPreferences(ctx context.Context, userID uuid.UUID) ([]UserNotificationPreference, error) {
	return p.db.GetUserPreferences(ctx, userID)
}

// GetUserPreferencesByType retrieves preferences for a user by config type.
func (p *PreferenceService) GetUserPreferencesByType(ctx context.Context, userID uuid.UUID, configType string) ([]UserNotificationPreference, error) {
	return p.db.GetUserPreferencesByType(ctx, userID, configType)
}

// GetUserPreferenceByConfig retrieves a preference for a specific config.
func (p *PreferenceService) GetUserPreferenceByConfig(ctx context.Context, userID uuid.UUID, configID uuid.UUID) (UserNotificationPreference, error) {
	return p.db.GetUserPreferenceByConfig(ctx, userID, configID)
}

// GetUserPreferenceByCategory retrieves a category-level preference.
func (p *PreferenceService) GetUserPreferenceByCategory(ctx context.Context, userID uuid.UUID, category string, configType string) (UserNotificationPreference, error) {
	return p.db.GetUserPreferenceByCategory(ctx, userID, category, configType)
}

// GetUserPreferenceByID retrieves a preference by ID.
func (p *PreferenceService) GetUserPreferenceByID(ctx context.Context, id uuid.UUID) (UserNotificationPreference, error) {
	return p.db.GetUserPreferenceByID(ctx, id)
}

// SetUserPreference creates or updates a user preference.
func (p *PreferenceService) SetUserPreference(ctx context.Context, request CreateUserPreferenceRequest) (UserNotificationPreference, error) {
	// Check if preference already exists
	var existingPreference *UserNotificationPreference
	var err error

	if request.ConfigID != nil {
		pref, err := p.db.GetUserPreferenceByConfig(ctx, request.UserID, *request.ConfigID)
		if err == nil {
			existingPreference = &pref
		}
	} else if request.Category != nil {
		pref, err := p.db.GetUserPreferenceByCategory(ctx, request.UserID, *request.Category, request.ConfigType)
		if err == nil {
			existingPreference = &pref
		}
	}

	if existingPreference != nil {
		// Update existing preference
		update := UpdateUserPreferenceRequest{
			Preferences:     &request.Preferences,
			CustomVariables: &request.CustomVariables,
			IsActive:        &request.IsActive,
		}
		return p.db.UpdateUserPreference(ctx, existingPreference.ID, update)
	}

	// Create new preference
	preferenceID, err := uuid.New()
	if err != nil {
		return UserNotificationPreference{}, ErrPreferences.Wrap(err)
	}

	preference := UserNotificationPreference{
		ID:             preferenceID,
		UserID:         request.UserID,
		ConfigType:     request.ConfigType,
		ConfigID:       request.ConfigID,
		Category:       request.Category,
		Preferences:    request.Preferences,
		CustomVariables: request.CustomVariables,
		IsActive:       request.IsActive,
	}

	return p.db.InsertUserPreference(ctx, preference)
}

// UpdateUserPreference updates a user preference.
func (p *PreferenceService) UpdateUserPreference(ctx context.Context, id uuid.UUID, update UpdateUserPreferenceRequest) (UserNotificationPreference, error) {
	return p.db.UpdateUserPreference(ctx, id, update)
}

// DeleteUserPreference deletes a user preference.
func (p *PreferenceService) DeleteUserPreference(ctx context.Context, id uuid.UUID) error {
	return p.db.DeleteUserPreference(ctx, id)
}

