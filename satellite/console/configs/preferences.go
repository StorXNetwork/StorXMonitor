// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"context"
	"strconv"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
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

// GetUserPreference retrieves the global preference row for a user.
func (p *PreferenceService) GetUserPreference(ctx context.Context, userID uuid.UUID) (UserNotificationPreference, error) {
	return p.db.GetUserPreference(ctx, userID)
}

// UpsertUserPreference creates or updates the global preference row for a user.
func (p *PreferenceService) UpsertUserPreference(ctx context.Context, userID uuid.UUID, preferences map[string]interface{}) (UserNotificationPreference, bool, error) {
	existingPreference, err := p.db.GetUserPreference(ctx, userID)
	if err == nil {
		update := UpdateUserPreferenceRequest{
			Preferences: &preferences,
		}
		preference, err := p.db.UpdateUserPreference(ctx, existingPreference.ID, update)
		if err != nil {
			return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
		}
		return preference, true, nil
	}

	preferenceID, err := uuid.New()
	if err != nil {
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}

	preference := UserNotificationPreference{
		ID:          preferenceID,
		UserID:      userID,
		Preferences: preferences,
	}

	createdPreference, err := p.db.InsertUserPreference(ctx, preference)
	if err != nil {
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}

	return createdPreference, false, nil
}

// GetConfigLevel extracts the level from config data.
// Returns 0 if level is not found or invalid.
func GetConfigLevel(configData map[string]interface{}) int {
	level, ok := configData["level"]
	if !ok {
		return 0
	}

	// Convert to int (handle float64 from JSON, int, etc.)
	switch v := level.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		// Try to parse string as int
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
		return 0
	default:
		return 0
	}
}

// ShouldSendNotification checks if a notification should be sent based on global user preferences.
// Returns true if notification should be sent, false if it should be filtered out.
// If user has no preference row, returns true (allow all) — same as legacy behavior.
func (p *PreferenceService) ShouldSendNotification(ctx context.Context, userID uuid.UUID, notificationType string, configLevel int) (bool, error) {
	preference, err := p.db.GetUserPreference(ctx, userID)
	if err != nil {
		return true, nil
	}

	userLevelValue, ok := preference.Preferences[notificationType]
	if !ok {
		return true, nil
	}

	userLevel, err := preferenceLevelValue(userLevelValue, notificationType)
	if err != nil {
		return true, nil
	}

	return configLevel >= userLevel, nil
}

func preferenceLevelValue(userLevelValue interface{}, notificationType string) (int, error) {
	switch v := userLevelValue.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed, nil
		}
		if num, ok := PriorityLevelNames[v]; ok {
			return num, nil
		}
		return 0, errs.New("invalid preference level for %s", notificationType)
	default:
		return 0, errs.New("invalid preference level type for %s", notificationType)
	}
}
