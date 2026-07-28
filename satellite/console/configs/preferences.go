// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	pgxerrcode "github.com/jackc/pgerrcode"
	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/shared/dbutil/pgutil/pgerrcode"
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

// GetUserPreferences retrieves all preferences for a user.
func (p *PreferenceService) GetUserPreferences(ctx context.Context, userID uuid.UUID) ([]UserNotificationPreference, error) {
	return p.db.GetUserPreferences(ctx, userID)
}

// GetUserPreferenceByCategory retrieves a category-level preference.
// If no preference exists yet, returns an empty default preference for the category.
func (p *PreferenceService) GetUserPreferenceByCategory(ctx context.Context, userID uuid.UUID, category string) (UserNotificationPreference, error) {
	pref, err := p.db.GetUserPreferenceByCategory(ctx, userID, category)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return UserNotificationPreference{
				UserID:      userID,
				Category:    category,
				Preferences: map[string]interface{}{},
			}, nil
		}
		return UserNotificationPreference{}, ErrPreferences.Wrap(err)
	}
	return pref, nil
}

// SetUserPreference creates or updates a user preference.
func (p *PreferenceService) SetUserPreference(ctx context.Context, request CreateUserPreferenceRequest) (UserNotificationPreference, error) {
	// Check if preference already exists
	pref, err := p.db.GetUserPreferenceByCategory(ctx, request.UserID, request.Category)
	if err == nil {
		update := UpdateUserPreferenceRequest{
			Preferences: &request.Preferences,
		}
		return p.db.UpdateUserPreference(ctx, pref.ID, update)
	}
	if !errs.Is(err, sql.ErrNoRows) {
		return UserNotificationPreference{}, ErrPreferences.Wrap(err)
	}

	// Create new preference
	preferenceID, err := uuid.New()
	if err != nil {
		return UserNotificationPreference{}, ErrPreferences.Wrap(err)
	}

	preference := UserNotificationPreference{
		ID:          preferenceID,
		UserID:      request.UserID,
		Category:    request.Category,
		Preferences: request.Preferences,
	}

	return p.db.InsertUserPreference(ctx, preference)
}

// UpdateUserPreference updates a user preference.
func (p *PreferenceService) UpdateUserPreference(ctx context.Context, id uuid.UUID, update UpdateUserPreferenceRequest) (UserNotificationPreference, error) {
	return p.db.UpdateUserPreference(ctx, id, update)
}

// UpsertUserPreference creates or updates a user preference.
// If a preference exists for the userID and category, it updates it.
// Otherwise, it creates a new preference.
// Returns the preference and a boolean indicating if it was an update (true) or create (false).
func (p *PreferenceService) UpsertUserPreference(ctx context.Context, userID uuid.UUID, category string, preferences map[string]interface{}) (UserNotificationPreference, bool, error) {
	pref, err := p.db.GetUserPreferenceByCategory(ctx, userID, category)
	if err == nil {
		return p.updateExistingPreference(ctx, pref.ID, category, preferences)
	}
	if !errs.Is(err, sql.ErrNoRows) {
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}

	// Category lookup missed — reuse an existing row when the DB only allows one
	// row per user (unique on user_id) or when category was previously NULL.
	existing, err := p.db.GetUserPreferences(ctx, userID)
	if err != nil {
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}
	if reusable := findReusablePreference(existing, category); reusable != nil {
		return p.updateExistingPreference(ctx, reusable.ID, category, preferences)
	}

	preferenceID, err := uuid.New()
	if err != nil {
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}

	createdPreference, err := p.db.InsertUserPreference(ctx, UserNotificationPreference{
		ID:          preferenceID,
		UserID:      userID,
		Category:    category,
		Preferences: preferences,
	})
	if err != nil {
		// Concurrent insert or unique(user_id): fall back to updating the existing row.
		if pgerrcode.FromError(err) == pgxerrcode.UniqueViolation ||
			strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			existing, listErr := p.db.GetUserPreferences(ctx, userID)
			if listErr != nil {
				return UserNotificationPreference{}, false, ErrPreferences.Wrap(listErr)
			}
			if reusable := findReusablePreference(existing, category); reusable != nil {
				return p.updateExistingPreference(ctx, reusable.ID, category, preferences)
			}
			if len(existing) > 0 {
				return p.updateExistingPreference(ctx, existing[0].ID, category, preferences)
			}
		}
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}

	return createdPreference, false, nil
}

func (p *PreferenceService) updateExistingPreference(ctx context.Context, id uuid.UUID, category string, preferences map[string]interface{}) (UserNotificationPreference, bool, error) {
	categoryCopy := category
	update := UpdateUserPreferenceRequest{
		Category:    &categoryCopy,
		Preferences: &preferences,
	}
	preference, err := p.db.UpdateUserPreference(ctx, id, update)
	if err != nil {
		return UserNotificationPreference{}, false, ErrPreferences.Wrap(err)
	}
	return preference, true, nil
}

// findReusablePreference picks an existing row to update when inserting a new
// category row is not possible or the prior row had a null/empty category.
func findReusablePreference(existing []UserNotificationPreference, category string) *UserNotificationPreference {
	for i := range existing {
		if existing[i].Category == category || existing[i].Category == "" {
			return &existing[i]
		}
	}
	// Legacy schema with UNIQUE(user_id): only one row can exist for the user.
	if len(existing) == 1 {
		return &existing[0]
	}
	return nil
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

// ShouldSendNotification checks if a notification should be sent based on user preferences.
// Returns true if notification should be sent, false if it should be filtered out.
// If user has no preference, returns true (default allow).
func (p *PreferenceService) ShouldSendNotification(ctx context.Context, userID uuid.UUID, category string, notificationType string, configLevel int) (bool, error) {
	// Get user preference for category
	preference, err := p.db.GetUserPreferenceByCategory(ctx, userID, category)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			// If no preference exists, allow by default
			return true, nil
		}
		return false, ErrPreferences.Wrap(err)
	}

	// Check if user has preference for notificationType (push/email/sms)
	userLevelValue, ok := preference.Preferences[notificationType]
	if !ok {
		// If no preference for this notification type, allow by default
		return true, nil
	}

	// Convert user preference level to int
	var userLevel int
	switch v := userLevelValue.(type) {
	case int:
		userLevel = v
	case int64:
		userLevel = int(v)
	case float64:
		userLevel = int(v)
	case string:
		// Try to parse string as int
		if parsed, err := strconv.Atoi(v); err == nil {
			userLevel = parsed
		} else {
			// If parsing fails, allow by default
			return true, nil
		}
	default:
		// If type is unknown, allow by default
		return true, nil
	}

	// Compare configLevel with user preference level
	// Return true if configLevel >= user preference level
	// (user wants notifications at level userLevel or higher)
	return configLevel >= userLevel, nil
}
