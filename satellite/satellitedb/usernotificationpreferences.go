// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console/configs"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that userNotificationPreferencesDB implements configs.UserPreferenceDB.
var _ configs.UserPreferenceDB = (*userNotificationPreferencesDB)(nil)

// ErrUserNotificationPreferences represents errors from the user_notification_preferences database.
var ErrUserNotificationPreferences = errs.Class("usernotificationpreferences")

type userNotificationPreferencesDB struct {
	db *satelliteDB
}

// InsertUserPreference creates a new user preference.
func (u *userNotificationPreferencesDB) InsertUserPreference(ctx context.Context, preference configs.UserNotificationPreference) (_ configs.UserNotificationPreference, err error) {
	defer mon.Task()(&ctx)(&err)

	preferencesJSON, err := json.Marshal(preference.Preferences)
	if err != nil {
		return preference, ErrUserNotificationPreferences.Wrap(err)
	}

	optional := dbx.UserNotificationPreference_Create_Fields{
		Category: dbx.UserNotificationPreference_Category(preference.Category),
	}

	dbxPreference, err := u.db.Create_UserNotificationPreference(ctx,
		dbx.UserNotificationPreference_Id(preference.ID[:]),
		dbx.UserNotificationPreference_UserId(preference.UserID[:]),
		dbx.UserNotificationPreference_Preferences(preferencesJSON),
		dbx.UserNotificationPreference_UpdatedAt(time.Now()),
		optional)
	if err != nil {
		return preference, ErrUserNotificationPreferences.Wrap(err)
	}

	return userPreferenceFromDBX(dbxPreference)
}

// GetUserPreferenceByID retrieves a preference by ID.
func (u *userNotificationPreferencesDB) GetUserPreferenceByID(ctx context.Context, id uuid.UUID) (_ configs.UserNotificationPreference, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxPreference, err := u.db.Get_UserNotificationPreference_By_Id(ctx,
		dbx.UserNotificationPreference_Id(id[:]))
	if err != nil {
		return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
	}

	return userPreferenceFromDBX(dbxPreference)
}

// GetUserPreferences retrieves all preferences for a user.
func (u *userNotificationPreferencesDB) GetUserPreferences(ctx context.Context, userID uuid.UUID) (_ []configs.UserNotificationPreference, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxPreferences, err := u.db.All_UserNotificationPreference_By_UserId(ctx,
		dbx.UserNotificationPreference_UserId(userID[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return []configs.UserNotificationPreference{}, nil
		}
		return nil, ErrUserNotificationPreferences.Wrap(err)
	}

	result := make([]configs.UserNotificationPreference, 0, len(dbxPreferences))
	for _, dbxPreference := range dbxPreferences {
		preference, err := userPreferenceFromDBX(dbxPreference)
		if err != nil {
			return nil, ErrUserNotificationPreferences.Wrap(err)
		}
		result = append(result, preference)
	}

	return result, nil
}

// GetUserPreferenceByCategory retrieves a category-level preference.
func (u *userNotificationPreferencesDB) GetUserPreferenceByCategory(ctx context.Context, userID uuid.UUID, category string) (_ configs.UserNotificationPreference, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxPreference, err := u.db.Get_UserNotificationPreference_By_UserId_And_Category(ctx,
		dbx.UserNotificationPreference_UserId(userID[:]),
		dbx.UserNotificationPreference_Category(category))
	if err != nil {
		return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
	}

	return userPreferenceFromDBX(dbxPreference)
}

// UpdateUserPreference updates a user preference.
func (u *userNotificationPreferencesDB) UpdateUserPreference(ctx context.Context, id uuid.UUID, update configs.UpdateUserPreferenceRequest) (_ configs.UserNotificationPreference, err error) {
	defer mon.Task()(&ctx)(&err)

	var updateFields dbx.UserNotificationPreference_Update_Fields

	if update.Preferences != nil {
		preferencesJSON, err := json.Marshal(*update.Preferences)
		if err != nil {
			return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
		}
		updateFields.Preferences = dbx.UserNotificationPreference_Preferences(preferencesJSON)
	}

	updateFields.UpdatedAt = dbx.UserNotificationPreference_UpdatedAt(time.Now())

	dbxPreference, err := u.db.Update_UserNotificationPreference_By_Id(ctx,
		dbx.UserNotificationPreference_Id(id[:]),
		updateFields)
	if err != nil {
		return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
	}

	return userPreferenceFromDBX(dbxPreference)
}

// userPreferenceFromDBX converts a dbx.UserNotificationPreference to configs.UserNotificationPreference.
func userPreferenceFromDBX(dbxPreference *dbx.UserNotificationPreference) (configs.UserNotificationPreference, error) {
	id, err := uuid.FromBytes(dbxPreference.Id)
	if err != nil {
		return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
	}

	userID, err := uuid.FromBytes(dbxPreference.UserId)
	if err != nil {
		return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
	}

	var preferences map[string]interface{}
	if dbxPreference.Preferences != nil {
		if err := json.Unmarshal(dbxPreference.Preferences, &preferences); err != nil {
			return configs.UserNotificationPreference{}, ErrUserNotificationPreferences.Wrap(err)
		}
	}

	preference := configs.UserNotificationPreference{
		ID:          id,
		UserID:      userID,
		Category:    *dbxPreference.Category,
		Preferences: preferences,
		CreatedAt:   dbxPreference.CreatedAt,
		UpdatedAt:   dbxPreference.UpdatedAt,
	}

	return preference, nil

}
