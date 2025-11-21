<!-- dc4d1cb7-c9b8-4714-a5df-f03952426f9e b2864c68-9231-46d4-8b3e-a5415c24d105 -->
# Remove APIs and Update Database Schema

## Overview

This plan removes three user-facing API endpoint groups and updates the database schema:

1. Make `created_by` nullable in `configs` table
2. Remove `config_id` column from `user_notification_preferences` table
3. Remove Configs API endpoints and controller
4. Remove Notification Templates API endpoints and controller
5. Remove User Notification Preferences API endpoints and controller

## Database Migrations

### Migration 1: Make `created_by` nullable in `configs` table

- **File**: `satellite/satellitedb/migrate.go`
- **Action**: Add new migration (version 295) to alter `configs.created_by` column from `NOT NULL` to nullable
- **SQL**: `ALTER TABLE configs ALTER COLUMN created_by DROP NOT NULL;`

### Migration 2: Remove `config_id` from `user_notification_preferences` table

- **File**: `satellite/satellitedb/migrate.go`
- **Action**: Add migration step to:

  1. Drop index `user_notification_preferences_user_config_index`
  2. Drop column `config_id` from `user_notification_preferences` table

- **SQL**: 
  ```sql
  DROP INDEX IF EXISTS user_notification_preferences_user_config_index;
  ALTER TABLE user_notification_preferences DROP COLUMN config_id;
  ```


## Remove API Endpoints

### Remove Configs API

- **File**: `satellite/console/consoleweb/server.go` (lines 493-502)
- **Action**: Remove the entire Configs API router setup including:
  - Controller initialization
  - Router creation
  - All 4 route handlers (ListConfigs, GetConfig, GetConfigByTypeAndName, ListConfigsByType)
- **File**: `satellite/console/consoleweb/consoleapi/configs.go`
- **Action**: Delete entire file

### Remove Notification Templates API

- **File**: `satellite/console/consoleweb/server.go` (lines 504-512)
- **Action**: Remove the entire Notification Templates API router setup including:
  - Controller initialization
  - Router creation
  - All 3 route handlers (ListTemplates, GetTemplate, GetTemplateByName)
- **File**: `satellite/console/consoleweb/consoleapi/notificationtemplates.go`
- **Action**: Delete entire file

### Remove User Notification Preferences API

- **File**: `satellite/console/consoleweb/server.go` (lines 514-526)
- **Action**: Remove the entire User Notification Preferences API router setup including:
  - Controller initialization
  - Router creation
  - All 7 route handlers (GetUserPreferences, SetUserPreference, GetUserPreferencesByType, GetUserPreferenceByConfig, GetUserPreferenceByCategory, UpdateUserPreference, DeleteUserPreference)
- **File**: `satellite/console/consoleweb/consoleapi/usernotificationpreferences.go`
- **Action**: Delete entire file

## Update Code to Remove `config_id` References

### Update Type Definitions

- **File**: `satellite/console/configs/types.go`
- **Action**: 
  - Remove `ConfigID *uuid.UUID` field from `UserNotificationPreference` struct (line 58)
  - Remove `ConfigID *uuid.UUID` field from `CreateUserPreferenceRequest` struct (line 88)

### Update Database Interface

- **File**: `satellite/console/configs/db.go`
- **Action**: Remove `GetUserPreferenceByConfig` method from `UserPreferenceDB` interface (line 50-51)

### Update Preference Service

- **File**: `satellite/console/configs/preferences.go`
- **Action**: 
  - Remove `GetUserPreferenceByConfig` method (lines 41-44)
  - Update `SetUserPreference` method to remove `config_id` check (lines 62-66), only keep category check

### Update Database Implementation

- **File**: `satellite/satellitedb/usernotificationpreferences.go`
- **Action**:
  - Remove `GetUserPreferenceByConfig` method (lines 134-146)
  - Update `InsertUserPreference` to remove `ConfigID` handling (lines 39-41)
  - Update `userPreferenceFromDBX` to remove `ConfigID` assignment (lines 251-257)

### Update Template Service

- **File**: `satellite/console/configs/templates.go`
- **Action**: Update `RenderTemplate` method to remove `GetUserPreferenceByConfig` call (lines 86-92). Since `config_id` is removed, user preferences lookup by config is no longer possible. Remove this logic entirely or replace with category-based lookup if needed.

## Update Code to Handle Nullable `created_by`

### Update Type Definitions

- **File**: `satellite/console/configs/types.go`
- **Action**: 
  - Change `CreatedBy uuid.UUID` to `CreatedBy *uuid.UUID` in `Config` struct (line 38)
  - Change `CreatedBy uuid.UUID` to `CreatedBy *uuid.UUID` in `CreateConfigRequest` struct (line 74)

### Update Database Implementation

- **File**: `satellite/satellitedb/configs.go`
- **Action**: 
  - Update `InsertConfig` to handle nullable `CreatedBy` (line 52) - make it optional in dbx call
  - Update `configFromDBX` to handle nullable `CreatedBy` field from database

## Files to Delete

1. `satellite/console/consoleweb/consoleapi/configs.go`
2. `satellite/console/consoleweb/consoleapi/notificationtemplates.go`
3. `satellite/console/consoleweb/consoleapi/usernotificationpreferences.go`

## Files to Modify

1. `satellite/satellitedb/migrate.go` - Add migrations
2. `satellite/console/consoleweb/server.go` - Remove API route registrations
3. `satellite/console/configs/types.go` - Update structs
4. `satellite/console/configs/db.go` - Remove interface method
5. `satellite/console/configs/preferences.go` - Remove method and update logic
6. `satellite/satellitedb/usernotificationpreferences.go` - Remove method and update logic
7. `satellite/console/configs/templates.go` - Update RenderTemplate
8. `satellite/satellitedb/configs.go` - Handle nullable created_by

### To-dos

- [ ] Create push_notification_webhook.go file with PushNotificationWebhook struct and SendNotificationByType handler method
- [ ] Add GetPushNotificationService() getter method in service.go to expose pushNotificationService
- [ ] Register push notification webhook controller and route in server.go
- [ ] Add migration to make created_by nullable in configs table
- [ ] Add migration to remove config_id column and index from user_notification_preferences table
- [ ] Remove Configs API endpoints from server.go and delete configs.go controller file
- [ ] Remove Notification Templates API endpoints from server.go and delete notificationtemplates.go controller file
- [ ] Remove User Notification Preferences API endpoints from server.go and delete usernotificationpreferences.go controller file
- [ ] Remove ConfigID field from UserNotificationPreference and CreateUserPreferenceRequest structs
- [ ] Remove GetUserPreferenceByConfig from UserPreferenceDB interface
- [ ] Remove GetUserPreferenceByConfig method and update SetUserPreference to remove config_id logic
- [ ] Remove GetUserPreferenceByConfig method and all config_id handling from usernotificationpreferences.go
- [ ] Remove GetUserPreferenceByConfig call from RenderTemplate method
- [ ] Make CreatedBy nullable in Config and CreateConfigRequest structs
- [ ] Update configs.go to handle nullable CreatedBy field