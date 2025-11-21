// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
)

// ConfigType represents the type of configuration.
type ConfigType string

const (
	// ConfigTypeNotificationTemplate represents notification templates.
	ConfigTypeNotificationTemplate ConfigType = "push"
	// ConfigTypeEmailTemplate represents email templates.
	ConfigTypeEmailTemplate ConfigType = "email"
	// ConfigTypePushTemplate represents push notification templates.
	ConfigTypePushTemplate ConfigType = "sms"
)

// PreferenceCategory represents the category for user notification preferences.
type PreferenceCategory string

const (
	// PreferenceCategoryBilling represents billing-related notifications.
	PreferenceCategoryBilling PreferenceCategory = "billing"
	// PreferenceCategoryBackup represents backup-related notifications.
	PreferenceCategoryBackup PreferenceCategory = "backup"
	// PreferenceCategoryAccount represents account-related notifications.
	PreferenceCategoryAccount PreferenceCategory = "account"
	// PreferenceCategoryVault represents vault-related notifications.
	PreferenceCategoryVault PreferenceCategory = "vault"
)

// ValidPreferenceCategories contains all valid preference categories.
var ValidPreferenceCategories = map[string]bool{
	string(PreferenceCategoryBilling): true,
	string(PreferenceCategoryBackup):  true,
	string(PreferenceCategoryAccount): true,
	string(PreferenceCategoryVault):   true,
}

// IsValidPreferenceCategory checks if a category string is valid.
func IsValidPreferenceCategory(category string) bool {
	return ValidPreferenceCategories[category]
}

// NotificationType represents the type of notification channel.
type NotificationType string

const (
	// NotificationTypePush represents push notifications.
	NotificationTypePush NotificationType = "push"
	// NotificationTypeEmail represents email notifications.
	NotificationTypeEmail NotificationType = "email"
	// NotificationTypeSMS represents SMS notifications.
	NotificationTypeSMS NotificationType = "sms"
)

// ValidNotificationTypes contains all valid notification types.
var ValidNotificationTypes = map[string]bool{
	string(NotificationTypePush):  true,
	string(NotificationTypeEmail): true,
	string(NotificationTypeSMS):   true,
}

// PriorityLevel represents the priority level for notifications.
type PriorityLevel int

const (
	// PriorityMarketing represents marketing notifications (priority 1).
	PriorityMarketing PriorityLevel = 1
	// PriorityInfo represents informational notifications (priority 2).
	PriorityInfo PriorityLevel = 2
	// PriorityWarning represents warning notifications (priority 3).
	PriorityWarning PriorityLevel = 3
	// PriorityCritical represents critical notifications (priority 4).
	PriorityCritical PriorityLevel = 4
)

// PriorityLevelNames maps priority level names to numbers.
var PriorityLevelNames = map[string]int{
	"marketing": int(PriorityMarketing),
	"info":      int(PriorityInfo),
	"warning":   int(PriorityWarning),
	"critical":  int(PriorityCritical),
}

// ValidPriorityLevels contains all valid priority level numbers.
var ValidPriorityLevels = map[int]bool{
	int(PriorityMarketing): true,
	int(PriorityInfo):      true,
	int(PriorityWarning):   true,
	int(PriorityCritical):  true,
}

// ValidateAndNormalizePreferences validates and normalizes user preferences.
// Only allows keys: push, email, sms
// Values must be numbers 1-4 (marketing=1, info=2, warning=3, critical=4)
// Converts string priority names to numbers if provided.
func ValidateAndNormalizePreferences(preferences map[string]interface{}) (map[string]interface{}, error) {
	normalized := make(map[string]interface{})

	for key, value := range preferences {
		// Only allow valid notification types
		if !ValidNotificationTypes[key] {
			return nil, errs.New("invalid preference key: %s. Valid keys are: push, email, sms", key)
		}

		// Convert value to number
		var priorityNum int
		switch v := value.(type) {
		case int:
			priorityNum = v
		case int64:
			priorityNum = int(v)
		case float64:
			priorityNum = int(v)
		case string:
			// Try to convert string priority name to number
			if num, ok := PriorityLevelNames[v]; ok {
				priorityNum = num
			} else {
				return nil, errs.New("invalid priority value for %s: %s. Valid values are: 1-4 or marketing, info, warning, critical", key, v)
			}
		default:
			return nil, errs.New("invalid priority value type for %s. Must be a number (1-4) or string (marketing, info, warning, critical)", key)
		}

		// Validate priority number is 1-4
		if !ValidPriorityLevels[priorityNum] {
			return nil, errs.New("invalid priority number for %s: %d. Valid values are: 1 (marketing), 2 (info), 3 (warning), 4 (critical)", key, priorityNum)
		}

		normalized[key] = priorityNum
	}

	return normalized, nil
}

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
// Preferences map should only contain keys: push, email, sms
// Values should be numbers 1-4 representing priority levels:
//
//	1 = marketing, 2 = info, 3 = warning, 4 = critical
type UserNotificationPreference struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Category    string                 // Required category: billing, backup, account, or vault
	Preferences map[string]interface{} // Keys: push, email, sms. Values: 1-4 (marketing, info, warning, critical)
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
	UserID      uuid.UUID
	Category    string
	Preferences map[string]interface{}
}

// UpdateUserPreferenceRequest represents a request to update user preferences.
type UpdateUserPreferenceRequest struct {
	Preferences *map[string]interface{}
}
