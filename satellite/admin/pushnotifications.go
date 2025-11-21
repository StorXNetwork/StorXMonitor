// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console/configs"
	"storj.io/storj/satellite/console/pushnotifications"
)

// sendPushNotificationWithPreferences sends a push notification after checking user preferences.
// This is a helper function for admin handlers that don't have access to console.Service.
func (server *Server) sendPushNotificationWithPreferences(ctx context.Context, userID uuid.UUID, category string, notification pushnotifications.Notification) error {
	// If console service is available, use it
	if server.consoleService != nil {
		return server.consoleService.SendPushNotificationWithPreferences(ctx, userID, category, notification)
	}

	// Otherwise, use database directly
	configsDB := server.db.Console().Configs()
	configsService := configs.NewService(configsDB)

	// Filter to find config with ConfigType == ConfigTypeNotificationTemplate (which is "push")
	pushConfigType := configs.ConfigTypeNotificationTemplate
	filters := configs.ListConfigFilters{
		ConfigType: &pushConfigType,
		Category:   &category,
	}

	configsList, err := configsService.ListConfigs(ctx, filters)
	if err != nil {
		// If we can't get configs, allow notification by default (send without validation)
		server.log.Debug("Failed to get push notification configs, sending notification by default",
			zap.Stringer("user_id", userID),
			zap.String("category", category),
			zap.Error(err))
		// Continue to send notification below
	} else {
		// Find the first active push config for this category
		var pushConfig *configs.Config
		for i := range configsList {
			if configsList[i].IsActive && configsList[i].ConfigType == pushConfigType {
				pushConfig = &configsList[i]
				break
			}
		}

		// If push config found, check user preferences
		if pushConfig != nil {
			// Extract level from ConfigData
			configLevel := configs.GetConfigLevel(pushConfig.ConfigData)

			// Check preferences using ShouldSendNotification
			// Note: ShouldSendNotification returns true by default if user has no preference
			preferenceDB := server.db.Console().UserNotificationPreferences()
			preferenceService := configs.NewPreferenceService(preferenceDB)

			shouldSend, err := preferenceService.ShouldSendNotification(ctx, userID, category, string(configs.NotificationTypePush), configLevel)
			if err != nil {
				// If we can't check preferences, allow notification by default (send without validation)
				server.log.Debug("Failed to check user notification preferences, sending notification by default",
					zap.Stringer("user_id", userID),
					zap.String("category", category),
					zap.Error(err))
				// Continue to send notification below
			} else if !shouldSend {
				// User has preference and it indicates we should not send
				return nil
			}
			// If shouldSend is true (including when user has no preference), continue to send notification
		}
		// If no push config found, allow notification by default (send without validation)
	}

	// Create push notification service if not already created
	// We need to create it on-demand since admin peer doesn't have it initialized
	if server.console.PushNotifications.Enabled {
		pushNotificationService, err := pushnotifications.NewService(
			server.log.Named("pushnotifications"),
			server.db.Console().FCMTokens(),
			server.db.Console().PushNotifications(),
			server.console.PushNotifications,
		)
		if err != nil {
			server.log.Warn("Failed to create push notification service, skipping notification",
				zap.Stringer("user_id", userID),
				zap.Error(err))
			return nil
		}

		// Send notification
		return pushNotificationService.SendNotification(ctx, userID, notification)
	}

	// Push notifications are disabled
	return nil
}

// sendPushNotificationByEventName sends a push notification by fetching config by event name,
// rendering templates from config_data, and sending the notification.
// Variables can be nil - defaults from config_data will be used. Runtime variables override defaults.
func (server *Server) sendPushNotificationByEventName(ctx context.Context, userID uuid.UUID, eventName string, category string, variables map[string]interface{}) error {
	// If console service is available, use it
	if server.consoleService != nil {
		return server.consoleService.SendPushNotificationByEventName(ctx, userID, eventName, category, variables)
	}

	// Otherwise, use database directly
	// Convert event name (e.g., "account_frozen") to config name (e.g., "account frozen")
	configName := strings.ReplaceAll(eventName, "_", " ")

	// Get configs service
	configsDB := server.db.Console().Configs()
	configsService := configs.NewService(configsDB)

	// Get config by name
	pushConfigType := configs.ConfigTypeNotificationTemplate
	config, err := configsService.GetConfigByName(ctx, pushConfigType, configName)
	if err != nil {
		// If config not found, log warning and return (don't send notification)
		server.log.Warn("Failed to get push notification config by name",
			zap.String("event_name", eventName),
			zap.String("config_name", configName),
			zap.String("category", category),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}

	// Parse template data from config
	var templateData configs.TemplateData
	configDataJSON, err := json.Marshal(config.ConfigData)
	if err != nil {
		server.log.Warn("Failed to marshal config data",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}
	if err := json.Unmarshal(configDataJSON, &templateData); err != nil {
		server.log.Warn("Failed to parse template data",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}

	// Merge default variables with runtime variables (runtime variables override defaults)
	mergedVars := configs.MergeUserPreferences(templateData.DefaultVariables, nil, variables)

	// Handle special "now" timestamp
	if timestamp, ok := mergedVars["timestamp"]; ok {
		if tsStr, ok := timestamp.(string); ok && tsStr == "now" {
			mergedVars["timestamp"] = time.Now().Format(time.RFC3339)
		}
	}

	// Validate required variables
	if err := configs.ValidateVariables(templateData, mergedVars); err != nil {
		server.log.Warn("Failed to validate template variables",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}

	// Render templates
	renderer := configs.NewRenderer()
	title, body, _, err := renderer.RenderTemplate(templateData, mergedVars)
	if err != nil {
		server.log.Warn("Failed to render push notification template",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}

	// Extract level from config_data and map to priority
	configLevel := configs.GetConfigLevel(config.ConfigData)
	priority := mapLevelToPriority(configLevel)

	// Build data map - include event name and all variables as strings
	data := make(map[string]string)
	data["event"] = eventName
	for k, v := range mergedVars {
		if v != nil {
			data[k] = fmt.Sprintf("%v", v)
		}
	}

	// Build notification
	notification := pushnotifications.Notification{
		Title:    title,
		Body:     body,
		Data:     data,
		Priority: priority,
	}

	// Send notification with preferences check
	return server.sendPushNotificationWithPreferences(ctx, userID, category, notification)
}

// mapLevelToPriority maps config level (1-4) to priority string.
// Level 1 = marketing, 2 = info, 3 = warning, 4 = critical
func mapLevelToPriority(level int) string {
	switch level {
	case 1:
		return "marketing"
	case 2:
		return "info"
	case 3:
		return "warning"
	case 4:
		return "critical"
	default:
		// Default to "normal" for unknown levels
		return "normal"
	}
}
