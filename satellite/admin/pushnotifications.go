// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"

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
