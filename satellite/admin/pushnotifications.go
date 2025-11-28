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
func (server *Server) sendPushNotificationWithPreferences(ctx context.Context, userID uuid.UUID, category string, notification pushnotifications.Notification) error {
	if server.consoleService != nil {
		return server.consoleService.SendPushNotificationWithPreferences(ctx, userID, category, notification)
	}

	// Check user preferences and configs
	shouldSend, err := server.checkNotificationPreferences(ctx, userID, category)
	if err != nil || !shouldSend {
		return err
	}

	// Send notification if enabled
	if server.console.PushNotifications.Enabled {
		pushService, err := server.createPushNotificationService()
		if err != nil {
			server.log.Warn("Failed to create push notification service, skipping notification",
				zap.Stringer("user_id", userID),
				zap.Error(err))
			return nil
		}
		return pushService.SendNotification(ctx, userID, notification)
	}

	return nil
}

func (server *Server) sendPushNotificationByEventName(ctx context.Context, userID uuid.UUID, eventName string, category string, variables map[string]interface{}) error {
	if server.consoleService != nil {
		return server.consoleService.SendPushNotificationByEventName(ctx, userID, eventName, category, variables)
	}

	configName := strings.ReplaceAll(eventName, "_", " ")
	templateData, configData, err := server.getTemplateData(ctx, eventName, configName, userID)
	if err != nil {
		return err
	}

	mergedVars := configs.MergeUserPreferences(templateData.DefaultVariables, nil, variables)
	server.handleSpecialVariables(mergedVars)

	if err := configs.ValidateVariables(templateData, mergedVars); err != nil {
		server.log.Warn("Failed to validate template variables",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}

	title, body, _, err := configs.NewRenderer().RenderTemplate(templateData, mergedVars)
	if err != nil {
		server.log.Warn("Failed to render push notification template",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return err
	}

	notification := pushnotifications.Notification{
		Title:    title,
		Body:     body,
		Data:     server.buildNotificationData(eventName, mergedVars),
		Priority: mapLevelToPriority(configs.GetConfigLevel(configData)), // Use configData here
	}

	return server.sendPushNotificationWithPreferences(ctx, userID, category, notification)
}

// sendNotificationAsync sends a push notification asynchronously.
func (server *Server) sendNotificationAsync(userID uuid.UUID, email string, eventName string, category string, variables map[string]interface{}) {
	go func() {
		notifyCtx := context.Background()
		eventDescription := strings.ReplaceAll(eventName, "_", " ")

		if err := server.sendPushNotificationByEventName(notifyCtx, userID, eventName, category, variables); err != nil {
			server.log.Warn("Failed to send push notification",
				zap.String("event", eventName),
				zap.String("description", eventDescription),
				zap.Stringer("user_id", userID),
				zap.String("email", email),
				zap.Error(err))
		} else {
		}
	}()
}

// checkNotificationPreferences checks if notification should be sent based on user preferences.
func (server *Server) checkNotificationPreferences(ctx context.Context, userID uuid.UUID, category string) (bool, error) {
	configsDB := server.db.Console().Configs()
	configsService := configs.NewService(configsDB)

	pushConfigType := configs.ConfigTypeNotificationTemplate
	filters := configs.ListConfigFilters{
		ConfigType: &pushConfigType,
		Category:   &category,
	}

	configsList, err := configsService.ListConfigs(ctx, filters)
	if err != nil {
		return true, nil // Default to sending on error
	}

	// Find active push config
	var pushConfig *configs.Config
	for i := range configsList {
		if configsList[i].IsActive && configsList[i].ConfigType == pushConfigType {
			pushConfig = &configsList[i]
			break
		}
	}

	if pushConfig == nil {
		return true, nil // No config found, send by default
	}

	// Check user preferences
	preferenceService := configs.NewPreferenceService(server.db.Console().UserNotificationPreferences())
	shouldSend, err := preferenceService.ShouldSendNotification(ctx, userID, category, string(configs.NotificationTypePush), configs.GetConfigLevel(pushConfig.ConfigData))
	if err != nil {
		return true, nil // Default to sending on error
	}

	return shouldSend, nil
}

// getTemplateData retrieves and parses template data for a notification event.
func (server *Server) getTemplateData(ctx context.Context, eventName, configName string, userID uuid.UUID) (configs.TemplateData, map[string]interface{}, error) {
	var templateData configs.TemplateData

	config, err := configs.NewService(server.db.Console().Configs()).GetConfigByName(ctx, configs.ConfigTypeNotificationTemplate, configName)
	if err != nil {
		server.log.Warn("Failed to get push notification config by name",
			zap.String("event_name", eventName),
			zap.String("config_name", configName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return templateData, nil, err
	}

	configDataJSON, err := json.Marshal(config.ConfigData)
	if err != nil {
		server.log.Warn("Failed to marshal config data",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return templateData, nil, err
	}

	if err := json.Unmarshal(configDataJSON, &templateData); err != nil {
		server.log.Warn("Failed to parse template data",
			zap.String("event_name", eventName),
			zap.Stringer("user_id", userID),
			zap.Error(err))
		return templateData, nil, err
	}

	return templateData, config.ConfigData, nil
}

// createPushNotificationService creates a new push notification service.
func (server *Server) createPushNotificationService() (*pushnotifications.Service, error) {
	return pushnotifications.NewService(
		server.log.Named("pushnotifications"),
		server.db.Console().FCMTokens(),
		server.db.Console().PushNotifications(),
		server.console.PushNotifications,
	)
}

// handleSpecialVariables processes special variable values like "now" timestamp.
func (server *Server) handleSpecialVariables(variables map[string]interface{}) {
	if timestamp, ok := variables["timestamp"]; ok {
		if tsStr, ok := timestamp.(string); ok && tsStr == "now" {
			variables["timestamp"] = time.Now().Format(time.RFC3339)
		}
	}
}

// buildNotificationData builds the data map for the notification.
func (server *Server) buildNotificationData(eventName string, variables map[string]interface{}) map[string]string {
	data := make(map[string]string)
	data["event"] = eventName
	for k, v := range variables {
		if v != nil {
			data[k] = fmt.Sprintf("%v", v)
		}
	}
	return data
}

// mapLevelToPriority maps config level to priority string.
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
		return "normal"
	}
}
