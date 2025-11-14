// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package pushnotifications

import (
	"context"
	"fmt"
	"os"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"google.golang.org/api/option"

	"storj.io/common/uuid"
)

var (
	mon = monkit.Package()
)

// ErrService represents errors from the push notifications service.
var ErrService = errs.Class("pushnotifications")

// Config contains FCM configuration.
type Config struct {
	Enabled         bool   `help:"enable FCM push notifications" default:"false"`
	ProjectID       string `help:"Firebase project ID" default:""`
	CredentialsPath string `help:"path to Firebase service account credentials JSON" default:""`
	CredentialsJSON string `help:"Firebase credentials as JSON string (alternative to path)" default:""`
}

// Service handles FCM push notification operations.
type Service struct {
	log            *zap.Logger
	db             DB
	notificationDB PushNotificationDB
	client         *messaging.Client
	config         Config
	enabled        bool
}

// NewService creates a new FCM service.
func NewService(log *zap.Logger, db DB, notificationDB PushNotificationDB, config Config) (*Service, error) {
	service := &Service{
		log:            log,
		db:             db,
		notificationDB: notificationDB,
		config:         config,
		enabled:        config.Enabled,
	}

	if !config.Enabled {
		log.Info("FCM push notifications are disabled")
		return service, nil
	}

	// Initialize Firebase Admin SDK
	var opts []option.ClientOption

	if config.CredentialsPath != "" {
		// Load credentials from file
		opts = append(opts, option.WithCredentialsFile(config.CredentialsPath))
	} else if config.CredentialsJSON != "" {
		// Load credentials from JSON string
		opts = append(opts, option.WithCredentialsJSON([]byte(config.CredentialsJSON)))
	} else {
		// Try to use default credentials (e.g., from environment variable GOOGLE_APPLICATION_CREDENTIALS)
		// If GOOGLE_APPLICATION_CREDENTIALS is set, it will be used automatically
		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			return nil, ErrService.New("Firebase credentials not provided. Set GOOGLE_APPLICATION_CREDENTIALS environment variable, or provide credentials path or JSON in config")
		}
	}

	app, err := firebase.NewApp(context.Background(), &firebase.Config{
		ProjectID: config.ProjectID,
	}, opts...)
	if err != nil {
		return nil, ErrService.Wrap(fmt.Errorf("failed to initialize Firebase app: %w", err))
	}

	// Create FCM messaging client
	client, err := app.Messaging(context.Background())
	if err != nil {
		return nil, ErrService.Wrap(fmt.Errorf("failed to create FCM messaging client: %w", err))
	}

	service.client = client
	log.Info("FCM push notifications service initialized", zap.String("project_id", config.ProjectID))

	return service, nil
}

// SendNotification sends a push notification to a user.
// This is the main function that will be called to send notifications.
func (s *Service) SendNotification(ctx context.Context, userID uuid.UUID, notification Notification) (err error) {
	defer mon.Task()(&ctx)(&err)

	if !s.enabled {
		return ErrService.New("FCM push notifications are disabled")
	}

	// Retrieve all active FCM tokens for the user
	tokens, err := s.db.GetTokensByUserID(ctx, userID)
	if err != nil {
		return ErrService.Wrap(err)
	}

	if len(tokens) == 0 {
		s.log.Debug("No active FCM tokens found for user", zap.Stringer("user_id", userID))
		return nil
	}

	// Convert notification data to map[string]interface{} for storage
	dataMap := make(map[string]interface{})
	for k, v := range notification.Data {
		dataMap[k] = v
	}

	// Create notification records for tracking
	notificationRecords := make([]PushNotificationRecord, 0, len(tokens))
	for _, token := range tokens {
		recordID, err := uuid.New()
		if err != nil {
			return ErrService.Wrap(err)
		}

		record := PushNotificationRecord{
			ID:         recordID,
			UserID:     userID,
			TokenID:    &token.ID,
			Title:      notification.Title,
			Body:       notification.Body,
			Data:       dataMap,
			Status:     "pending",
			RetryCount: 0,
		}

		// Insert notification record
		createdRecord, err := s.notificationDB.InsertNotification(ctx, record)
		if err != nil {
			s.log.Warn("Failed to create notification record", zap.Error(err))
			continue
		}
		notificationRecords = append(notificationRecords, createdRecord)
	}

	// Send to all tokens
	var tokenStrings []string
	for _, token := range tokens {
		tokenStrings = append(tokenStrings, token.Token)
	}

	results, err := s.SendNotificationToMultipleTokens(ctx, tokenStrings, notification)
	if err != nil {
		// Update all records to failed status
		errorMsg := err.Error()
		for _, record := range notificationRecords {
			_ = s.notificationDB.UpdateNotificationStatus(ctx, record.ID, "failed", &errorMsg, nil)
		}
		return ErrService.Wrap(err)
	}

	// Handle results and update notification records
	now := time.Now()
	for i, result := range results {
		if i >= len(notificationRecords) {
			break
		}

		record := notificationRecords[i]
		if result.Error != nil {
			errorMsg := result.Error.Error()
			_ = s.notificationDB.UpdateNotificationStatus(ctx, record.ID, "failed", &errorMsg, nil)

			s.log.Warn("Failed to send notification to token",
				zap.String("token", tokenStrings[i]),
				zap.Error(result.Error))

			// Check if token is invalid and should be removed
			if messaging.IsInvalidArgument(result.Error) || messaging.IsRegistrationTokenNotRegistered(result.Error) {
				s.log.Info("Removing invalid FCM token", zap.String("token", tokenStrings[i]))
				if err := s.db.DeleteToken(ctx, tokens[i].ID); err != nil {
					s.log.Error("Failed to delete invalid token", zap.Error(err))
				}
			}
		} else {
			// Update to sent status
			_ = s.notificationDB.UpdateNotificationStatus(ctx, record.ID, "sent", nil, &now)
			s.log.Debug("Successfully sent notification to token", zap.String("token", tokenStrings[i]))
		}
	}

	return nil
}

// SendNotificationToToken sends a push notification to a specific token.
func (s *Service) SendNotificationToToken(ctx context.Context, token string, notification Notification) (err error) {
	defer mon.Task()(&ctx)(&err)

	if !s.enabled {
		return ErrService.New("FCM push notifications are disabled")
	}

	message := &messaging.Message{
		Token: token,
		Notification: &messaging.Notification{
			Title: notification.Title,
			Body:  notification.Body,
		},
		Data: make(map[string]string),
	}

	// Add custom data
	for k, v := range notification.Data {
		message.Data[k] = v
	}

	// Set priority
	if notification.Priority == "high" {
		message.Android = &messaging.AndroidConfig{
			Priority: "high",
		}
		message.APNS = &messaging.APNSConfig{
			Headers: map[string]string{
				"apns-priority": "10",
			},
		}
	}

	_, err = s.client.Send(ctx, message)
	if err != nil {
		return ErrService.Wrap(err)
	}

	return nil
}

// SendNotificationToMultipleTokens sends to multiple tokens (batch).
func (s *Service) SendNotificationToMultipleTokens(ctx context.Context, tokens []string, notification Notification) (_ []*messaging.SendResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	if !s.enabled {
		return nil, ErrService.New("FCM push notifications are disabled")
	}

	if len(tokens) == 0 {
		return []*messaging.SendResponse{}, nil
	}

	// Build multicast message
	message := &messaging.MulticastMessage{
		Tokens: tokens,
		Notification: &messaging.Notification{
			Title: notification.Title,
			Body:  notification.Body,
		},
		Data: make(map[string]string),
	}

	// Add custom data
	for k, v := range notification.Data {
		message.Data[k] = v
	}

	// Set priority
	if notification.Priority == "high" {
		message.Android = &messaging.AndroidConfig{
			Priority: "high",
		}
		message.APNS = &messaging.APNSConfig{
			Headers: map[string]string{
				"apns-priority": "10",
			},
		}
	}

	br, err := s.client.SendMulticast(ctx, message)
	if err != nil {
		return nil, ErrService.Wrap(err)
	}

	return br.Responses, nil
}
