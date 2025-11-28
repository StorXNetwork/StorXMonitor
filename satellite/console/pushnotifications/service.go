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
}

// NewService creates a new FCM service.
func NewService(log *zap.Logger, db DB, notificationDB PushNotificationDB, config Config) (*Service, error) {
	if !config.Enabled {
		log.Info("FCM push notifications are disabled")
		return &Service{log: log, db: db, notificationDB: notificationDB, config: config}, nil
	}

	opts, err := createFirebaseOptions(config)
	if err != nil {
		return nil, ErrService.Wrap(err)
	}

	app, err := firebase.NewApp(context.Background(), &firebase.Config{
		ProjectID: config.ProjectID,
	}, opts...)
	if err != nil {
		return nil, ErrService.Wrap(fmt.Errorf("failed to initialize Firebase app: %w", err))
	}

	client, err := app.Messaging(context.Background())
	if err != nil {
		return nil, ErrService.Wrap(fmt.Errorf("failed to create FCM messaging client: %w", err))
	}

	log.Info("FCM push notifications service initialized", zap.String("project_id", config.ProjectID))
	return &Service{log: log, db: db, notificationDB: notificationDB, client: client, config: config}, nil
}

// createFirebaseOptions creates Firebase client options based on config.
func createFirebaseOptions(config Config) ([]option.ClientOption, error) {
	switch {
	case config.CredentialsPath != "":
		return []option.ClientOption{option.WithCredentialsFile(config.CredentialsPath)}, nil
	case config.CredentialsJSON != "":
		return []option.ClientOption{option.WithCredentialsJSON([]byte(config.CredentialsJSON))}, nil
	case os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "":
		return []option.ClientOption{}, nil // Use default credentials
	default:
		return nil, ErrService.New("Firebase credentials not provided")
	}
}

// SendNotification sends a push notification to a user.
func (s *Service) SendNotification(ctx context.Context, userID uuid.UUID, notification Notification) (err error) {
	defer mon.Task()(&ctx)(&err)

	if !s.config.Enabled {
		return ErrService.New("FCM push notifications are disabled")
	}

	tokens, err := s.db.GetTokensByUserID(ctx, userID)
	if err != nil {
		return ErrService.Wrap(err)
	}

	if len(tokens) == 0 {
		s.log.Warn("No active FCM tokens found for user", zap.Stringer("user_id", userID))
		return nil
	}

	s.log.Info("Found FCM tokens for user",
		zap.Stringer("user_id", userID),
		zap.Int("token_count", len(tokens)),
		zap.Strings("token_previews", s.getTokenPreviews(tokens)))

	// Create notification records
	records, err := s.createNotificationRecords(ctx, userID, tokens, notification)
	if err != nil {
		return ErrService.Wrap(err)
	}

	// Send notifications
	tokenStrings := s.extractTokenStrings(tokens)
	results, err := s.SendNotificationToMultipleTokens(ctx, tokenStrings, notification)
	if err != nil {
		s.updateRecordsStatus(ctx, records, "failed", err.Error())
		return ErrService.Wrap(err)
	}

	// Process results
	s.processSendResults(ctx, records, tokenStrings, tokens, results)
	return nil
}

// SendNotificationToToken sends a push notification to a specific token.
func (s *Service) SendNotificationToToken(ctx context.Context, token string, notification Notification) error {
	if !s.config.Enabled {
		return ErrService.New("FCM push notifications are disabled")
	}

	message := s.buildMessage(token, notification)
	_, err := s.client.Send(ctx, message)
	return ErrService.Wrap(err)
}

// SendNotificationToMultipleTokens sends to multiple tokens.
func (s *Service) SendNotificationToMultipleTokens(ctx context.Context, tokens []string, notification Notification) ([]*messaging.SendResponse, error) {
	if !s.config.Enabled {
		return nil, ErrService.New("FCM push notifications are disabled")
	}

	responses := make([]*messaging.SendResponse, 0, len(tokens))
	for _, token := range tokens {
		message := s.buildMessage(token, notification)
		msgID, err := s.client.Send(ctx, message)

		response := &messaging.SendResponse{
			Success: err == nil,
			Error:   err,
		}
		if err == nil {
			response.MessageID = msgID
		} else {
			s.log.Warn("Failed to send notification", zap.String("token", token), zap.Error(err))
		}
		responses = append(responses, response)
	}

	return responses, nil
}

// Helper methods

func (s *Service) getTokenPreviews(tokens []FCMToken) []string {
	previews := make([]string, len(tokens))
	for i, t := range tokens {
		if len(t.Token) > 20 {
			previews[i] = t.Token[:20] + "..."
		} else {
			previews[i] = t.Token
		}
	}
	return previews
}

func (s *Service) createNotificationRecords(ctx context.Context, userID uuid.UUID, tokens []FCMToken, notification Notification) ([]PushNotificationRecord, error) {
	records := make([]PushNotificationRecord, 0, len(tokens))
	dataMap := s.convertDataToMap(notification.Data)

	for _, token := range tokens {
		recordID, err := uuid.New()
		if err != nil {
			return nil, err
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

		createdRecord, err := s.notificationDB.InsertNotification(ctx, record)
		if err != nil {
			s.log.Warn("Failed to create notification record", zap.Error(err))
			continue
		}
		records = append(records, createdRecord)
	}
	return records, nil
}

func (s *Service) extractTokenStrings(tokens []FCMToken) []string {
	tokenStrings := make([]string, len(tokens))
	for i, token := range tokens {
		tokenStrings[i] = token.Token
	}
	return tokenStrings
}

func (s *Service) updateRecordsStatus(ctx context.Context, records []PushNotificationRecord, status, errorMsg string) {
	for _, record := range records {
		_ = s.notificationDB.UpdateNotificationStatus(ctx, record.ID, status, &errorMsg, nil)
	}
}

func (s *Service) processSendResults(ctx context.Context, records []PushNotificationRecord, tokenStrings []string, tokens []FCMToken, results []*messaging.SendResponse) {
	now := time.Now()
	for i, result := range results {
		if i >= len(records) {
			break
		}

		record := records[i]
		if result.Error != nil {
			errorMsg := result.Error.Error()
			_ = s.notificationDB.UpdateNotificationStatus(ctx, record.ID, "failed", &errorMsg, nil)
			s.handleFailedToken(ctx, tokenStrings[i], tokens[i], result.Error)
		} else {
			_ = s.notificationDB.UpdateNotificationStatus(ctx, record.ID, "sent", nil, &now)
		}
	}
}

func (s *Service) handleFailedToken(ctx context.Context, token string, fcmToken FCMToken, sendErr error) {
	s.log.Warn("Failed to send notification", zap.String("token", token), zap.Error(sendErr))

	if messaging.IsInvalidArgument(sendErr) || messaging.IsRegistrationTokenNotRegistered(sendErr) {
		s.log.Info("Removing invalid FCM token", zap.String("token", token))
		if err := s.db.DeleteToken(ctx, fcmToken.ID); err != nil {
			s.log.Error("Failed to delete invalid token", zap.Error(err))
		}
	}
}

func (s *Service) buildMessage(token string, notification Notification) *messaging.Message {
	message := &messaging.Message{
		Token: token,
		Notification: &messaging.Notification{
			Title: notification.Title,
			Body:  notification.Body,
		},
		Data: notification.Data, // Direct assignment since both are map[string]string
	}

	if notification.Priority == "high" {
		message.Android = &messaging.AndroidConfig{Priority: "high"}
		message.APNS = &messaging.APNSConfig{
			Headers: map[string]string{"apns-priority": "10"},
		}
	}

	return message
}

func (s *Service) convertDataToMap(data map[string]string) map[string]interface{} {
	dataMap := make(map[string]interface{})
	for k, v := range data {
		dataMap[k] = v
	}
	return dataMap
}
