// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package pushnotifications

import (
	"context"
	"time"

	"storj.io/common/uuid"
)

// DB defines database operations for FCM tokens.
type DB interface {
	// InsertToken inserts a new FCM token for a user.
	InsertToken(ctx context.Context, token FCMToken) (FCMToken, error)

	// GetTokensByUserID retrieves all active tokens for a user.
	GetTokensByUserID(ctx context.Context, userID uuid.UUID) ([]FCMToken, error)

	// GetTokenByID retrieves a token by ID.
	GetTokenByID(ctx context.Context, tokenID uuid.UUID) (FCMToken, error)

	// GetTokenByToken retrieves a token by token string.
	GetTokenByToken(ctx context.Context, token string) (FCMToken, error)

	// UpdateToken updates an existing token.
	UpdateToken(ctx context.Context, tokenID uuid.UUID, update UpdateTokenRequest) error

	// DeleteToken deletes a token (soft delete by setting is_active = false).
	DeleteToken(ctx context.Context, tokenID uuid.UUID) error

	// DeleteTokensByUserID deletes all tokens for a user.
	DeleteTokensByUserID(ctx context.Context, userID uuid.UUID) error
}

// NotificationPage represents a paginated page of notifications.
type NotificationPage struct {
	Notifications []PushNotificationRecord
	TotalCount    int
	Limit         int
	Page          int
	PageCount     int
}

// PushNotificationDB defines database operations for push notification tracking.
type PushNotificationDB interface {
	// InsertNotification inserts a new push notification record.
	InsertNotification(ctx context.Context, notification PushNotificationRecord) (PushNotificationRecord, error)

	// UpdateNotificationStatus updates the status of a notification.
	UpdateNotificationStatus(ctx context.Context, id uuid.UUID, status string, errorMsg *string, sentAt *time.Time) error

	// IncrementRetryCount increments the retry count for a notification.
	IncrementRetryCount(ctx context.Context, id uuid.UUID) error

	// GetNotificationsByUserID retrieves all notifications for a user.
	GetNotificationsByUserID(ctx context.Context, userID uuid.UUID) ([]PushNotificationRecord, error)

	// GetNotificationByID retrieves a notification by ID.
	GetNotificationByID(ctx context.Context, id uuid.UUID) (PushNotificationRecord, error)

	// ListNotifications retrieves paginated notifications for a user with optional filter.
	ListNotifications(ctx context.Context, userID uuid.UUID, limit, page int, filter NotificationFilter) (*NotificationPage, error)

	// MarkNotificationAsRead marks a single notification as read (updates status to "read").
	MarkNotificationAsRead(ctx context.Context, notificationID, userID uuid.UUID) error

	// MarkAllNotificationsAsRead marks all unread notifications for a user as read (updates status to "read").
	MarkAllNotificationsAsRead(ctx context.Context, userID uuid.UUID) error

	// GetUnreadCount returns the count of unread notifications for a user.
	GetUnreadCount(ctx context.Context, userID uuid.UUID) (int, error)
}
