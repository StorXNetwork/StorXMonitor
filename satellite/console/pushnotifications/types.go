// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package pushnotifications

import (
	"time"

	"storj.io/common/uuid"
)

// FCMToken represents an FCM token stored in the database.
type FCMToken struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Token       string
	DeviceID    *string
	DeviceType  *string
	AppVersion  *string
	OSVersion   *string
	DeviceModel *string
	BrowserName *string
	UserAgent   *string
	IPAddress   *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastUsedAt  *time.Time
	IsActive    bool
}

// UpdateTokenRequest contains fields that can be updated for an FCM token.
type UpdateTokenRequest struct {
	Token       *string
	DeviceID    *string
	DeviceType  *string
	AppVersion  *string
	OSVersion   *string
	DeviceModel *string
	BrowserName *string
	UserAgent   *string
	IsActive    *bool
}

// Notification represents a push notification to be sent.
type Notification struct {
	Title    string
	Body     string
	Data     map[string]string
	ImageURL string
	Priority string // "normal" or "high"
}

// PushNotificationRecord represents a push notification record stored in the database.
type PushNotificationRecord struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TokenID      *uuid.UUID
	Title        string
	Body         string
	Data         map[string]interface{}
	Status       string // "pending", "sent", "failed"
	ErrorMessage *string
	RetryCount   int
	SentAt       *time.Time
	CreatedAt    time.Time
}
