// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// NotificationChannelPreferencesSwagger is global per-channel minimum priority.
// Keys: push, email, sms. Values: 1=marketing, 2=info, 3=warning, 4=critical (or string names).
type NotificationChannelPreferencesSwagger struct {
	Push  *int `json:"push,omitempty" example:"2" enums:"1,2,3,4"`
	Email *int `json:"email,omitempty" example:"2" enums:"1,2,3,4"`
	SMS   *int `json:"sms,omitempty" example:"4" enums:"1,2,3,4"`
}

// UserNotificationPreferenceSwagger is a global notification preference row (Settings → Notifications).
type UserNotificationPreferenceSwagger struct {
	ID          string                 `json:"ID" example:"00000000-0000-0000-0000-000000000000"`
	UserID      string                 `json:"UserID" example:"00000000-0000-0000-0000-000000000000"`
	Preferences map[string]interface{} `json:"Preferences" swaggertype:"object"`
	CreatedAt   time.Time              `json:"CreatedAt"`
	UpdatedAt   time.Time              `json:"UpdatedAt"`
}

// UpsertUserNotificationPreferenceSwaggerRequest is the body for PUT /api/v0/user/notification-preferences.
type UpsertUserNotificationPreferenceSwaggerRequest struct {
	Preferences NotificationChannelPreferencesSwagger `json:"preferences"`
}

// FCMTokenSwaggerResponse is an FCM device token record (Settings → Push devices).
type FCMTokenSwaggerResponse struct {
	ID          string     `json:"ID" example:"00000000-0000-0000-0000-000000000000"`
	UserID      string     `json:"UserID" example:"00000000-0000-0000-0000-000000000000"`
	Token       string     `json:"Token" example:"fcm-device-token"`
	DeviceID    *string    `json:"DeviceID" example:"device-uuid-123"`
	DeviceType  *string    `json:"DeviceType" example:"web" enums:"android,ios,web"`
	AppVersion  *string    `json:"AppVersion" example:"1.2.0"`
	OSVersion   *string    `json:"OSVersion" example:"14.0"`
	DeviceModel *string    `json:"DeviceModel" example:"Pixel 8"`
	BrowserName *string    `json:"BrowserName" example:"Chrome"`
	UserAgent   *string    `json:"UserAgent" example:"Mozilla/5.0 ..."`
	IPAddress   *string    `json:"IPAddress" example:"203.0.113.10"`
	CreatedAt   time.Time  `json:"CreatedAt"`
	UpdatedAt   time.Time  `json:"UpdatedAt"`
	LastUsedAt  *time.Time `json:"LastUsedAt"`
	IsActive    bool       `json:"IsActive" example:"true"`
}

// RegisterFCMTokenSwaggerRequest is the body for POST /api/v0/fcm-token.
type RegisterFCMTokenSwaggerRequest struct {
	Token       string  `json:"token" example:"fcm-device-token-string" binding:"required"`
	DeviceID    *string `json:"deviceId" example:"device-uuid-123"`
	DeviceType  *string `json:"deviceType" example:"web" enums:"android,ios,web"`
	AppVersion  *string `json:"appVersion" example:"1.2.0"`
	OSVersion   *string `json:"osVersion" example:"14.0"`
	DeviceModel *string `json:"deviceModel" example:"Pixel 8"`
	BrowserName *string `json:"browserName" example:"Chrome"`
	UserAgent   *string `json:"userAgent" example:"Mozilla/5.0 ..."`
}

// UpdateFCMTokenSwaggerRequest is the body for PUT /api/v0/fcm-token/{tokenId}.
type UpdateFCMTokenSwaggerRequest struct {
	Token       *string `json:"token" example:"fcm-device-token-string"`
	DeviceID    *string `json:"deviceId" example:"device-uuid-123"`
	DeviceType  *string `json:"deviceType" example:"web" enums:"android,ios,web"`
	AppVersion  *string `json:"appVersion" example:"1.2.0"`
	OSVersion   *string `json:"osVersion" example:"14.0"`
	DeviceModel *string `json:"deviceModel" example:"Pixel 8"`
	BrowserName *string `json:"browserName" example:"Chrome"`
	UserAgent   *string `json:"userAgent" example:"Mozilla/5.0 ..."`
	IsActive    *bool   `json:"isActive" example:"true"`
}

// SettingsMessageSwaggerResponse is a simple success message for settings mutations.
type SettingsMessageSwaggerResponse struct {
	Message string `json:"message" example:"token updated successfully"`
}
