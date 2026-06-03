// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// AuthAccountSwaggerResponse is returned by GET /api/v0/auth/account.
type AuthAccountSwaggerResponse struct {
	ID                    string     `json:"id" example:"00000000-0000-0000-0000-000000000000"`
	FullName              string     `json:"fullName" example:"Jane Doe"`
	ShortName             string     `json:"shortName" example:"Jane"`
	Email                 string     `json:"email" example:"user@example.com"`
	Partner               string     `json:"partner" example:""`
	ProjectLimit          int        `json:"projectLimit" example:"10"`
	ProjectStorageLimit   int64      `json:"projectStorageLimit" example:"0"`
	ProjectBandwidthLimit int64      `json:"projectBandwidthLimit" example:"0"`
	ProjectSegmentLimit   int64      `json:"projectSegmentLimit" example:"0"`
	IsProfessional        bool       `json:"isProfessional" example:"false"`
	Position              string     `json:"position" example:""`
	CompanyName           string     `json:"companyName" example:""`
	EmployeeCount         string     `json:"employeeCount" example:""`
	HaveSalesContact      bool       `json:"haveSalesContact" example:"false"`
	PaidTier              bool       `json:"paidTier" example:"false"`
	IsMFAEnabled          bool       `json:"isMFAEnabled" example:"false"`
	MFARecoveryCodeCount  int        `json:"mfaRecoveryCodeCount" example:"0"`
	CreatedAt             time.Time  `json:"createdAt"`
	PendingVerification   bool       `json:"pendingVerification" example:"false"`
	TrialExpiration       *time.Time `json:"trialExpiration"`
	HasVarPartner         bool       `json:"hasVarPartner" example:"false"`
	LoginToken            string     `json:"loginToken" example:""`
	SocialLinkedin        string     `json:"socialLinkedin" example:""`
	SocialTwitter         string     `json:"socialTwitter" example:""`
	SocialFacebook        string     `json:"socialFacebook" example:""`
	SocialGithub          string     `json:"socialGithub" example:""`
	WalletID              string     `json:"walletId" example:""`
}

// UpdateAuthAccountSwaggerRequest is the body for PATCH /api/v0/auth/account.
type UpdateAuthAccountSwaggerRequest struct {
	FullName  string `json:"fullName" example:"Jane Doe"`
	ShortName string `json:"shortName" example:"Jane"`
}

// UpdateAuthAccountInfoSwaggerRequest is the body for PATCH /api/v0/auth/account/info.
type UpdateAuthAccountInfoSwaggerRequest struct {
	SocialLinkedin *string `json:"socialLinkedin,omitempty" example:"https://linkedin.com/in/jane"`
	SocialTwitter  *string `json:"socialTwitter,omitempty" example:"@jane"`
	SocialFacebook *string `json:"socialFacebook,omitempty"`
	SocialGithub   *string `json:"socialGithub,omitempty" example:"jane"`
	WalletID       *string `json:"walletId,omitempty" example:"0xabc"`
}

// AuthAccountFreezeStatusSwaggerResponse is returned by GET /api/v0/auth/account/freezestatus.
type AuthAccountFreezeStatusSwaggerResponse struct {
	Frozen             bool `json:"frozen" example:"false"`
	Warned             bool `json:"warned" example:"false"`
	ViolationFrozen    bool `json:"violationFrozen" example:"false"`
	TrialExpiredFrozen bool `json:"trialExpiredFrozen" example:"false"`
}

// AuthUserSettingsSwaggerResponse is returned by GET /api/v0/auth/account/settings.
type AuthUserSettingsSwaggerResponse struct {
	SessionDuration  *int64                 `json:"sessionDuration" example:"3600"`
	OnboardingStart  bool                   `json:"onboardingStart" example:"true"`
	OnboardingEnd    bool                   `json:"onboardingEnd" example:"false"`
	PassphrasePrompt bool                   `json:"passphrasePrompt" example:"true"`
	OnboardingStep   *string                `json:"onboardingStep" example:"welcome"`
	NoticeDismissal  map[string]interface{} `json:"noticeDismissal" swaggertype:"object"`
}

// SetAuthUserSettingsSwaggerRequest is the body for PATCH /api/v0/auth/account/settings.
type SetAuthUserSettingsSwaggerRequest struct {
	OnboardingStart  *bool                  `json:"onboardingStart,omitempty" example:"true"`
	OnboardingEnd    *bool                  `json:"onboardingEnd,omitempty" example:"false"`
	PassphrasePrompt *bool                  `json:"passphrasePrompt,omitempty" example:"true"`
	OnboardingStep   *string                `json:"onboardingStep,omitempty" example:"welcome"`
	SessionDuration  *int64                 `json:"sessionDuration,omitempty" example:"3600"`
	NoticeDismissal  map[string]interface{} `json:"noticeDismissal,omitempty" swaggertype:"object"`
}

// SetAuthOnboardingStatusSwaggerRequest is the body for PATCH /api/v0/auth/account/onboarding.
type SetAuthOnboardingStatusSwaggerRequest struct {
	OnboardingStart *bool   `json:"onboardingStart,omitempty" example:"true"`
	OnboardingEnd   *bool   `json:"onboardingEnd,omitempty" example:"false"`
	OnboardingStep  *string `json:"onboardingStep,omitempty" example:"welcome"`
}

// DeleteAuthAccountSwaggerRequest is the body for DELETE /api/v0/auth/account (admin flow).
type DeleteAuthAccountSwaggerRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"admin-verification-password"`
}

// PaymentPlansSwaggerResponse is returned by GET /payment-plans (server root, not under /api/v0).
type PaymentPlansSwaggerResponse struct {
	CryptoModes []string                   `json:"crypto_modes" example:"SRX,XDC,USDT"`
	Group       []PaymentPlanGroupSwagger  `json:"group"`
}

// PaymentPlanGroupSwagger groups plans by billing group name.
type PaymentPlanGroupSwagger struct {
	Name  string        `json:"name" example:"monthly"`
	Plans []interface{} `json:"plans" swaggertype:"array,object"`
}

// MFAEnableSwaggerRequest is the body for POST /api/v0/auth/mfa/enable.
type MFAEnableSwaggerRequest struct {
	Passcode string `json:"passcode" example:"123456"`
}

// MFADisableSwaggerRequest is the body for POST /api/v0/auth/mfa/disable.
type MFADisableSwaggerRequest struct {
	Passcode     string `json:"passcode" example:"123456"`
	RecoveryCode string `json:"recoveryCode" example:""`
}

// MFARegenerateRecoveryCodesSwaggerRequest is the body for POST /api/v0/auth/mfa/regenerate-recovery-codes.
type MFARegenerateRecoveryCodesSwaggerRequest struct {
	Passcode     string `json:"passcode" example:"123456"`
	RecoveryCode string `json:"recoveryCode" example:""`
}

// UserDeveloperAccessSwaggerItem is one OAuth developer with access to the user account.
type UserDeveloperAccessSwaggerItem struct {
	DeveloperID            string     `json:"developer_id" example:"00000000-0000-0000-0000-000000000000"`
	DeveloperName          string     `json:"developer_name" example:"Acme App"`
	DeveloperEmail         string     `json:"developer_email" example:"dev@example.com"`
	ClientID               string     `json:"client_id" example:"client-id"`
	ApplicationName        string     `json:"application_name" example:"My Integration"`
	ApplicationDescription string     `json:"application_description" example:"Backup integration"`
	ApprovedScopes         []string   `json:"approved_scopes" example:"read,write"`
	RejectedScopes         []string   `json:"rejected_scopes"`
	AccessGrantedDate      time.Time  `json:"access_granted_date"`
	LastAccessDate         *time.Time `json:"last_access_date"`
	ConsentExpiresAt       *time.Time `json:"consent_expires_at"`
	IsActive               bool       `json:"is_active" example:"true"`
	TotalRequests          int        `json:"total_requests" example:"12"`
}

// UserDeveloperAccessHistorySwaggerItem is one history row for developer access.
type UserDeveloperAccessHistorySwaggerItem struct {
	RequestID       string    `json:"request_id" example:"00000000-0000-0000-0000-000000000000"`
	ClientID        string    `json:"client_id" example:"client-id"`
	ApplicationName string    `json:"application_name" example:"My Integration"`
	Scopes          []string  `json:"scopes" example:"read"`
	Status          int       `json:"status" example:"1"`
	CreatedAt       time.Time `json:"created_at"`
}

// UserNotificationPreferenceSwagger is a notification preference row.
type UserNotificationPreferenceSwagger struct {
	ID          string                 `json:"ID" example:"00000000-0000-0000-0000-000000000000"`
	UserID      string                 `json:"UserID" example:"00000000-0000-0000-0000-000000000000"`
	Category    string                 `json:"Category" example:"billing"`
	Preferences map[string]interface{} `json:"Preferences" swaggertype:"object"`
	CreatedAt   time.Time              `json:"CreatedAt"`
	UpdatedAt   time.Time              `json:"UpdatedAt"`
}

// UpsertUserNotificationPreferenceSwaggerRequest is the body for PUT /api/v0/user/notification-preferences.
type UpsertUserNotificationPreferenceSwaggerRequest struct {
	Category    string                 `json:"category" example:"billing"`
	Preferences map[string]interface{} `json:"preferences" swaggertype:"object"`
}

// FCMTokenSwaggerResponse is an FCM device token record.
type FCMTokenSwaggerResponse struct {
	ID          string     `json:"ID" example:"00000000-0000-0000-0000-000000000000"`
	UserID      string     `json:"UserID" example:"00000000-0000-0000-0000-000000000000"`
	Token       string     `json:"Token" example:"fcm-device-token"`
	DeviceID    *string    `json:"DeviceID"`
	DeviceType  *string    `json:"DeviceType" example:"web"`
	AppVersion  *string    `json:"AppVersion"`
	OSVersion   *string    `json:"OSVersion"`
	DeviceModel *string    `json:"DeviceModel"`
	BrowserName *string    `json:"BrowserName"`
	UserAgent   *string    `json:"UserAgent"`
	IPAddress   *string    `json:"IPAddress"`
	CreatedAt   time.Time  `json:"CreatedAt"`
	UpdatedAt   time.Time  `json:"UpdatedAt"`
	LastUsedAt  *time.Time `json:"LastUsedAt"`
	IsActive    bool       `json:"IsActive" example:"true"`
}
