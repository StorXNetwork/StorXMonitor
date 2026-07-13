// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

// Swagger models for seller / reseller routes (used by swag only).

// SellerStatusSwaggerResponse is returned from GET /seller/status.
type SellerStatusSwaggerResponse struct {
	Service string `json:"service" example:"seller"`
	Status  string `json:"status" example:"ok"`
}

// SellerResellerSwagger is the reseller object on seller auth responses.
type SellerResellerSwagger struct {
	ID    string `json:"id" example:"00000000-0000-0000-0000-000000000001"`
	Email string `json:"email" example:"reseller@example.com"`
	Name  string `json:"name" example:"Acme Reseller"`
}

// SellerGoogleAuthSuccess is returned from GET /seller/auth/google on success.
type SellerGoogleAuthSuccess struct {
	Success  bool                  `json:"success" example:"true"`
	Action   string                `json:"action" example:"registered" enums:"registered,logged_in"`
	Token    string                `json:"token" example:"<session token>"`
	Reseller SellerResellerSwagger `json:"reseller"`
}

// SellerGoogleAuthError is returned when GET /seller/auth/google fails.
type SellerGoogleAuthError struct {
	Success bool   `json:"success" example:"false"`
	Error   string `json:"error" example:"Error getting token from Google!"`
}

// SellerAuthErrorResponse is returned when a protected seller route rejects the session.
type SellerAuthErrorResponse struct {
	Error string `json:"error" example:"authorization failed"`
}

// SellerAuthTokenSwaggerRequest is the body for POST /seller/auth/token.
type SellerAuthTokenSwaggerRequest struct {
	Email              string `json:"email" example:"reseller@example.com"`
	Password           string `json:"password" example:"securePassword123"`
	CaptchaResponse    string `json:"captchaResponse" example:""`
	RememberForOneWeek bool   `json:"rememberForOneWeek" example:"false"`
	MFAPasscode        string `json:"mfaPasscode" example:""`
	MFARecoveryCode    string `json:"mfaRecoveryCode" example:""`
}

// SellerAuthTokenSwaggerResponse is returned from login and activation routes.
type SellerAuthTokenSwaggerResponse struct {
	Token     string `json:"token" example:"<session token>"`
	ExpiresAt string `json:"expiresAt" example:"2026-07-08T12:00:00Z"`
}

// SellerRegisterSwaggerRequest is the body for POST /seller/auth/register.
type SellerRegisterSwaggerRequest struct {
	FullName        string `json:"fullName" example:"Acme Reseller"`
	Email           string `json:"email" example:"reseller@example.com"`
	Password        string `json:"password" example:"securePassword123"`
	CompanyName     string `json:"companyName" example:"Acme Inc"`
	CaptchaResponse string `json:"captchaResponse" example:""`
}

// SellerForgotPasswordSwaggerRequest is the body for POST /seller/auth/forgot-password.
type SellerForgotPasswordSwaggerRequest struct {
	Email           string `json:"email" example:"reseller@example.com"`
	CaptchaResponse string `json:"captchaResponse" example:""`
}

// SellerResetPasswordSwaggerRequest is the body for POST /seller/auth/reset-password.
type SellerResetPasswordSwaggerRequest struct {
	Token           string `json:"token" example:"<recovery token from email>"`
	Password        string `json:"password" example:"newSecurePassword123"`
	MFAPasscode     string `json:"mfaPasscode" example:""`
	MFARecoveryCode string `json:"mfaRecoveryCode" example:""`
}

// SellerActivateAccountSwaggerRequest is the body for PATCH /seller/auth/code-activation.
type SellerActivateAccountSwaggerRequest struct {
	Email    string `json:"email" example:"reseller@example.com"`
	Code     string `json:"code" example:"123456"`
	SignupID string `json:"signupId" example:""`
}

// SellerResendEmailSwaggerRequest is the body for POST /seller/auth/resend-email.
type SellerResendEmailSwaggerRequest struct {
	Email string `json:"email" example:"reseller@example.com"`
}

// SellerAccountSwaggerResponse is returned from GET /seller/auth/account.
type SellerAccountSwaggerResponse struct {
	ID                   string  `json:"id" example:"00000000-0000-0000-0000-000000000001"`
	Email                string  `json:"email" example:"reseller@example.com"`
	Name                 string  `json:"name" example:"Acme Reseller"`
	CompanyName          *string `json:"companyName" example:"Acme Inc"`
	HasPassword          bool    `json:"hasPassword" example:"true"`
	Status               int     `json:"status" example:"1"`
	IsMFAEnabled         bool    `json:"isMFAEnabled" example:"false"`
	MFARecoveryCodeCount int     `json:"mfaRecoveryCodeCount" example:"0"`
}

// SellerChangePasswordSwaggerRequest is the body for POST /seller/auth/account/change-password.
type SellerChangePasswordSwaggerRequest struct {
	Password    string `json:"password" example:"currentPassword123"`
	NewPassword string `json:"newPassword" example:"newSecurePassword123"`
}

// SellerSetPasswordSwaggerRequest is the body for POST /seller/auth/account/set-password.
type SellerSetPasswordSwaggerRequest struct {
	NewPassword string `json:"newPassword" example:"newSecurePassword123"`
}

// SellerMFAEnableSwaggerRequest is the body for POST /seller/auth/mfa/enable.
type SellerMFAEnableSwaggerRequest struct {
	Passcode string `json:"passcode" example:"123456"`
}

// SellerMFADisableSwaggerRequest is the body for POST /seller/auth/mfa/disable.
type SellerMFADisableSwaggerRequest struct {
	Passcode     string `json:"passcode" example:"123456"`
	RecoveryCode string `json:"recoveryCode" example:""`
}

// SellerMFARegenerateRecoveryCodesSwaggerRequest is the body for POST /seller/auth/mfa/regenerate-recovery-codes.
type SellerMFARegenerateRecoveryCodesSwaggerRequest struct {
	Passcode     string `json:"passcode" example:"123456"`
	RecoveryCode string `json:"recoveryCode" example:""`
}

// SellerAccountActionSwaggerRequest is the body for POST /seller/auth/change-email.
type SellerAccountActionSwaggerRequest struct {
	Step int    `json:"step" example:"1"`
	Data string `json:"data" example:"currentPassword123"`
}

// SellerDeleteAccountSwaggerRequest is the body for DELETE /seller/auth/account.
type SellerDeleteAccountSwaggerRequest struct {
	Email    string `json:"email" example:"reseller@example.com"`
	Password string `json:"password" example:"admin-verification-password"`
}

// SellerWebappSessionSwagger is one active reseller webapp session.
type SellerWebappSessionSwagger struct {
	ID                        string `json:"id" example:"00000000-0000-0000-0000-000000000001"`
	ResellerID                string `json:"resellerId" example:"00000000-0000-0000-0000-000000000002"`
	IP                        string `json:"ip" example:"203.0.113.1"`
	Status                    int    `json:"status" example:"1"`
	ExpiresAt                 string `json:"expiresAt" example:"2026-07-08T12:00:00Z"`
	IsRequesterCurrentSession bool   `json:"isRequesterCurrentSession" example:"true"`
}

// SellerWebappSessionsPageSwagger is returned from GET /seller/auth/sessions.
type SellerWebappSessionsPageSwagger struct {
	Sessions         []SellerWebappSessionSwagger `json:"sessions"`
	Limit            uint                         `json:"limit" example:"10"`
	Order            int8                         `json:"order" example:"0"`
	OrderDirection   uint8                        `json:"orderDirection" example:"0"`
	Offset           uint64                       `json:"offset" example:"0"`
	PageCount        uint                         `json:"pageCount" example:"1"`
	CurrentPage      uint                         `json:"currentPage" example:"1"`
	TotalCount       uint64                       `json:"totalCount" example:"1"`
}

// SellerFrontendConfigSwagger is returned from GET /seller/config.
type SellerFrontendConfigSwagger struct {
	ExternalAddress               string `json:"externalAddress" example:"http://localhost:9081"`
	ApiBaseURL                    string `json:"apiBaseURL" example:"http://localhost:9081"`
	SatelliteName                 string `json:"satelliteName" example:"Storj"`
	CSRFProtectionEnabled         bool   `json:"csrfProtectionEnabled" example:"false"`
	CSRFToken                     string `json:"csrfToken" example:""`
	SignupActivationCodeEnabled   bool   `json:"signupActivationCodeEnabled" example:"false"`
	PasswordMinimumLength         int    `json:"passwordMinimumLength" example:"8"`
	PasswordMaximumLength         int    `json:"passwordMaximumLength" example:"64"`
	InactivityTimerEnabled        bool   `json:"inactivityTimerEnabled" example:"true"`
	InactivityTimerDuration       int    `json:"inactivityTimerDuration" example:"1800"`
	EmailChangeFlowEnabled        bool   `json:"emailChangeFlowEnabled" example:"false"`
	SelfServeAccountDeleteEnabled bool   `json:"selfServeAccountDeleteEnabled" example:"false"`
	ActiveSessionsViewEnabled     bool   `json:"activeSessionsViewEnabled" example:"false"`
	LiveCheckBadPasswords         bool   `json:"liveCheckBadPasswords" example:"false"`
}
