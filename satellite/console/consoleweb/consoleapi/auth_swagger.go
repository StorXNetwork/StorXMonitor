// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// AuthTokenSwaggerRequest is the body for POST /api/v0/auth/token (email + password login).
type AuthTokenSwaggerRequest struct {
	Email              string `json:"email" example:"user@example.com"`
	Password           string `json:"password" example:"MySecurePass1!"`
	CaptchaResponse    string `json:"captchaResponse,omitempty" example:""`
	MFAPasscode        string `json:"mfaPasscode,omitempty" example:"123456"`
	MFARecoveryCode    string `json:"mfaRecoveryCode,omitempty" example:""`
	RememberForOneWeek bool   `json:"rememberForOneWeek,omitempty" example:"false"`
}

// AuthCredentialLoginSwaggerResponse is returned by POST /api/v0/auth/token on success.
// Same onboarding and google_backup shape as GET /auth/google-backup (action is always logged_in).
type AuthCredentialLoginSwaggerResponse struct {
	ExpiresAt    time.Time                     `json:"expiresAt"`
	Token        string                        `json:"token" example:"<session-token>"`
	Success      bool                          `json:"success" example:"true"`
	Action       string                        `json:"action" example:"logged_in" enums:"logged_in"`
	Onboarding   GoogleBackupOnboardingSwagger `json:"onboarding"`
	GoogleBackup map[string]interface{}        `json:"google_backup,omitempty" swaggertype:"object"`
}

// AuthForgotPasswordSwaggerRequest is the body for POST /api/v0/auth/forgot-password.
type AuthForgotPasswordSwaggerRequest struct {
	Email           string `json:"email" example:"user@example.com"`
	CaptchaResponse string `json:"captchaResponse" example:"<captcha-token>"`
}

// AuthResetPasswordSwaggerRequest is the body for POST /api/v0/auth/reset-password.
type AuthResetPasswordSwaggerRequest struct {
	Token           string `json:"token" example:"<recovery-token-from-email>"`
	Password        string `json:"password" example:"NewSecurePass1!"`
	MFAPasscode     string `json:"mfaPasscode,omitempty" example:"123456"`
	MFARecoveryCode string `json:"mfaRecoveryCode,omitempty" example:""`
}

// AuthResetPasswordMFARequiredResponse is returned when MFA is required during reset.
type AuthResetPasswordMFARequiredResponse struct {
	Error string `json:"error" example:"A MFA passcode or recovery code is required"`
	Code  string `json:"code" example:"mfa_required"`
}

// AuthResetPasswordErrorResponse is returned for expired token or too many attempts during reset.
type AuthResetPasswordErrorResponse struct {
	Error string `json:"error" example:"The recovery token has expired"`
	Code  string `json:"code" example:"token_expired" enums:"token_expired,too_many_attempts"`
}
