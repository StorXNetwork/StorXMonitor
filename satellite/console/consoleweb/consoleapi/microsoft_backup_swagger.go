// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// MicrosoftBackupOnboardingSwagger is the onboarding block on GET /auth/microsoft-backup responses.
type MicrosoftBackupOnboardingSwagger struct {
	OnboardingStart  bool   `json:"onboardingStart" example:"true"`
	OnboardingEnd    bool   `json:"onboardingEnd" example:"false"`
	OnboardingStep   string `json:"onboardingStep" example:"MicrosoftBackupPending"`
	OnboardingStatus string `json:"onboarding_status" example:"pending" enums:"pending,in_progress,completed"`
}

// MicrosoftBackupAuthSuccess is returned from GET /auth/microsoft-backup on success.
type MicrosoftBackupAuthSuccess struct {
	Success         bool                             `json:"success" example:"true"`
	Action          string                           `json:"action" example:"logged_in" enums:"registered,logged_in"`
	Token           string                           `json:"token" example:"..."`
	Onboarding      MicrosoftBackupOnboardingSwagger `json:"onboarding"`
	MicrosoftBackup map[string]interface{}           `json:"microsoft_backup,omitempty" swaggertype:"object"`
}

// MicrosoftBackupAuthError is returned when GET /auth/microsoft-backup fails.
type MicrosoftBackupAuthError struct {
	Success bool   `json:"success" example:"false"`
	Error   string `json:"error" example:"Error getting token from Microsoft!"`
}

// MicrosoftBackupConnectSwaggerRequest is the body for POST /microsoft-backup/connect.
type MicrosoftBackupConnectSwaggerRequest struct {
	Code string `json:"code" example:"0.AXo..."`
}

// MicrosoftBackupConnectSwaggerResponse is returned after connecting Microsoft for backup.
type MicrosoftBackupConnectSwaggerResponse struct {
	Success         bool                   `json:"success" example:"true"`
	MicrosoftEmail  string                 `json:"microsoft_email" example:"user@contoso.com"`
	Created         bool                   `json:"created" example:"true"`
	HasRefreshToken bool                   `json:"has_refresh_token" example:"true"`
	MicrosoftBackup map[string]interface{} `json:"microsoft_backup,omitempty" swaggertype:"object"`
}

// MicrosoftBackupDomainUsersSwaggerResponse is returned from GET /microsoft-backup/domain-users.
type MicrosoftBackupDomainUsersSwaggerResponse struct {
	MicrosoftBackup map[string]interface{} `json:"microsoft_backup,omitempty" swaggertype:"object"`
}
