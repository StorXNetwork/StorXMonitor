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
