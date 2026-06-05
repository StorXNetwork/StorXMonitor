// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const (
	// OnboardingStatusPending — registered, Google backup onboarding not finished.
	OnboardingStatusPending = "pending"
	// OnboardingStatusInProgress — user started backup onboarding (service selection, connect, etc.).
	OnboardingStatusInProgress = "in_progress"
	// OnboardingStatusCompleted — backup jobs created / onboarding_end is true.
	OnboardingStatusCompleted = "completed"

	// OnboardingStepGoogleBackupPending is set at register-google.
	OnboardingStepGoogleBackupPending = "GoogleBackupPending"
	// OnboardingStepGoogleBackupCompleted is set when auto-sync jobs are created successfully.
	OnboardingStepGoogleBackupCompleted = "GoogleBackupCompleted"
	// OnboardingStepGoogleBackupSkipped may be set by the UI when the user skips backup onboarding.
	OnboardingStepGoogleBackupSkipped = "GoogleBackupSkipped"
)

func googleBackupOnboardingStep(settings *UserSettings) string {
	if settings == nil || settings.OnboardingStep == nil {
		return ""
	}
	return strings.TrimSpace(*settings.OnboardingStep)
}

// IsGoogleBackupOnboardingStep reports whether onboarding_step belongs to the Google backup flow
// (not the legacy satellite tour steps such as tour-end, cli, welcome, etc.).
func IsGoogleBackupOnboardingStep(step string) bool {
	step = strings.TrimSpace(step)
	if step == "" {
		return false
	}
	return strings.HasPrefix(step, "GoogleBackup")
}

func isGoogleBackupOnboardingCompleteStep(step string) bool {
	return step == OnboardingStepGoogleBackupCompleted
}

// GoogleBackupOnboardingStatus derives backup onboarding status from user_settings.
// Returns empty string when settings reflect the legacy tour only (e.g. tour-end with onboardingEnd true).
func GoogleBackupOnboardingStatus(settings *UserSettings) string {
	if settings == nil {
		return OnboardingStatusPending
	}
	step := googleBackupOnboardingStep(settings)
	if !IsGoogleBackupOnboardingStep(step) {
		if settings.OnboardingEnd {
			return OnboardingStatusCompleted
		}
		return ""
	}
	if settings.OnboardingEnd || isGoogleBackupOnboardingCompleteStep(step) || step == OnboardingStepGoogleBackupSkipped {
		return OnboardingStatusCompleted
	}
	if step == OnboardingStepGoogleBackupPending {
		return OnboardingStatusPending
	}
	return OnboardingStatusInProgress
}

// InitGoogleBackupOnboarding marks a new Google backup user as pending after register-google.
// Does not use GetUserSettings: that helper auto-sets onboardingEnd=true when the user already has a project
// (register-google creates "My Project" first), which incorrectly skipped pending and returned completed.
func (s *Service) InitGoogleBackupOnboarding(ctx context.Context) error {
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	settings, err := s.store.Users().GetSettings(ctx, user.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Error.Wrap(err)
	}
	if settings != nil && settings.OnboardingEnd {
		step := googleBackupOnboardingStep(settings)
		if isGoogleBackupOnboardingCompleteStep(step) || step == OnboardingStepGoogleBackupSkipped {
			return nil
		}
	}

	onboardingStart := true
	onboardingEnd := false
	step := OnboardingStepGoogleBackupPending
	err = s.store.Users().UpsertSettings(ctx, user.ID, UpsertUserSettingsRequest{
		OnboardingStart: &onboardingStart,
		OnboardingEnd:   &onboardingEnd,
		OnboardingStep:  &step,
	})
	return Error.Wrap(err)
}

// GoogleBackupOnboardingAPI is returned on Google Backup auth and onboarding PATCH responses.
// UI should use this instead of GET /auth/account/settings for backup onboarding state.
type GoogleBackupOnboardingAPI struct {
	OnboardingStart  bool   `json:"onboardingStart"`
	OnboardingEnd    bool   `json:"onboardingEnd"`
	OnboardingStep   string `json:"onboardingStep"`
	OnboardingStatus string `json:"onboarding_status"`
}

// GoogleBackupOnboardingAPIFromSettings builds the onboarding block for API responses.
func GoogleBackupOnboardingAPIFromSettings(settings *UserSettings) GoogleBackupOnboardingAPI {
	if settings == nil {
		return GoogleBackupOnboardingAPI{
			OnboardingStart:  true,
			OnboardingEnd:    false,
			OnboardingStep:   OnboardingStepGoogleBackupPending,
			OnboardingStatus: OnboardingStatusPending,
		}
	}
	step := googleBackupOnboardingStep(settings)
	if step == "" {
		step = OnboardingStepGoogleBackupPending
	}
	return GoogleBackupOnboardingAPI{
		OnboardingStart:  settings.OnboardingStart,
		OnboardingEnd:    settings.OnboardingEnd,
		OnboardingStep:   step,
		OnboardingStatus: GoogleBackupOnboardingStatus(settings),
	}
}
