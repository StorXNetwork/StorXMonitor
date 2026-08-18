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
	// OnboardingStepMicrosoftBackupPending is set at microsoft-backup registration.
	OnboardingStepMicrosoftBackupPending = "MicrosoftBackupPending"
	// OnboardingStepMicrosoftBackupCompleted is set when Microsoft backup onboarding finishes.
	OnboardingStepMicrosoftBackupCompleted = "MicrosoftBackupCompleted"
	// OnboardingStepMicrosoftBackupSkipped may be set by the UI when the user skips Microsoft backup onboarding.
	OnboardingStepMicrosoftBackupSkipped = "MicrosoftBackupSkipped"
)

func microsoftBackupOnboardingStep(settings *UserSettings) string {
	if settings == nil || settings.OnboardingStep == nil {
		return ""
	}
	return strings.TrimSpace(*settings.OnboardingStep)
}

// IsMicrosoftBackupOnboardingStep reports whether onboarding_step belongs to the Microsoft backup flow.
func IsMicrosoftBackupOnboardingStep(step string) bool {
	step = strings.TrimSpace(step)
	if step == "" {
		return false
	}
	return strings.HasPrefix(step, "MicrosoftBackup")
}

func isMicrosoftBackupOnboardingCompleteStep(step string) bool {
	return step == OnboardingStepMicrosoftBackupCompleted
}

// MicrosoftBackupOnboardingStatus derives Microsoft backup onboarding status from user_settings.
func MicrosoftBackupOnboardingStatus(settings *UserSettings) string {
	if settings == nil {
		return OnboardingStatusPending
	}
	step := microsoftBackupOnboardingStep(settings)
	if !IsMicrosoftBackupOnboardingStep(step) {
		if settings.OnboardingEnd {
			return OnboardingStatusCompleted
		}
		return ""
	}
	if settings.OnboardingEnd || isMicrosoftBackupOnboardingCompleteStep(step) || step == OnboardingStepMicrosoftBackupSkipped {
		return OnboardingStatusCompleted
	}
	if step == OnboardingStepMicrosoftBackupPending {
		return OnboardingStatusPending
	}
	return OnboardingStatusInProgress
}

// InitMicrosoftBackupOnboarding marks a new Microsoft backup user as pending after microsoft-backup auth.
func (s *Service) InitMicrosoftBackupOnboarding(ctx context.Context) error {
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	settings, err := s.store.Users().GetSettings(ctx, user.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Error.Wrap(err)
	}
	if settings != nil && settings.OnboardingEnd {
		step := microsoftBackupOnboardingStep(settings)
		if isMicrosoftBackupOnboardingCompleteStep(step) || step == OnboardingStepMicrosoftBackupSkipped {
			return nil
		}
	}

	onboardingStart := true
	onboardingEnd := false
	step := OnboardingStepMicrosoftBackupPending
	err = s.store.Users().UpsertSettings(ctx, user.ID, UpsertUserSettingsRequest{
		OnboardingStart: &onboardingStart,
		OnboardingEnd:   &onboardingEnd,
		OnboardingStep:  &step,
	})
	return Error.Wrap(err)
}

// MicrosoftBackupOnboardingAPI is returned on Microsoft Backup auth responses.
type MicrosoftBackupOnboardingAPI struct {
	OnboardingStart  bool   `json:"onboardingStart"`
	OnboardingEnd    bool   `json:"onboardingEnd"`
	OnboardingStep   string `json:"onboardingStep"`
	OnboardingStatus string `json:"onboarding_status"`
}

// MicrosoftBackupOnboardingAPIFromSettings builds the Microsoft onboarding block for API responses.
func MicrosoftBackupOnboardingAPIFromSettings(settings *UserSettings) MicrosoftBackupOnboardingAPI {
	if settings == nil {
		return MicrosoftBackupOnboardingAPI{
			OnboardingStart:  true,
			OnboardingEnd:    false,
			OnboardingStep:   OnboardingStepMicrosoftBackupPending,
			OnboardingStatus: OnboardingStatusPending,
		}
	}
	step := microsoftBackupOnboardingStep(settings)
	if step == "" {
		step = OnboardingStepMicrosoftBackupPending
	}
	return MicrosoftBackupOnboardingAPI{
		OnboardingStart:  settings.OnboardingStart,
		OnboardingEnd:    settings.OnboardingEnd,
		OnboardingStep:   step,
		OnboardingStatus: MicrosoftBackupOnboardingStatus(settings),
	}
}

// GetMicrosoftBackupOnboarding reads user_settings for the current user and returns the Microsoft onboarding block.
func (s *Service) GetMicrosoftBackupOnboarding(ctx context.Context) (MicrosoftBackupOnboardingAPI, error) {
	defer mon.Task()(&ctx)

	user, err := GetUser(ctx)
	if err != nil {
		return MicrosoftBackupOnboardingAPI{}, Error.Wrap(err)
	}

	settings, err := s.store.Users().GetSettings(ctx, user.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MicrosoftBackupOnboardingAPI{}, Error.Wrap(err)
	}
	return MicrosoftBackupOnboardingAPIFromSettings(settings), nil
}
