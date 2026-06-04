// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoogleBackupOnboardingStatus(t *testing.T) {
	stepPending := OnboardingStepGoogleBackupPending
	stepCompleted := OnboardingStepGoogleBackupCompleted
	stepCompletedLegacy := onboardingStepGoogleBackupCompletedLegacy
	stepSkipped := OnboardingStepGoogleBackupSkipped
	stepCustom := "GoogleBackupServiceSelection"
	stepTourEnd := "tour-end"

	tests := []struct {
		name     string
		settings *UserSettings
		want     string
	}{
		{
			name:     "nil settings",
			settings: nil,
			want:     OnboardingStatusPending,
		},
		{
			name:     "completed via jobs",
			settings: &UserSettings{OnboardingEnd: true, OnboardingStep: &stepCompleted},
			want:     OnboardingStatusCompleted,
		},
		{
			name:     "completed via legacy step name",
			settings: &UserSettings{OnboardingEnd: true, OnboardingStep: &stepCompletedLegacy},
			want:     OnboardingStatusCompleted,
		},
		{
			name:     "skipped by ui",
			settings: &UserSettings{OnboardingEnd: true, OnboardingStep: &stepSkipped},
			want:     OnboardingStatusCompleted,
		},
		{
			name:     "pending step",
			settings: &UserSettings{OnboardingEnd: false, OnboardingStep: &stepPending},
			want:     OnboardingStatusPending,
		},
		{
			name:     "in progress",
			settings: &UserSettings{OnboardingEnd: false, OnboardingStep: &stepCustom},
			want:     OnboardingStatusInProgress,
		},
		{
			name:     "legacy tour completed",
			settings: &UserSettings{OnboardingEnd: true, OnboardingStep: &stepTourEnd},
			want:     OnboardingStatusCompleted,
		},
		{
			name:     "legacy tour in progress",
			settings: &UserSettings{OnboardingEnd: false, OnboardingStep: &stepTourEnd},
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, GoogleBackupOnboardingStatus(tt.settings))
		})
	}
}
