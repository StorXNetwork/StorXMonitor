// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// Swagger models for Google Backup onboarding (register, login, settings).
//
// ## Architecture (frontend vs backend)
//
// **Backend stores** in `user_settings`: `onboardingStart`, `onboardingEnd`, `onboardingStep` (step name only — never frontend URLs).
//
// **Frontend controls** which page/screen the user sees (e.g. `/google-backup/onboarding`, `/google-backup/services`, `/google-backup/connect`, `/google-backup/domain-users`). Map `onboardingStep` from GET /auth/account/settings to your routes on resume.
//
// **Custom steps:** PATCH accepts any `onboardingStep` starting with `GoogleBackup` (UI progress). Only three steps are set by backend logic: `GoogleBackupPending` (register), `GoogleBackupCompleted` (POST /auto-sync/jobs success), `GoogleBackupSkipped` (UI skip PATCH).
//
// **onboarding_status** (`pending` | `in_progress` | `completed`) is computed for API hints — not stored in DB.

// GoogleBackupOnboardingArchitecture is documentation-only (see package comment above).
type GoogleBackupOnboardingArchitecture struct{}

// GoogleBackupOnboardingStepBackendDefined lists steps set automatically by Satellite (not sent by UI).
type GoogleBackupOnboardingStepBackendDefined struct {
	Pending  string `json:"GoogleBackupPending" example:"GoogleBackupPending"`   // register-google
	Completed string `json:"GoogleBackupCompleted" example:"GoogleBackupCompleted"` // POST /auto-sync/jobs success
	Skipped  string `json:"GoogleBackupSkipped" example:"GoogleBackupSkipped"`   // UI PATCH skip
}

// GoogleBackupOnboardingStepUIExamples lists common UI-only steps (PATCH /auth/account/onboarding).
type GoogleBackupOnboardingStepUIExamples struct {
	Connect           string `json:"GoogleBackupConnect" example:"GoogleBackupConnect"`
	ServiceSelection  string `json:"GoogleBackupServiceSelection" example:"GoogleBackupServiceSelection"`
	DomainUsers       string `json:"GoogleBackupDomainUsers" example:"GoogleBackupDomainUsers"`
}

// GoogleBackupMetadataSwagger is the google_backup object on register and connect responses.
type GoogleBackupMetadataSwagger struct {
	AccountType      string   `json:"account_type,omitempty" example:"personal"`
	Email            string   `json:"email,omitempty" example:"user@gmail.com"`
	GrantedScopes    []string `json:"granted_scopes" example:"openid,email,profile,https://www.googleapis.com/auth/gmail.readonly"`
	UngrantedScopes  []string `json:"ungranted_scopes" example:""`
	DomainUsersError string   `json:"domain_users_error,omitempty" example:""`
}

// GoogleBackupOnboardingStatusValues documents onboarding_status enum in API responses (computed, not stored).
type GoogleBackupOnboardingStatusValues struct {
	Pending    string `json:"pending" example:"pending"`       // onboardingStep=GoogleBackupPending
	InProgress string `json:"in_progress" example:"in_progress"` // any other GoogleBackup* step, onboardingEnd=false
	Completed  string `json:"completed" example:"completed"`   // GoogleBackupCompleted, GoogleBackupSkipped, or onboardingEnd=true
}

// SetGoogleBackupOnboardingSkipSwaggerRequest example body when user skips onboarding (UI-driven).
type SetGoogleBackupOnboardingSkipSwaggerRequest struct {
	OnboardingStart bool   `json:"onboardingStart" example:"true"`
	OnboardingEnd   bool   `json:"onboardingEnd" example:"true"`
	OnboardingStep  string `json:"onboardingStep" example:"GoogleBackupSkipped"`
}

// SetGoogleBackupOnboardingStepSwaggerRequest example when user opens service selection (frontend route /google-backup/services).
type SetGoogleBackupOnboardingStepSwaggerRequest struct {
	OnboardingStart bool   `json:"onboardingStart" example:"true"`
	OnboardingEnd   bool   `json:"onboardingEnd" example:"false"`
	OnboardingStep  string `json:"onboardingStep" example:"GoogleBackupServiceSelection"`
}

// SetGoogleBackupOnboardingDomainUsersSwaggerRequest example when user opens workspace mailbox screen (frontend route /google-backup/domain-users).
type SetGoogleBackupOnboardingDomainUsersSwaggerRequest struct {
	OnboardingStart bool   `json:"onboardingStart" example:"true"`
	OnboardingEnd   bool   `json:"onboardingEnd" example:"false"`
	OnboardingStep  string `json:"onboardingStep" example:"GoogleBackupDomainUsers"`
}

// SetGoogleBackupOnboardingConnectSwaggerRequest example when user opens connect screen (frontend route /google-backup/connect).
type SetGoogleBackupOnboardingConnectSwaggerRequest struct {
	OnboardingStart bool   `json:"onboardingStart" example:"true"`
	OnboardingEnd   bool   `json:"onboardingEnd" example:"false"`
	OnboardingStep  string `json:"onboardingStep" example:"GoogleBackupConnect"`
}

// GoogleBackupOnboardingDocResponse groups architecture docs for Swagger Schemas (reference model).
type GoogleBackupOnboardingDocResponse struct {
	BackendDefinedSteps GoogleBackupOnboardingStepBackendDefined `json:"backendDefinedSteps"`
	UIStepExamples      GoogleBackupOnboardingStepUIExamples     `json:"uiStepExamples"`
	OnboardingStatus      GoogleBackupOnboardingStatusValues       `json:"onboardingStatusValues"`
	PatchSkipExample      SetGoogleBackupOnboardingSkipSwaggerRequest `json:"patchSkipExample"`
	PatchServiceExample   SetGoogleBackupOnboardingStepSwaggerRequest `json:"patchServiceSelectionExample"`
	PatchConnectExample   SetGoogleBackupOnboardingConnectSwaggerRequest `json:"patchConnectExample"`
	PatchDomainUsersExample SetGoogleBackupOnboardingDomainUsersSwaggerRequest `json:"patchDomainUsersExample"`
	FrontendRouteExamples map[string]string `json:"frontendRouteExamples" swaggertype:"object"`
}

