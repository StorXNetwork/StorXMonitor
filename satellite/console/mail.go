// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information

package console

import (
	"fmt"
	"time"
)

// TrialExpirationReminderEmail is mailservice template with trial expiration reminder data.
type TrialExpirationReminderEmail struct {
	Origin              string
	SignInLink          string
	ContactInfoURL      string
	ScheduleMeetingLink string
}

// Template returns email template name.
func (*TrialExpirationReminderEmail) Template() string { return "TrialExpirationReminder" }

// Subject gets email subject.
func (*TrialExpirationReminderEmail) Subject() string { return "Your Storj trial is ending soon" }

// TrialExpiredEmail is mailservice template with trial expiration data.
type TrialExpiredEmail struct {
	Origin              string
	SignInLink          string
	ContactInfoURL      string
	ScheduleMeetingLink string
}

// Template returns email template name.
func (*TrialExpiredEmail) Template() string { return "TrialExpired" }

// Subject gets email subject.
func (*TrialExpiredEmail) Subject() string {
	return "Your Storj trial has ended - Act now to continue!"
}

// AccountActivationEmail is mailservice template with activation data.
type AccountActivationEmail struct {
	Username              string
	Origin                string
	ActivationLink        string
	ContactInfoURL        string
	TermsAndConditionsURL string
}

// Template returns email template name.
func (*AccountActivationEmail) Template() string { return "Welcome" }

// Subject gets email subject.
func (*AccountActivationEmail) Subject() string { return "Activate your email" }

// AccountActivationCodeEmail is mailservice template with activation code.
type AccountActivationCodeEmail struct {
	ActivationCode string
}

// Template returns email template name.
func (*AccountActivationCodeEmail) Template() string { return "WelcomeWithCode" }

// Subject gets email subject.
func (*AccountActivationCodeEmail) Subject() string { return "Activate your email" }

// ForgotPasswordEmail is mailservice template with reset password data.
type ForgotPasswordEmail struct {
	UserName                   string
	Origin                     string
	ResetLink                  string
	CancelPasswordRecoveryLink string
	LetUsKnowURL               string
	ContactInfoURL             string
	TermsAndConditionsURL      string
}

// Template returns email template name.
func (*ForgotPasswordEmail) Template() string { return "Forgot" }

// Subject gets email subject.
func (*ForgotPasswordEmail) Subject() string { return "Password recovery request" }

// ProjectInvitationEmail is mailservice template for project invitation email.
type ProjectInvitationEmail struct {
	InviterEmail string
	SignInLink   string
}

// Template returns email template name.
func (*ProjectInvitationEmail) Template() string { return "Invite" }

// Subject gets email subject.
func (email *ProjectInvitationEmail) Subject() string {
	return "You were invited to join a project on StorX"
}

// StorageUsageEmail is the email sent for storage usage reminders
type StorageUsageEmail struct {
	UserName    string
	StorageUsed float64
	Percentage  float64
	Limit       float64
	ProjectName string
	SignInLink  string
	ContactLink string
}

// Template returns the template name for storage usage reminder emails.
func (e *StorageUsageEmail) Template() string {
	return "StorageUsageReminder"
}

// Subject returns the storage usage reminder email subject.
func (e *StorageUsageEmail) Subject() string {
	return fmt.Sprintf("Storage Usage Alert for Project %s", e.ProjectName)
}

// create a new email template for autobackup failure
type AutoBackupFailureEmail struct {
	Email  string
	Error  string
	Method string
}

// Template returns email template name.
func (*AutoBackupFailureEmail) Template() string { return "AutoBackupFailure" }

// Subject gets email subject.
func (*AutoBackupFailureEmail) Subject() string { return "Auto Backup Failure" }

// ExistingUserProjectInvitationEmail is mailservice template for project invitation email for existing users.
type ExistingUserProjectInvitationEmail struct {
	InviterEmail string
	SignInLink   string
}

// Template returns email template name.
func (*ExistingUserProjectInvitationEmail) Template() string { return "ExistingUserInvite" }

// Subject gets email subject.
func (email *ExistingUserProjectInvitationEmail) Subject() string {
	return "You were invited to join a project on StorX"
}

// UnverifiedUserProjectInvitationEmail is mailservice template for project invitation email for unverified users.
type UnverifiedUserProjectInvitationEmail struct {
	InviterEmail   string
	Region         string
	ActivationLink string
}

// Template returns email template name.
func (*UnverifiedUserProjectInvitationEmail) Template() string { return "UnverifiedUserInvite" }

// Subject gets email subject.
func (email *UnverifiedUserProjectInvitationEmail) Subject() string {
	return "You were invited to join a project on StorX"
}

// NewUserProjectInvitationEmail is mailservice template for project invitation email for new users.
type NewUserProjectInvitationEmail struct {
	InviterEmail string
	Region       string
	SignUpLink   string
}

// Template returns email template name.
func (*NewUserProjectInvitationEmail) Template() string { return "NewUserInvite" }

// Subject gets email subject.
func (email *NewUserProjectInvitationEmail) Subject() string {
	return "You were invited to join a project on StorX"
}

// UnknownResetPasswordEmail is mailservice template with unknown password reset data.
type UnknownResetPasswordEmail struct {
	Satellite           string
	Email               string
	DoubleCheckLink     string
	ResetPasswordLink   string
	CreateAnAccountLink string
	SupportTeamLink     string
}

// Template returns email template name.
func (*UnknownResetPasswordEmail) Template() string { return "UnknownReset" }

// Subject gets email subject.
func (*UnknownResetPasswordEmail) Subject() string {
	return "You have requested to reset your password, but..."
}

// AccountAlreadyExistsEmail is mailservice template for email where user tries to create account, but one already exists.
type AccountAlreadyExistsEmail struct {
	Origin            string
	SatelliteName     string
	SignInLink        string
	ResetPasswordLink string
	CreateAccountLink string
}

// Template returns email template name.
func (*AccountAlreadyExistsEmail) Template() string { return "AccountAlreadyExists" }

// Subject gets email subject.
func (*AccountAlreadyExistsEmail) Subject() string {
	return "Are you trying to sign in?"
}

// RegistrationWelcomeEmail is mailservice template for email where user tries to create account, but one already exists.
type RegistrationWelcomeEmail struct {
	Username  string
	LoginLink string
}

// Template returns email template name.
func (*RegistrationWelcomeEmail) Template() string { return "RegistrationWelcome" }

// Subject gets email subject.
func (*RegistrationWelcomeEmail) Subject() string {
	return "Welcome to StorX"
}

// AccountAlreadyExistsEmail is mailservice template for email where user tries to create account, but one already exists.
type ContactUsForm struct {
	Email   string
	Name    string
	Message string
}

// Template returns email template name.
func (*ContactUsForm) Template() string { return "ContactUsAdminEmail" }

// Subject gets email subject.
func (*ContactUsForm) Subject() string {
	return "Contact Us form on Storx"
}

// LoginLockAccountEmail is mailservice template with login lock account data.
type LoginLockAccountEmail struct {
	LockoutDuration   time.Duration
	ResetPasswordLink string
}

// Template returns email template name.
func (*LoginLockAccountEmail) Template() string { return "LoginLockAccount" }

// Subject gets email subject.
func (*LoginLockAccountEmail) Subject() string { return "Account Lock" }

// ActivationLockAccountEmail is mailservice template with activation lock account data.
type ActivationLockAccountEmail struct {
	LockoutDuration time.Duration
	SupportURL      string
}

// Template returns email template name.
func (*ActivationLockAccountEmail) Template() string { return "ActivationLockAccount" }

// Subject gets email subject.
func (*ActivationLockAccountEmail) Subject() string { return "Account Lock" }

type UpgradeExpiredEmail struct {
	UserName  string
	Signature string
}

// Template returns email template name.
func (*UpgradeExpiredEmail) Template() string { return "UpgradeExpired" }

// Subject gets email subject.
func (*UpgradeExpiredEmail) Subject() string {
	return "Your StorX Account Expired / Your Account Downgraded Automatically"
}

type UpgradeExpiringEmail struct {
	UserName  string
	Signature string
	ExpireOn  string
}

// Template returns email template name.
func (*UpgradeExpiringEmail) Template() string { return "UpgradeExpiring" }

// Subject gets email subject.
func (*UpgradeExpiringEmail) Subject() string {
	return "Your StorX Account Due For Renewal, Kindly Renew Urgently"
}

type UpgradeSuccessfullEmail struct {
	UserName  string
	Signature string
	GBsize    string
	Bandwidth string
}

// Template returns email template name.
func (*UpgradeSuccessfullEmail) Template() string { return "UpgradeSuccessfull" }

// Subject gets email subject.
func (*UpgradeSuccessfullEmail) Subject() string {
	return "Payment Receipt Confirmation for Your StorX Account"
}
