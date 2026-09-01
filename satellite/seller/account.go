// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/StorXNetwork/StorXMonitor/private/post"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/utils"
	"github.com/StorXNetwork/common/uuid"
)

const accountActionWrongStepOrderErrMsg = "please complete the previous step first"

// ChangeEmailReseller handles change reseller email actions.
func (s *Service) ChangeEmailReseller(ctx context.Context, step console.AccountActionStep, data string) (err error) {
	defer mon.Task()(&ctx)(&err)

	if !s.authConfig.EmailChangeFlowEnabled {
		return console.ErrForbidden.New("this feature is disabled")
	}

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if reseller.LoginLockoutExpiration.After(time.Now()) {
		s.auditLog(ctx, "change email: failed account locked out", &reseller.ID, reseller.Email)
		return console.ErrUnauthorized.New("please try again later")
	}

	switch step {
	case console.VerifyAccountPasswordStep:
		return s.handleChangeEmailPasswordStep(ctx, reseller, data)
	case console.VerifyAccountMfaStep:
		return s.handleChangeEmailMfaStep(ctx, reseller, data)
	case console.VerifyAccountEmailStep:
		return s.handleChangeEmailVerifyCurrentStep(ctx, reseller, data)
	case console.ChangeAccountEmailStep:
		return s.handleChangeEmailNewEmailStep(ctx, reseller, data)
	case console.VerifyNewAccountEmailStep:
		return s.handleChangeEmailVerifyNewStep(ctx, reseller, data)
	default:
		return ErrValidation.New("step value is out of range")
	}
}

func (s *Service) handleChangeEmailPasswordStep(ctx context.Context, reseller *Reseller, data string) error {
	if err := bcrypt.CompareHashAndPassword(reseller.PasswordHash, []byte(data)); err != nil {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New("password is incorrect")
	}

	var verificationCode string
	if !reseller.MFAEnabled {
		code, err := generateVerificationCode()
		if err != nil {
			return Error.Wrap(err)
		}
		verificationCode = code
	}

	if err := s.updateResellerEmailChangeStep(ctx, reseller.ID, console.VerifyAccountPasswordStep, verificationCode, nil); err != nil {
		return Error.Wrap(err)
	}

	if !reseller.MFAEnabled && s.mailService != nil {
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: reseller.Email, Name: reseller.Name}},
			&console.EmailAddressVerificationEmail{
				VerificationCode: verificationCode,
				Action:           "an account email address change",
			},
		)
	}

	return nil
}

func (s *Service) handleChangeEmailMfaStep(ctx context.Context, reseller *Reseller, data string) error {
	if !reseller.MFAEnabled {
		return nil
	}

	if reseller.EmailChangeVerificationStep < console.VerifyAccountPasswordStep {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New(accountActionWrongStepOrderErrMsg)
	}

	valid, err := console.ValidateMFAPasscode(data, reseller.MFASecretKey, time.Now())
	if err != nil || !valid {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		if err != nil {
			return console.ErrMFAPasscode.Wrap(err)
		}
		return console.ErrMFAPasscode.New("The MFA passcode is not valid or has expired")
	}

	verificationCode, err := generateVerificationCode()
	if err != nil {
		return Error.Wrap(err)
	}

	if err := s.updateResellerEmailChangeStep(ctx, reseller.ID, console.VerifyAccountMfaStep, verificationCode, nil); err != nil {
		return Error.Wrap(err)
	}

	if s.mailService != nil {
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: reseller.Email, Name: reseller.Name}},
			&console.EmailAddressVerificationEmail{
				VerificationCode: verificationCode,
				Action:           "an account email address change",
			},
		)
	}

	return nil
}

func (s *Service) handleChangeEmailVerifyCurrentStep(ctx context.Context, reseller *Reseller, data string) error {
	previousStep := console.VerifyAccountPasswordStep
	if reseller.MFAEnabled {
		previousStep = console.VerifyAccountMfaStep
	}

	if reseller.EmailChangeVerificationStep < previousStep {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New(accountActionWrongStepOrderErrMsg)
	}

	if reseller.ActivationCode != data {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New("verification code is incorrect")
	}

	return s.updateResellerEmailChangeStep(ctx, reseller.ID, console.VerifyAccountEmailStep, "", nil)
}

func (s *Service) handleChangeEmailNewEmailStep(ctx context.Context, reseller *Reseller, data string) error {
	if reseller.EmailChangeVerificationStep == console.ChangeAccountEmailStep && reseller.NewUnverifiedEmail != nil {
		return console.ErrConflict.New("a new unverified email is already set. Please verify it or restart the flow")
	}

	if reseller.EmailChangeVerificationStep < console.VerifyAccountEmailStep {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New(accountActionWrongStepOrderErrMsg)
	}

	if !utils.ValidateEmail(data) {
		return ErrValidation.New("invalid email")
	}

	verified, unverified, err := s.GetResellerByEmailWithUnverified(ctx, data)
	if err != nil && !ErrEmailNotFound.Has(err) {
		return Error.Wrap(err)
	}
	if verified != nil || len(unverified) > 0 {
		return ErrValidation.New("invalid email")
	}

	verificationCode, err := generateVerificationCode()
	if err != nil {
		return Error.Wrap(err)
	}

	newEmail := strings.TrimSpace(data)
	if err := s.updateResellerEmailChangeStep(ctx, reseller.ID, console.ChangeAccountEmailStep, verificationCode, &newEmail); err != nil {
		return Error.Wrap(err)
	}

	if s.mailService != nil {
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: newEmail, Name: reseller.Name}},
			&console.EmailAddressVerificationEmail{
				VerificationCode: verificationCode,
				Action:           "account email address change",
			},
		)
	}

	return nil
}

func (s *Service) handleChangeEmailVerifyNewStep(ctx context.Context, reseller *Reseller, data string) error {
	if reseller.EmailChangeVerificationStep < console.ChangeAccountEmailStep {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New(accountActionWrongStepOrderErrMsg)
	}

	if reseller.ActivationCode != data {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return lockErr
		}
		return ErrValidation.New("verification code is incorrect")
	}

	if reseller.NewUnverifiedEmail == nil {
		return Error.New("new email is not set")
	}

	zero := 0
	var zeroTime *time.Time
	emptyCode := ""
	var nilEmail *string
	_, err := s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		Email:                       reseller.NewUnverifiedEmail,
		EmailChangeVerificationStep: &zero,
		FailedLoginCount:            &zero,
		LoginLockoutExpiration:      &zeroTime,
		ActivationCode:              &emptyCode,
		NewUnverifiedEmail:          &nilEmail,
		UpdatedAt:                   time.Now(),
	})
	if err != nil {
		return Error.Wrap(err)
	}

	if s.mailService != nil {
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: *reseller.NewUnverifiedEmail, Name: reseller.Name}},
			&console.ChangeEmailSuccessEmail{},
		)
	}

	return nil
}

func (s *Service) updateResellerEmailChangeStep(ctx context.Context, resellerID uuid.UUID, step console.AccountActionStep, verificationCode string, newUnverifiedEmail *string) error {
	zero := 0
	var zeroTime *time.Time
	_, err := s.store.Resellers().Update(ctx, resellerID, UpdateResellerRequest{
		EmailChangeVerificationStep: &step,
		FailedLoginCount:            &zero,
		LoginLockoutExpiration:      &zeroTime,
		ActivationCode:              &verificationCode,
		NewUnverifiedEmail:          &newUnverifiedEmail,
		UpdatedAt:                   time.Now(),
	})
	return Error.Wrap(err)
}

// DeleteAccountRequestReseller schedules reseller account deletion.
func (s *Service) DeleteAccountRequestReseller(ctx context.Context) error {
	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	deleteAt := time.Now().AddDate(0, 1, 0)
	if err := s.store.ResellerDeleteRequests().CreateDeleteRequest(ctx, reseller.ID, deleteAt); err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "delete account request", &reseller.ID, reseller.Email)
	return nil
}

// DeleteAccountReseller soft-deletes a reseller account by email (admin verification).
func (s *Service) DeleteAccountReseller(ctx context.Context, email string) error {
	verified, unverified, err := s.GetResellerByEmailWithUnverified(ctx, email)
	if err != nil && !ErrEmailNotFound.Has(err) {
		return Error.Wrap(err)
	}

	var reseller *Reseller
	if verified != nil {
		reseller = verified
	} else if len(unverified) > 0 {
		reseller = &unverified[0]
	} else {
		return ErrEmailNotFound.New("reseller not found with email: %s", email)
	}

	now := time.Now()
	deletedStatus := ResellerDeleted
	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		Status:    &deletedStatus,
		DeletedAt: &now,
		UpdatedAt: now,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	_, _ = s.store.WebappSessionResellers().DeleteAllByResellerID(ctx, reseller.ID)
	if secret, _, tokenErr := s.store.ResetPasswordTokens().GetByOwnerID(ctx, reseller.ID); tokenErr == nil {
		_ = s.store.ResetPasswordTokens().Delete(ctx, secret)
	}

	s.auditLog(ctx, "delete account", &reseller.ID, reseller.Email)
	return nil
}
