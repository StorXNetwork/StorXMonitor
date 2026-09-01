// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/common/uuid"
)

// EnableResellerMFA enables multi-factor authentication for the reseller.
func (s *Service) EnableResellerMFA(ctx context.Context, passcode string, t time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if reseller.MFAEnabled {
		return console.ErrMFAEnabled.New("")
	}

	valid, err := console.ValidateMFAPasscode(passcode, reseller.MFASecretKey, t)
	if err != nil {
		return ErrValidation.Wrap(console.ErrMFAPasscode.Wrap(err))
	}
	if !valid {
		return ErrValidation.Wrap(console.ErrMFAPasscode.New("The MFA passcode is not valid or has expired"))
	}

	reseller.MFAEnabled = true
	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		MFAEnabled: &reseller.MFAEnabled,
		UpdatedAt:  time.Now(),
	})
	return Error.Wrap(err)
}

// DisableResellerMFA disables multi-factor authentication for the reseller.
func (s *Service) DisableResellerMFA(ctx context.Context, passcode string, t time.Time, recoveryCode string) (err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if !reseller.MFAEnabled {
		return nil
	}

	if recoveryCode != "" && passcode != "" {
		return console.ErrMFAConflict.New("Expected either passcode or recovery code, but got both")
	}

	if recoveryCode != "" {
		found := false
		for _, code := range reseller.MFARecoveryCodes {
			if code == recoveryCode {
				found = true
				break
			}
		}
		if !found {
			return console.ErrMFARecoveryCode.New("The MFA recovery code is not valid or has been previously used")
		}
	} else if passcode != "" {
		valid, validateErr := console.ValidateMFAPasscode(passcode, reseller.MFASecretKey, t)
		if validateErr != nil {
			return ErrValidation.Wrap(console.ErrMFAPasscode.Wrap(validateErr))
		}
		if !valid {
			return ErrValidation.Wrap(console.ErrMFAPasscode.New("The MFA passcode is not valid or has expired"))
		}
	} else {
		return console.ErrMFAMissing.New("A MFA passcode or recovery code is required")
	}

	reseller.MFAEnabled = false
	reseller.MFASecretKey = ""
	reseller.MFARecoveryCodes = nil

	secretKeyPtr := &reseller.MFASecretKey
	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		MFAEnabled:       &reseller.MFAEnabled,
		MFASecretKey:     &secretKeyPtr,
		MFARecoveryCodes: &reseller.MFARecoveryCodes,
		UpdatedAt:        time.Now(),
	})
	return Error.Wrap(err)
}

// ResetResellerMFASecretKey creates a new TOTP secret key for the reseller.
func (s *Service) ResetResellerMFASecretKey(ctx context.Context) (key string, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return "", Error.Wrap(err)
	}

	if reseller.MFAEnabled {
		return "", console.ErrMFAEnabled.New("")
	}

	key, err = console.NewMFASecretKey()
	if err != nil {
		return "", Error.Wrap(err)
	}

	reseller.MFASecretKey = key
	mfaSecretKeyPtr := &reseller.MFASecretKey

	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		MFASecretKey: &mfaSecretKeyPtr,
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		return "", Error.Wrap(err)
	}

	return key, nil
}

// ResetResellerMFARecoveryCodes creates a new set of MFA recovery codes for the reseller.
func (s *Service) ResetResellerMFARecoveryCodes(ctx context.Context, requireCode bool, passcode string, recoveryCode string) (codes []string, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if !reseller.MFAEnabled {
		return nil, console.ErrUnauthorized.New("MFA recovery codes cannot be generated while MFA is disabled.")
	}

	if requireCode {
		t := time.Now()
		if recoveryCode != "" && passcode != "" {
			return nil, console.ErrMFAConflict.New("Expected either passcode or recovery code, but got both")
		}

		if recoveryCode != "" {
			found := false
			for _, code := range reseller.MFARecoveryCodes {
				if code == recoveryCode {
					found = true
					break
				}
			}
			if !found {
				return nil, console.ErrMFARecoveryCode.New("The MFA recovery code is not valid or has been previously used")
			}
		} else if passcode != "" {
			valid, validateErr := console.ValidateMFAPasscode(passcode, reseller.MFASecretKey, t)
			if validateErr != nil {
				return nil, ErrValidation.Wrap(console.ErrMFAPasscode.Wrap(validateErr))
			}
			if !valid {
				return nil, ErrValidation.Wrap(console.ErrMFAPasscode.New("The MFA passcode is not valid or has expired"))
			}
		} else {
			return nil, console.ErrMFAMissing.New("A MFA passcode or recovery code is required")
		}
	}

	codes = make([]string, console.MFARecoveryCodeCount)
	for i := 0; i < console.MFARecoveryCodeCount; i++ {
		code, codeErr := console.NewMFARecoveryCode()
		if codeErr != nil {
			return nil, Error.Wrap(codeErr)
		}
		codes[i] = code
	}

	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		MFARecoveryCodes: &codes,
		UpdatedAt:        time.Now(),
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return codes, nil
}

// DeleteAllSessionsByResellerIDExcept removes all sessions except the specified session.
func (s *Service) DeleteAllSessionsByResellerIDExcept(ctx context.Context, resellerID uuid.UUID, sessionID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = s.store.WebappSessionResellers().DeleteAllByResellerIDExcept(ctx, resellerID, sessionID)
	return Error.Wrap(err)
}

// ValidateSecurityToken validates a signed security token.
func (s *Service) ValidateSecurityToken(value string) error {
	token, err := consoleauth.FromBase64URLString(value)
	if err != nil {
		return err
	}

	valid, err := s.tokens.ValidateToken(token)
	if err != nil {
		return err
	}
	if !valid {
		return errs.New("Invalid security token")
	}

	return nil
}
