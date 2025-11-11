// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developerservice

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"storj.io/common/http/requestid"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleauth"
)

// CreateUserFromDeveloper creates User without password and active state.
func (s *Service) CreateUserFromDeveloper(ctx context.Context, user console.CreateUser, developerID uuid.UUID, tokenSecret console.RegistrationSecret) (u *console.User, err error) {
	defer mon.Task()(&ctx)(&err)

	var captchaScore *float64

	mon.Counter("create_user_attempt").Inc(1) //mon:locked

	var registrationToken *console.RegistrationToken
	if s.regTokenChecker != nil {
		registrationToken, err = s.regTokenChecker.CheckRegistrationSecret(ctx, tokenSecret)
		if err != nil {
			return nil, ErrRegToken.Wrap(err)
		}
	}

	// store data
	err = s.store.WithTx(ctx, func(ctx context.Context, tx console.DBTx) error {
		userID, err := uuid.New()
		if err != nil {
			return err
		}

		newUser := &console.User{
			ID:               userID,
			Email:            user.Email,
			FullName:         user.FullName,
			ShortName:        user.ShortName,
			Status:           console.Active,
			IsProfessional:   user.IsProfessional,
			PasswordHash:     []byte{},
			Position:         user.Position,
			CompanyName:      user.CompanyName,
			EmployeeCount:    user.EmployeeCount,
			HaveSalesContact: user.HaveSalesContact,
			SignupPromoCode:  user.SignupPromoCode,
			SignupCaptcha:    captchaScore,
			ActivationCode:   user.ActivationCode,
			SignupId:         user.SignupId,
			Source:           user.Source,
		}

		if user.UserAgent != nil {
			newUser.UserAgent = user.UserAgent
		}

		u, err = tx.Users().Insert(ctx, newUser)
		if err != nil {
			return err
		}

		if registrationToken != nil {
			err = tx.RegistrationTokens().UpdateOwner(ctx, registrationToken.Secret, u.ID)
			if err != nil {
				return err
			}
		}

		err = tx.Developers().AddDeveloperUserMapping(ctx, developerID, u.ID)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, "create user", nil, user.Email)
	mon.Counter("create_user_success").Inc(1) //mon:locked

	return u, nil
}

// CreateDeveloper gets password hash value and creates new inactive developer.
func (s *Service) CreateDeveloper(ctx context.Context, developer console.CreateDeveloper, tokenSecret console.RegistrationSecret) (u *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	mon.Counter("create_developer_attempt").Inc(1) //mon:locked

	var registrationToken *console.RegistrationToken
	if s.regTokenChecker != nil {
		registrationToken, err = s.regTokenChecker.CheckRegistrationSecret(ctx, tokenSecret)
		if err != nil {
			return nil, ErrRegToken.Wrap(err)
		}
	}

	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developer.Email)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if verified != nil {
		mon.Counter("create_developer_duplicate_verified").Inc(1) //mon:locked
		return nil, ErrEmailUsed.New(emailUsedErrMsg)
	} else if len(unverified) != 0 {
		mon.Counter("create_developer_duplicate_unverified").Inc(1) //mon:locked
		return nil, ErrEmailUsed.New(emailUsedErrMsg)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(developer.Password), s.config.PasswordCost)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// store data
	err = s.store.WithTx(ctx, func(ctx context.Context, tx console.DBTx) error {
		developerID, err := uuid.New()
		if err != nil {
			return err
		}

		newDeveloper := &console.Developer{
			ID:             developerID,
			Email:          developer.Email,
			FullName:       developer.FullName,
			PasswordHash:   hash,
			Status:         console.Active,
			CompanyName:    developer.CompanyName,
			ActivationCode: developer.ActivationCode,
			SignupId:       developer.SignupId,
		}

		u, err = tx.Developers().Insert(ctx, newDeveloper)
		if err != nil {
			return err
		}

		if registrationToken != nil {
			err = tx.RegistrationTokens().UpdateOwner(ctx, registrationToken.Secret, u.ID)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, "create developer", nil, developer.Email)
	mon.Counter("create_developer_success").Inc(1) //mon:locked

	return u, nil
}

// GenerateSessionTokenForDeveloper creates a new developer session and returns the string representation of its token.
func (s *Service) GenerateSessionTokenForDeveloper(ctx context.Context, developerID uuid.UUID, email, ip string, customDuration *time.Duration) (_ *console.TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	sessionID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	duration := s.config.Session.Duration
	if customDuration != nil {
		duration = *customDuration
	} else if s.config.Session.InactivityTimerEnabled {
		duration = time.Duration(s.config.Session.InactivityTimerDuration) * time.Second
	}
	expiresAt := time.Now().Add(duration)

	_, err = s.store.WebappSessionDevelopers().Create(ctx, sessionID, developerID, ip, expiresAt)
	if err != nil {
		return nil, err
	}

	token := consoleauth.Token{Payload: sessionID.Bytes()}

	signature, err := s.tokens.SignToken(token)
	if err != nil {
		return nil, err
	}
	token.Signature = signature

	s.auditLog(ctx, "login developer", &developerID, email)

	return &console.TokenInfo{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// SetAccountActiveDeveloper - is a method for setting developer account status to Active and sending
// event to hubspot.
func (s *Service) SetAccountActiveDeveloper(ctx context.Context, developer *console.Developer) (err error) {
	defer mon.Task()(&ctx)(&err)

	activeStatus := console.Active
	err = s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		Status: &activeStatus,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "activate account", &developer.ID, developer.Email)
	s.analytics.TrackAccountVerified(developer.ID, developer.Email)

	return nil
}

// SetActivationCodeAndSignupIDForDeveloper - generates and updates a new code for developer's signup verification.
// It updates the request ID associated with the signup as well.
func (s *Service) SetActivationCodeAndSignupIDForDeveloper(ctx context.Context, developer console.Developer) (_ console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	randNum, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return console.Developer{}, Error.Wrap(err)
	}
	randNum = randNum.Add(randNum, big.NewInt(100000))
	code := randNum.String()

	requestID := requestid.FromContext(ctx)
	err = s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		ActivationCode: &code,
		SignupId:       &requestID,
	})
	if err != nil {
		return console.Developer{}, Error.Wrap(err)
	}

	developer.SignupId = requestID
	developer.ActivationCode = code

	return developer, nil
}

// TokenDeveloper authenticates Developer by credentials and returns session token.
func (s *Service) TokenDeveloper(ctx context.Context, request console.AuthDeveloper) (response *console.TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	mon.Counter("login_attempt_developer").Inc(1) //mon:locked

	developer, nonActiveDevelopers, err := s.store.Developers().GetByEmailWithUnverified(ctx, request.Email)
	if developer == nil {
		shouldProceed := false
		for _, usr := range nonActiveDevelopers {
			if usr.Status == console.PendingBotVerification || usr.Status == console.LegalHold {
				shouldProceed = true
				botAccount := usr
				developer = &botAccount
				break
			}
		}

		if !shouldProceed {
			if len(nonActiveDevelopers) > 0 {
				mon.Counter("login_email_unverified_developer").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed email unverified", nil, request.Email)
			} else {
				mon.Counter("login_email_invalid_developer").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed invalid email", nil, request.Email)
			}
			return nil, ErrLoginCredentials.New(credentialsErrMsg)
		}
	}

	now := time.Now()

	if developer.LoginLockoutExpiration.After(now) {
		mon.Counter("login_locked_out_developer").Inc(1) //mon:locked
		s.auditLog(ctx, "login: failed account locked out", &developer.ID, request.Email)
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	handleLockAccount := func() error {
		lockoutDuration, err := s.UpdateDevelopersFailedLoginState(ctx, developer)
		if err != nil {
			return err
		}
		if lockoutDuration > 0 {
			// Email notification can be added here if needed
		}

		mon.Counter("login_failed_developer").Inc(1)                                                    //mon:locked
		mon.IntVal("login_developer_failed_count_developer").Observe(int64(developer.FailedLoginCount)) //mon:locked

		if developer.FailedLoginCount == s.config.LoginAttemptsWithoutPenalty {
			mon.Counter("login_lockout_initiated_developer").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed login count reached maximum attempts", &developer.ID, request.Email)
		}

		if developer.FailedLoginCount > s.config.LoginAttemptsWithoutPenalty {
			mon.Counter("login_lockout_reinitiated_developer").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed locked account", &developer.ID, request.Email)
		}

		return nil
	}

	err = bcrypt.CompareHashAndPassword(developer.PasswordHash, []byte(request.Password))
	if err != nil {
		err = handleLockAccount()
		if err != nil {
			return nil, err
		}
		mon.Counter("login_invalid_password_developer").Inc(1) //mon:locked
		s.auditLog(ctx, "login: failed password invalid", &developer.ID, developer.Email)
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if developer.FailedLoginCount != 0 {
		err = s.ResetAccountLockDeveloper(ctx, developer)
		if err != nil {
			return nil, err
		}
	}

	if developer.Status == console.PendingBotVerification || developer.Status == console.LegalHold {
		return nil, ErrLoginRestricted.New("")
	}

	var customDurationPtr *time.Duration
	if request.RememberForOneWeek {
		weekDuration := 7 * 24 * time.Hour
		customDurationPtr = &weekDuration
	}
	response, err = s.GenerateSessionTokenForDeveloper(ctx, developer.ID, developer.Email, request.IP, customDurationPtr)
	if err != nil {
		return nil, err
	}

	mon.Counter("login_success_developer").Inc(1) //mon:locked

	return response, nil
}

// UpdateDevelopersFailedLoginState updates Developer's failed login state.
func (s *Service) UpdateDevelopersFailedLoginState(ctx context.Context, developer *console.Developer) (lockoutDuration time.Duration, err error) {
	defer mon.Task()(&ctx)(&err)

	var failedLoginPenalty *float64
	if developer.FailedLoginCount >= s.config.LoginAttemptsWithoutPenalty-1 {
		lockoutDuration = time.Duration(math.Pow(s.config.FailedLoginPenalty, float64(developer.FailedLoginCount-1))) * time.Minute
		failedLoginPenalty = &s.config.FailedLoginPenalty
	}

	return lockoutDuration, s.store.Developers().UpdateFailedLoginCountAndExpiration(ctx, failedLoginPenalty, developer.ID)
}

// ResetAccountLockDeveloper resets a developer's failed login count and lockout duration.
func (s *Service) ResetAccountLockDeveloper(ctx context.Context, developer *console.Developer) (err error) {
	defer mon.Task()(&ctx)(&err)

	developer.FailedLoginCount = 0
	loginLockoutExpirationPtr := &time.Time{}
	return s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		FailedLoginCount:       &developer.FailedLoginCount,
		LoginLockoutExpiration: &loginLockoutExpirationPtr,
	})
}

// GetDeveloperByEmailWithUnverified returns Developer by email.
func (s *Service) GetDeveloperByEmailWithUnverified(ctx context.Context, email string) (verified *console.Developer, unverified []console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	verified, unverified, err = s.store.Developers().GetByEmailWithUnverified(ctx, email)
	if err != nil {
		return verified, unverified, err
	}

	if verified == nil && len(unverified) == 0 {
		err = ErrEmailNotFound.New(emailNotFoundErrMsg)
	}

	return verified, unverified, err
}

// UpdateAccountDeveloper updates Developer.
func (s *Service) UpdateAccountDeveloper(ctx context.Context, fullName string) (err error) {
	defer mon.Task()(&ctx)(&err)
	developer, err := s.getDeveloperAndAuditLog(ctx, "update account developer")
	if err != nil {
		return Error.Wrap(err)
	}

	// validate fullName
	err = console.ValidateFullName(fullName)
	if err != nil {
		return ErrValidation.Wrap(err)
	}

	developer.FullName = fullName
	err = s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		FullName: &developer.FullName,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// ChangePasswordDeveloper updates password for a given developer.
func (s *Service) ChangePasswordDeveloper(ctx context.Context, pass, newPass string) (err error) {
	defer mon.Task()(&ctx)(&err)
	developer, err := s.getDeveloperAndAuditLog(ctx, "change password developer")
	if err != nil {
		return Error.Wrap(err)
	}

	err = bcrypt.CompareHashAndPassword(developer.PasswordHash, []byte(pass))
	if err != nil {
		return ErrChangePassword.New(changePasswordErrMsg)
	}

	if err := console.ValidateNewPassword(newPass); err != nil {
		return ErrValidation.Wrap(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), s.config.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	developer.PasswordHash = hash
	err = s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		PasswordHash: hash,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	resetPasswordToken, err := s.store.ResetPasswordTokens().GetByOwnerID(ctx, developer.ID)
	if err == nil {
		err := s.store.ResetPasswordTokens().Delete(ctx, resetPasswordToken.Secret)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	_, err = s.store.WebappSessionDevelopers().DeleteAllByDeveloperId(ctx, developer.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// TokenAuthForDeveloper returns an authenticated context by session token.
func (s *Service) TokenAuthForDeveloper(ctx context.Context, token consoleauth.Token, authTime time.Time) (_ context.Context, err error) {
	defer mon.Task()(&ctx)(&err)

	valid, err := s.tokens.ValidateToken(token)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !valid {
		return nil, Error.New("incorrect signature")
	}

	sessionID, err := uuid.FromBytes(token.Payload)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	developerSession, err := s.store.WebappSessionDevelopers().GetBySessionID(ctx, sessionID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	ctx, err = s.authorizeDeveloper(ctx, developerSession.DeveloperID, developerSession.ExpiresAt, authTime)
	if err != nil {
		err := errs.Combine(err, s.store.WebappSessionDevelopers().DeleteBySessionID(ctx, sessionID))
		if err != nil {
			return nil, Error.Wrap(err)
		}
		return nil, err
	}

	return ctx, nil
}

// authorizeDeveloper returns an authorized context by developer ID.
func (s *Service) authorizeDeveloper(ctx context.Context, developerID uuid.UUID, expiration time.Time, authTime time.Time) (_ context.Context, err error) {
	defer mon.Task()(&ctx)(&err)
	if !expiration.IsZero() && expiration.Before(authTime) {
		return nil, ErrTokenExpiration.New("authorization failed. expiration reached.")
	}

	developer, err := s.store.Developers().Get(ctx, developerID)
	if err != nil {
		return nil, Error.New("authorization failed. no user with id: %s", developerID.String())
	}

	return console.WithDeveloper(ctx, developer), nil
}

// DeleteSessionDeveloper removes the developer session from the database.
func (s *Service) DeleteSessionDeveloper(ctx context.Context, sessionID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(s.store.WebappSessionDevelopers().DeleteBySessionID(ctx, sessionID))
}

// RefreshSessionDeveloper resets the expiration time of the session.
func (s *Service) RefreshSessionDeveloper(ctx context.Context, sessionID uuid.UUID) (expiresAt time.Time, err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = s.getDeveloperAndAuditLog(ctx, "refresh session developer")
	if err != nil {
		return time.Time{}, Error.Wrap(err)
	}

	duration := time.Duration(s.config.Session.InactivityTimerDuration) * time.Second
	expiresAt = time.Now().Add(duration)

	err = s.store.WebappSessionDevelopers().UpdateExpiration(ctx, sessionID, expiresAt)
	if err != nil {
		return time.Time{}, err
	}

	return expiresAt, nil
}

// CreateDeveloperOAuthClient creates a new OAuth client for a developer.
func (s *Service) CreateDeveloperOAuthClient(ctx context.Context, req console.CreateOAuthClientRequest) (*console.DeveloperOAuthClient, error) {
	// if redirect_uris or name is empty, return an error
	if req.Name == "" || len(req.RedirectURIs) == 0 {
		return nil, errs.New("invalid_request")
	}

	clientID, err := uuid.New()
	if err != nil {
		return nil, err
	}
	clientSecret, err := generateRandomSecret(32)
	if err != nil {
		return nil, err
	}
	hashedSecret, err := hashSecret(clientSecret)
	if err != nil {
		return nil, err
	}

	developerID, err := s.getDeveloperAndAuditLog(ctx, "create developer oauth client", zap.String("name", req.Name))
	if err != nil {
		return nil, err
	}

	id, err := uuid.New()
	if err != nil {
		return nil, err
	}

	client := &console.DeveloperOAuthClient{
		ID:           id,
		DeveloperID:  developerID.ID,
		ClientID:     clientID.String(),
		ClientSecret: string(hashedSecret),
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Status:       1, // active
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	created, err := s.store.DeveloperOAuthClients().Insert(ctx, client)
	if err != nil {
		return nil, err
	}
	created.ClientSecret = string(hashedSecret) // Only return plaintext once
	return created, nil
}

// ListDeveloperOAuthClients lists all OAuth clients for the current developer.
func (s *Service) ListDeveloperOAuthClients(ctx context.Context) ([]console.DeveloperOAuthClient, error) {
	developerID, err := s.getDeveloperAndAuditLog(ctx, "list developer oauth clients")
	if err != nil {
		return nil, err
	}

	return s.store.DeveloperOAuthClients().ListByDeveloperID(ctx, developerID.ID)
}

// DeleteDeveloperOAuthClient deletes an OAuth client for a developer.
func (s *Service) DeleteDeveloperOAuthClient(ctx context.Context, id uuid.UUID) error {
	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, id)
	if err != nil {
		return err
	}
	if !isOwner {
		return errs.New("client does not belong to developer")
	}

	return s.store.DeveloperOAuthClients().Delete(ctx, id)
}

// UpdateDeveloperOAuthClientStatus updates the status of an OAuth client.
func (s *Service) UpdateDeveloperOAuthClientStatus(ctx context.Context, id uuid.UUID, status int) error {
	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, id)
	if err != nil {
		return err
	}

	if !isOwner {
		return errs.New("client does not belong to developer")
	}

	return s.store.DeveloperOAuthClients().StatusUpdate(ctx, id, status, time.Now().UTC())
}

// isCurrentDeveloperOAuthClientOwner checks if the current developer owns the OAuth client.
func (s *Service) isCurrentDeveloperOAuthClientOwner(ctx context.Context, clientID uuid.UUID) (isOwner bool, err error) {
	defer mon.Task()(&ctx)(&err)

	developerID, err := s.getDeveloperAndAuditLog(ctx, "is current developer oauth client owner", zap.String("clientID", clientID.String()))
	if err != nil {
		return false, err
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, clientID)
	if err != nil {
		return false, err
	}

	return client.DeveloperID == developerID.ID, nil
}

// CreateDeveloperAdmin creates a new developer (admin version - without registration token).
// This is used by admin API to create developers directly.
func (s *Service) CreateDeveloperAdmin(ctx context.Context, developer console.CreateDeveloper) (u *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	mon.Counter("create_developer_attempt").Inc(1) //mon:locked

	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developer.Email)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if verified != nil {
		mon.Counter("create_developer_duplicate_verified").Inc(1) //mon:locked
		return nil, ErrEmailUsed.New(emailUsedErrMsg)
	} else if len(unverified) != 0 {
		mon.Counter("create_developer_duplicate_unverified").Inc(1) //mon:locked
		return nil, ErrEmailUsed.New(emailUsedErrMsg)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(developer.Password), s.config.PasswordCost)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	developerID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Set default status to Active if not provided
	status := console.UserStatus(developer.Status)
	if status == 0 {
		status = console.Active
	}

	newDeveloper := &console.Developer{
		ID:           developerID,
		FullName:     developer.FullName,
		Email:        developer.Email,
		PasswordHash: hash,
		Status:       status,
		CompanyName:  developer.CompanyName,
	}

	u, err = s.store.Developers().Insert(ctx, newDeveloper)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, "create developer (admin)", nil, developer.Email)
	mon.Counter("create_developer_success").Inc(1) //mon:locked

	return u, nil
}

// UpdateDeveloperAdmin updates an existing developer (admin version).
// This allows updating any field including email, password, status, etc.
func (s *Service) UpdateDeveloperAdmin(ctx context.Context, developerEmail string, updateRequest console.UpdateDeveloperRequest) (u *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	// Get developer by email (including unverified/deleted for admin operations)
	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developerEmail)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var developer *console.Developer
	if verified != nil {
		developer = verified
	} else if len(unverified) > 0 {
		developer = &unverified[0]
	} else {
		return nil, ErrEmailNotFound.New("developer with email %q does not exist", developerEmail)
	}

	// If email is being updated, check if new email already exists
	if updateRequest.Email != nil && *updateRequest.Email != developer.Email {
		existingVerified, existingUnverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, *updateRequest.Email)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		// Check if email is taken by a different developer
		if existingVerified != nil && existingVerified.ID != developer.ID {
			return nil, ErrEmailUsed.New("developer with email already exists %s", *updateRequest.Email)
		}
		if len(existingUnverified) > 0 {
			for _, unv := range existingUnverified {
				if unv.ID != developer.ID {
					return nil, ErrEmailUsed.New("developer with email already exists %s", *updateRequest.Email)
				}
			}
		}
	}

	// Validate status if being updated
	if updateRequest.Status != nil {
		statusValue := *updateRequest.Status
		if statusValue < 0 || statusValue > 5 {
			return nil, ErrValidation.New("invalid status value: status must be between 0 (Inactive) and 5 (Pending Bot Verification)")
		}
	}

	// Perform update
	err = s.store.Developers().Update(ctx, developer.ID, updateRequest)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Return updated developer
	lookupEmail := developer.Email
	if updateRequest.Email != nil {
		lookupEmail = *updateRequest.Email
	}

	updatedDeveloper, err := s.store.Developers().Get(ctx, developer.ID)
	if err != nil {
		// If Get fails (e.g., status was set to deleted), try GetByEmailWithUnverified
		verified, unverified, err2 := s.store.Developers().GetByEmailWithUnverified(ctx, lookupEmail)
		if err2 != nil {
			return nil, Error.Wrap(err)
		}
		if verified != nil && verified.ID == developer.ID {
			updatedDeveloper = verified
		} else if len(unverified) > 0 {
			for _, unv := range unverified {
				if unv.ID == developer.ID {
					updatedDeveloper = &unv
					break
				}
			}
		}
		if updatedDeveloper == nil {
			return nil, Error.Wrap(err)
		}
	}

	s.auditLog(ctx, "update developer (admin)", &developer.ID, developer.Email)
	return updatedDeveloper, nil
}

// DeleteDeveloperAdmin deletes a developer (soft delete with cleanup).
// This deletes OAuth clients and sessions, then soft deletes the developer.
func (s *Service) DeleteDeveloperAdmin(ctx context.Context, developerEmail string) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Get developer by email (including unverified/deleted for admin operations)
	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developerEmail)
	if err != nil {
		return Error.Wrap(err)
	}

	var developer *console.Developer
	if verified != nil {
		developer = verified
	} else if len(unverified) > 0 {
		developer = &unverified[0]
	} else {
		return ErrEmailNotFound.New("developer with email %q does not exist", developerEmail)
	}

	// Check if developer has OAuth clients and delete them
	oauthClients, err := s.store.DeveloperOAuthClients().ListByDeveloperID(ctx, developer.ID)
	if err != nil {
		return Error.Wrap(err)
	}
	if len(oauthClients) > 0 {
		// Delete all OAuth clients for this developer
		for _, client := range oauthClients {
			err := s.store.DeveloperOAuthClients().Delete(ctx, client.ID)
			if err != nil {
				return Error.Wrap(err)
			}
		}
	}

	// Delete all developer sessions
	_, err = s.store.WebappSessionDevelopers().DeleteAllByDeveloperId(ctx, developer.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	// Soft delete: Update developer status to Deleted and anonymize email
	emptyName := ""
	deactivatedEmail := fmt.Sprintf("deactivated+%s@storj.io", developer.ID.String())
	status := console.Deleted

	err = s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		FullName: &emptyName,
		Email:    &deactivatedEmail,
		Status:   &status,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "delete developer (admin)", &developer.ID, developer.Email)
	return nil
}

// UpdateDeveloperStatusAdmin updates only the status of a developer (admin version).
func (s *Service) UpdateDeveloperStatusAdmin(ctx context.Context, developerEmail string, status console.UserStatus) (u *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	// Validate status value (0-5 are valid statuses)
	if status < 0 || status > 5 {
		return nil, ErrValidation.New("invalid status value: status must be between 0 (Inactive) and 5 (Pending Bot Verification)")
	}

	// Get developer by email (including unverified/deleted for admin operations)
	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developerEmail)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var developer *console.Developer
	if verified != nil {
		developer = verified
	} else if len(unverified) > 0 {
		developer = &unverified[0]
	} else {
		return nil, ErrEmailNotFound.New("developer with email %q does not exist", developerEmail)
	}

	updateRequest := console.UpdateDeveloperRequest{
		Status: &status,
	}

	err = s.store.Developers().Update(ctx, developer.ID, updateRequest)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Return updated developer
	updatedDeveloper, err := s.store.Developers().Get(ctx, developer.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, "update developer status (admin)", &developer.ID, developer.Email)
	return updatedDeveloper, nil
}
