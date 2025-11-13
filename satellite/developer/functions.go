// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"storj.io/common/http/requestid"
	"storj.io/common/uuid"
	"storj.io/storj/private/post"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleauth"
)

// CreateUserFromDeveloper creates User without password and active state.
// NOTE: This function is currently unused but kept for potential future use.
// If not needed, it can be removed.
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
	if err != nil {
		s.log.Warn("Failed to get developer by email during login",
			zap.String("email", request.Email),
			zap.Error(err),
		)
		mon.Counter("login_email_invalid_developer").Inc(1) //mon:locked
		s.auditLog(ctx, "login: failed database error", nil, request.Email)
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

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
			// Check if there's a developer with ResetPass status in unverified list
			for _, usr := range nonActiveDevelopers {
				if usr.Status == console.ResetPass {
					shouldProceed = true
					developer = &usr
					s.log.Info("Found developer with ResetPass status in unverified list",
						zap.String("email", request.Email),
						zap.String("developerID", developer.ID.String()),
						zap.Int("status", int(developer.Status)),
					)
					break
				}
			}

			if !shouldProceed {
				if len(nonActiveDevelopers) > 0 {
					s.log.Warn("Login failed: developer found but status not allowed",
						zap.String("email", request.Email),
						zap.Int("unverifiedCount", len(nonActiveDevelopers)),
						zap.Any("statuses", func() []int {
							statuses := make([]int, len(nonActiveDevelopers))
							for i, u := range nonActiveDevelopers {
								statuses[i] = int(u.Status)
							}
							return statuses
						}()),
					)
					mon.Counter("login_email_unverified_developer").Inc(1) //mon:locked
					s.auditLog(ctx, "login: failed email unverified", nil, request.Email)
				} else {
					s.log.Warn("Login failed: developer not found by email",
						zap.String("email", request.Email),
					)
					mon.Counter("login_email_invalid_developer").Inc(1) //mon:locked
					s.auditLog(ctx, "login: failed invalid email", nil, request.Email)
				}
				return nil, ErrLoginCredentials.New(credentialsErrMsg)
			}
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

	// Handle ResetPass status (6) - allow one-time login with default credentials
	// After first login, developer must reset password before accessing console
	if developer.Status == console.ResetPass {
		// Generate a short-lived session token that indicates password reset is required
		// The frontend should redirect to reset password page
		var customDurationPtr *time.Duration
		shortDuration := 15 * time.Minute // Short duration for reset password flow
		customDurationPtr = &shortDuration

		response, err = s.GenerateSessionTokenForDeveloper(ctx, developer.ID, developer.Email, request.IP, customDurationPtr)
		if err != nil {
			return nil, err
		}

		mon.Counter("login_success_developer_reset_required").Inc(1) //mon:locked
		s.auditLog(ctx, "login: password reset required", &developer.ID, developer.Email)

		// Return response - frontend should check status and redirect to reset password
		return response, nil
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

// VerifyTokenForDeveloper verifies a JWT token from email link and returns developer info.
func (s *Service) VerifyTokenForDeveloper(ctx context.Context, tokenString string) (developer *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	token, err := consoleauth.FromBase64URLString(tokenString)
	if err != nil {
		return nil, ErrTokenExpiration.New("invalid token format")
	}

	valid, err := s.tokens.ValidateToken(token)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !valid {
		return nil, ErrTokenExpiration.New("invalid token signature")
	}

	claims, err := consoleauth.FromJSON(token.Payload)
	if err != nil {
		return nil, ErrTokenExpiration.New("invalid token payload")
	}

	// Check if token is expired
	if !claims.Expiration.IsZero() && claims.Expiration.Before(time.Now()) {
		return nil, ErrTokenExpiration.New("token has expired")
	}

	// Get developer by ID
	developer, err = s.store.Developers().Get(ctx, claims.ID)
	if err != nil {
		// Log the error for debugging
		s.log.Warn("Developer not found by ID from token",
			zap.String("developerID", claims.ID.String()),
			zap.String("email", claims.Email),
			zap.Error(err),
		)
		// Try to find by email as fallback (in case ID mismatch or database connection issue)
		if claims.Email != "" {
			verified, unverified, err2 := s.store.Developers().GetByEmailWithUnverified(ctx, claims.Email)
			if err2 != nil {
				s.log.Warn("Failed to find developer by email as fallback",
					zap.String("email", claims.Email),
					zap.Error(err2),
				)
			}
			if verified != nil {
				s.log.Info("Found developer by email (verified), but ID mismatch",
					zap.String("tokenID", claims.ID.String()),
					zap.String("dbID", verified.ID.String()),
					zap.String("email", claims.Email),
					zap.Int("status", int(verified.Status)),
				)
				// Use the developer found by email
				developer = verified
			} else if len(unverified) > 0 {
				// Found unverified developer(s) - use the first one
				s.log.Info("Found developer by email (unverified), but ID mismatch",
					zap.String("tokenID", claims.ID.String()),
					zap.String("dbID", unverified[0].ID.String()),
					zap.String("email", claims.Email),
					zap.Int("status", int(unverified[0].Status)),
				)
				developer = &unverified[0]
			} else {
				s.log.Error("Developer not found by ID or email - possible database connection mismatch",
					zap.String("tokenID", claims.ID.String()),
					zap.String("email", claims.Email),
					zap.Error(err),
				)
				return nil, ErrEmailNotFound.New("developer not found by ID %s or email %s. Please verify the developer exists in the database and that admin and developer processes are using the same database connection.", claims.ID.String(), claims.Email)
			}
		} else {
			return nil, ErrEmailNotFound.New("developer not found by ID %s", claims.ID.String())
		}
	}

	// Verify email matches if provided in token
	if claims.Email != "" && claims.Email != developer.Email {
		return nil, ErrTokenExpiration.New("token email mismatch")
	}

	// Only allow reset for developers with ResetPass status
	if developer.Status != console.ResetPass {
		return nil, ErrValidation.New("developer account is not in reset password status")
	}

	return developer, nil
}

// ResetPasswordWithToken resets developer password using JWT token and sets status to Active.
func (s *Service) ResetPasswordWithToken(ctx context.Context, tokenString, newPassword string) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Verify token and get developer
	developer, err := s.VerifyTokenForDeveloper(ctx, tokenString)
	if err != nil {
		return Error.Wrap(err)
	}

	// Validate new password
	if err := console.ValidateNewPassword(newPassword); err != nil {
		return ErrValidation.Wrap(err)
	}

	// Check if new password is the same as current password
	err = bcrypt.CompareHashAndPassword(developer.PasswordHash, []byte(newPassword))
	if err == nil {
		return ErrValidation.New("new password must be different from your current temporary password")
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.config.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	// Update password and set status to Active
	activeStatus := console.Active
	err = s.store.Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		PasswordHash: hash,
		Status:       &activeStatus,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	// Delete all existing sessions to force re-login
	_, err = s.store.WebappSessionDevelopers().DeleteAllByDeveloperId(ctx, developer.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "reset password with token", &developer.ID, developer.Email)
	mon.Counter("developer_password_reset_success").Inc(1) //mon:locked

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
		Description:  req.Description,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		Status:       1, // active
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	created, err := s.store.DeveloperOAuthClients().Insert(ctx, client)
	if err != nil {
		return nil, err
	}
	// Encode secret as base64 for safe display
	created.ClientSecret = base64.URLEncoding.EncodeToString(clientSecret) // Return plaintext only once
	return created, nil
}

// ListDeveloperOAuthClients lists all OAuth clients for the current developer.
func (s *Service) ListDeveloperOAuthClients(ctx context.Context) ([]console.DeveloperOAuthClient, error) {
	developerID, err := s.getDeveloperAndAuditLog(ctx, "list developer oauth clients")
	if err != nil {
		return nil, err
	}

	clients, err := s.store.DeveloperOAuthClients().ListByDeveloperID(ctx, developerID.ID)
	if err != nil {
		return nil, err
	}
	// Never return secrets in list
	for i := range clients {
		clients[i].ClientSecret = ""
	}
	return clients, nil
}

// GetDeveloperOAuthClient gets a single OAuth client by ID.
func (s *Service) GetDeveloperOAuthClient(ctx context.Context, id uuid.UUID) (*console.DeveloperOAuthClient, error) {
	defer mon.Task()(&ctx)(nil)

	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, id)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, errs.New("client does not belong to developer")
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	client.ClientSecret = "" // Never return secret
	return client, nil
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

// RegenerateDeveloperOAuthClientSecret generates a new client secret for an OAuth client.
func (s *Service) RegenerateDeveloperOAuthClientSecret(ctx context.Context, id uuid.UUID) (*console.DeveloperOAuthClient, error) {
	defer mon.Task()(&ctx)(nil)

	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, id)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, errs.New("client does not belong to developer")
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, id)
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

	client.ClientSecret = string(hashedSecret)
	client.UpdatedAt = time.Now().UTC()
	err = s.store.DeveloperOAuthClients().Update(ctx, id, client)
	if err != nil {
		return nil, err
	}

	developerID, err := s.getDeveloperAndAuditLog(ctx, "regenerate developer oauth client secret", zap.String("clientID", client.ClientID))
	if err == nil {
		s.auditLog(ctx, "regenerate developer oauth client secret", &developerID.ID, "")
	}

	// Encode secret as base64 for safe display
	client.ClientSecret = base64.URLEncoding.EncodeToString(clientSecret) // Return plaintext only once
	return client, nil
}

// UpdateDeveloperOAuthClient updates an OAuth client.
func (s *Service) UpdateDeveloperOAuthClient(ctx context.Context, id uuid.UUID, req console.UpdateOAuthClientRequest) (*console.DeveloperOAuthClient, error) {
	defer mon.Task()(&ctx)(nil)

	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, id)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, errs.New("client does not belong to developer")
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.Description != nil {
		client.Description = *req.Description
	}
	if req.RedirectURIs != nil {
		client.RedirectURIs = *req.RedirectURIs
	}
	if req.Scopes != nil {
		client.Scopes = *req.Scopes
	}
	client.UpdatedAt = time.Now().UTC()

	err = s.store.DeveloperOAuthClients().Update(ctx, id, client)
	if err != nil {
		return nil, err
	}

	developerID, err := s.getDeveloperAndAuditLog(ctx, "update developer oauth client", zap.String("clientID", client.ClientID))
	if err == nil {
		s.auditLog(ctx, "update developer oauth client", &developerID.ID, "")
	}

	client.ClientSecret = "" // Never return secret
	return client, nil
}

// validateRedirectURI validates a redirect URI format and security requirements.
func validateRedirectURI(uri string) error {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return errs.New("redirect URI cannot be empty")
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		return errs.New("invalid URL format: %v", err)
	}

	// Check if HTTPS (required for production) or localhost (allowed for development)
	if parsedURL.Scheme != "https" {
		// Allow HTTP only for localhost
		if parsedURL.Scheme != "http" || (parsedURL.Hostname() != "localhost" && parsedURL.Hostname() != "127.0.0.1") {
			return errs.New("production URLs must use HTTPS. Only localhost is allowed for HTTP")
		}
	}

	return nil
}

// AddRedirectURI adds a redirect URI to an OAuth client.
func (s *Service) AddRedirectURI(ctx context.Context, clientID uuid.UUID, uri string) (*console.DeveloperOAuthClient, error) {
	defer mon.Task()(&ctx)(nil)

	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, errs.New("client does not belong to developer")
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Validate URI
	if err := validateRedirectURI(uri); err != nil {
		return nil, err
	}

	// Check for duplicates (case-insensitive)
	uriLower := strings.ToLower(strings.TrimSpace(uri))
	for _, existingURI := range client.RedirectURIs {
		if strings.ToLower(strings.TrimSpace(existingURI)) == uriLower {
			return nil, errs.New("redirect URI already exists")
		}
	}

	// Add the URI
	client.RedirectURIs = append(client.RedirectURIs, strings.TrimSpace(uri))
	client.UpdatedAt = time.Now().UTC()

	err = s.store.DeveloperOAuthClients().Update(ctx, clientID, client)
	if err != nil {
		return nil, err
	}

	developerID, err := s.getDeveloperAndAuditLog(ctx, "add redirect URI", zap.String("clientID", client.ClientID), zap.String("uri", uri))
	if err == nil {
		s.auditLog(ctx, "add redirect URI", &developerID.ID, "")
	}

	client.ClientSecret = "" // Never return secret
	return client, nil
}

// UpdateRedirectURI updates a redirect URI in an OAuth client.
func (s *Service) UpdateRedirectURI(ctx context.Context, clientID uuid.UUID, oldURI, newURI string) (*console.DeveloperOAuthClient, error) {
	defer mon.Task()(&ctx)(nil)

	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, errs.New("client does not belong to developer")
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Validate new URI
	if err := validateRedirectURI(newURI); err != nil {
		return nil, err
	}

	// Find and update the URI
	oldURILower := strings.ToLower(strings.TrimSpace(oldURI))
	newURILower := strings.ToLower(strings.TrimSpace(newURI))
	found := false

	for i, existingURI := range client.RedirectURIs {
		if strings.ToLower(strings.TrimSpace(existingURI)) == oldURILower {
			// Check if new URI is duplicate (excluding the one being updated)
			for j, otherURI := range client.RedirectURIs {
				if i != j && strings.ToLower(strings.TrimSpace(otherURI)) == newURILower {
					return nil, errs.New("redirect URI already exists")
				}
			}
			client.RedirectURIs[i] = strings.TrimSpace(newURI)
			found = true
			break
		}
	}

	if !found {
		return nil, errs.New("redirect URI not found")
	}

	client.UpdatedAt = time.Now().UTC()

	err = s.store.DeveloperOAuthClients().Update(ctx, clientID, client)
	if err != nil {
		return nil, err
	}

	developerID, err := s.getDeveloperAndAuditLog(ctx, "update redirect URI", zap.String("clientID", client.ClientID), zap.String("oldURI", oldURI), zap.String("newURI", newURI))
	if err == nil {
		s.auditLog(ctx, "update redirect URI", &developerID.ID, "")
	}

	client.ClientSecret = "" // Never return secret
	return client, nil
}

// DeleteRedirectURI removes a redirect URI from an OAuth client.
func (s *Service) DeleteRedirectURI(ctx context.Context, clientID uuid.UUID, uri string) (*console.DeveloperOAuthClient, error) {
	defer mon.Task()(&ctx)(nil)

	isOwner, err := s.isCurrentDeveloperOAuthClientOwner(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, errs.New("client does not belong to developer")
	}

	client, err := s.store.DeveloperOAuthClients().GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Check if at least one URI will remain
	if len(client.RedirectURIs) <= 1 {
		return nil, errs.New("cannot delete the last redirect URI. At least one redirect URI is required")
	}

	// Find and remove the URI
	uriLower := strings.ToLower(strings.TrimSpace(uri))
	found := false
	newURIs := make([]string, 0, len(client.RedirectURIs))

	for _, existingURI := range client.RedirectURIs {
		if strings.ToLower(strings.TrimSpace(existingURI)) == uriLower {
			found = true
			continue // Skip this URI
		}
		newURIs = append(newURIs, existingURI)
	}

	if !found {
		return nil, errs.New("redirect URI not found")
	}

	client.RedirectURIs = newURIs
	client.UpdatedAt = time.Now().UTC()

	err = s.store.DeveloperOAuthClients().Update(ctx, clientID, client)
	if err != nil {
		return nil, err
	}

	developerID, err := s.getDeveloperAndAuditLog(ctx, "delete redirect URI", zap.String("clientID", client.ClientID), zap.String("uri", uri))
	if err == nil {
		s.auditLog(ctx, "delete redirect URI", &developerID.ID, "")
	}

	client.ClientSecret = "" // Never return secret
	return client, nil
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

	// Check if email already exists
	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developer.Email)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if verified != nil || len(unverified) > 0 {
		mon.Counter("create_developer_duplicate_verified").Inc(1) //mon:locked
		return nil, ErrEmailUsed.New(emailUsedErrMsg)
	}

	// Generate password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(developer.Password), s.config.PasswordCost)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Generate developer ID
	developerID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Create developer with ResetPass status
	status := console.ResetPass
	newDeveloper := &console.Developer{
		ID:           developerID,
		FullName:     developer.FullName,
		Email:        developer.Email,
		PasswordHash: hash,
		Status:       status,
		CompanyName:  developer.CompanyName,
	}

	// Insert developer
	u, err = s.store.Developers().Insert(ctx, newDeveloper)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Update status to ResetPass (required because status field has 'autoinsert' tag)
	err = s.store.Developers().Update(ctx, u.ID, console.UpdateDeveloperRequest{
		Status: &status,
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Set status on returned object
	u.Status = console.ResetPass

	// Send activation email if mail service is configured
	if s.mailService != nil && s.externalAddress != "" {
		token, err := s.tokens.CreateToken(ctx, u.ID, u.Email)
		if err == nil {
			activationLink := s.externalAddress + "login?token=" + token
			s.mailService.SendRenderedAsync(
				ctx,
				[]post.Address{{Address: u.Email, Name: u.FullName}},
				&console.DeveloperAccountCreationEmail{
					FullName:       u.FullName,
					Email:          u.Email,
					Password:       developer.Password,
					ActivationLink: activationLink,
					Origin:         s.externalAddress,
				},
			)
		}
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
		if statusValue < 0 || statusValue > 6 {
			return nil, ErrValidation.New("invalid status value: status must be between 0 (Inactive) and 6 (Reset Password)")
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

	// Validate status value (0-6 are valid statuses)
	if status < 0 || status > 6 {
		return nil, ErrValidation.New("invalid status value: status must be between 0 (Inactive) and 6 (Reset Password)")
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
