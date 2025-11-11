// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developerservice

import (
	"context"
	"crypto/rand"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleauth"
)

var mon = monkit.Package()

// Error messages.
const (
	emailUsedErrMsg      = "This email is already in use, try another"
	emailNotFoundErrMsg  = "There are no users with the specified email"
	credentialsErrMsg    = "Your login credentials are incorrect, please try again"
	changePasswordErrMsg = "Your old password is incorrect, please try again"
)

var (
	// Error describes internal developer service error.
	Error = errs.Class("developer service")

	// ErrEmailUsed is error type that occurs on repeating auth attempts with email.
	ErrEmailUsed = errs.Class("email used")

	// ErrEmailNotFound occurs when no developers have the specified email.
	ErrEmailNotFound = errs.Class("email not found")

	// ErrLoginCredentials occurs when provided invalid login credentials.
	ErrLoginCredentials = errs.Class("login credentials")

	// ErrChangePassword occurs when provided old password is incorrect.
	ErrChangePassword = errs.Class("change password")

	// ErrTokenExpiration is error type of token reached expiration time.
	ErrTokenExpiration = errs.Class("token expiration")

	// ErrLoginRestricted occurs when a developer with PendingBotVerification or LegalHold status tries to log in.
	ErrLoginRestricted = errs.Class("user can't be authenticated")

	// ErrValidation is error type for validation errors.
	ErrValidation = errs.Class("validation")

	// ErrRegToken describes registration token errors.
	ErrRegToken = errs.Class("registration token")
)

// RegistrationTokenChecker is an interface for checking registration tokens.
type RegistrationTokenChecker interface {
	CheckRegistrationSecret(ctx context.Context, tokenSecret console.RegistrationSecret) (*console.RegistrationToken, error)
}

// Service handles developer-related logic.
//
// architecture: Service
type Service struct {
	log, auditLogger *zap.Logger
	store            console.DB
	analytics        *analytics.Service
	tokens           *consoleauth.Service
	config           console.Config
	regTokenChecker  RegistrationTokenChecker
}

// NewService returns a new instance of Service.
func NewService(
	log *zap.Logger,
	store console.DB,
	analytics *analytics.Service,
	tokens *consoleauth.Service,
	config console.Config,
	regTokenChecker RegistrationTokenChecker,
) (*Service, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if store == nil {
		return nil, errs.New("store can't be nil")
	}
	if config.PasswordCost == 0 {
		config.PasswordCost = bcrypt.DefaultCost
	}

	return &Service{
		log:             log,
		auditLogger:     log.Named("auditlog"),
		store:           store,
		analytics:       analytics,
		tokens:          tokens,
		config:          config,
		regTokenChecker: regTokenChecker,
	}, nil
}

// getRequestingIP extracts IP from context.
func getRequestingIP(ctx context.Context) (source, forwardedFor string) {
	if req := console.GetRequest(ctx); req != nil {
		return req.RemoteAddr, req.Header.Get("X-Forwarded-For")
	}
	return "", ""
}

// auditLog logs an operation to the audit logger.
func (s *Service) auditLog(ctx context.Context, operation string, developerID *uuid.UUID, email string, extra ...zap.Field) {
	fields := make([]zap.Field, 0, len(extra)+4)
	fields = append(fields,
		zap.String("operation", operation),
		zap.String("developer", "true"),
	)
	if developerID != nil {
		fields = append(fields, zap.Stringer("developerID", *developerID))
	}
	if email != "" {
		fields = append(fields, zap.String("email", email))
	}
	sourceIP, forwardedForIP := getRequestingIP(ctx)
	if sourceIP != "" {
		fields = append(fields, zap.String("source-ip", sourceIP))
	}
	if forwardedForIP != "" {
		fields = append(fields, zap.String("forwarded-for-ip", forwardedForIP))
	}
	fields = append(fields, extra...)
	s.auditLogger.Info("developer activity", fields...)
}

// getDeveloperAndAuditLog gets Developer from context and logs the operation.
func (s *Service) getDeveloperAndAuditLog(ctx context.Context, operation string, extra ...zap.Field) (*console.Developer, error) {
	developer, err := console.GetDeveloper(ctx)
	if err != nil {
		sourceIP, forwardedForIP := getRequestingIP(ctx)
		s.auditLogger.Info("developer activity unauthorized",
			append(append(
				make([]zap.Field, 0, len(extra)+4),
				zap.String("developer", "true"),
				zap.String("operation", operation),
				zap.Error(err),
				zap.String("source-ip", sourceIP),
				zap.String("forwarded-for-ip", forwardedForIP),
			), extra...)...)
		return nil, err
	}
	s.auditLog(ctx, operation, &developer.ID, developer.Email, extra...)
	return developer, nil
}

// generateRandomSecret generates a random secret of the specified length.
func generateRandomSecret(length int) ([]byte, error) {
	secret := make([]byte, length)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// hashSecret hashes a secret using bcrypt (for OAuth client secrets).
func hashSecret(secret []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// GetLoginAttemptsWithoutPenalty returns the login attempts without penalty from config.
func (s *Service) GetLoginAttemptsWithoutPenalty() int {
	return s.config.LoginAttemptsWithoutPenalty
}
