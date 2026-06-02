// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

var (
	// ErrCredentialsInvalid indicates Google backup credentials are missing required fields.
	ErrCredentialsInvalid = errs.Class("google backup credentials invalid")

	// ErrReauthRequired indicates the user must re-authenticate with Google OAuth.
	ErrReauthRequired = errs.Class("google backup reauth required")
)

// GoogleBackupCredential stores Google OAuth tokens for backup during registration and onboarding.
type GoogleBackupCredential struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	GoogleEmail       string
	AccessToken       string
	RefreshToken      string
	AccessTokenExpiry *time.Time
	AccountType       string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// GoogleBackupCredentials exposes persistence for Google backup OAuth credentials.
//
// architecture: Database
type GoogleBackupCredentials interface {
	Create(ctx context.Context, credential GoogleBackupCredential) (*GoogleBackupCredential, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*GoogleBackupCredential, error)
	GetByUserIDAndGoogleEmail(ctx context.Context, userID uuid.UUID, googleEmail string) (*GoogleBackupCredential, error)
	UpdateAccountType(ctx context.Context, id uuid.UUID, accountType string) error
	UpdateTokens(ctx context.Context, id uuid.UUID, accessToken, refreshToken string, accessTokenExpiry *time.Time) error
}

// ValidateForBackup checks fields required before Backup-Tools onboarding (access token from DB only).
func (c *GoogleBackupCredential) ValidateForBackup() error {
	if c == nil {
		return ErrCredentialsInvalid.New("credential is nil")
	}
	if c.GoogleEmail == "" {
		return ErrCredentialsInvalid.New("google email is required")
	}
	if c.AccessToken == "" {
		return ErrCredentialsInvalid.New("access token is required")
	}
	return nil
}
