// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
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
	UpdateAccountType(ctx context.Context, id uuid.UUID, accountType string) error
	UpdateTokens(ctx context.Context, id uuid.UUID, accessToken, refreshToken string, accessTokenExpiry *time.Time) error
}
