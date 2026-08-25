// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

const (
	// BackupProviderGoogle is stored in backup_credentials.provider for Google Backup.
	BackupProviderGoogle = "google"
	// BackupProviderMicrosoft is stored in backup_credentials.provider for Microsoft Backup.
	BackupProviderMicrosoft = "microsoft"
)

var (
	// ErrCredentialsInvalid indicates backup credentials are missing required fields.
	ErrCredentialsInvalid = errs.Class("backup credentials invalid")

	// ErrReauthRequired indicates the user must re-authenticate with the provider OAuth.
	ErrReauthRequired = errs.Class("backup reauth required")
)

// BackupCredential stores OAuth tokens for Google or Microsoft backup (shared table).
type BackupCredential struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	Provider          string
	Email             string
	AccessToken       string
	RefreshToken      string
	AccessTokenExpiry *time.Time
	AccountType       string
	TenantID          string
	TenantName        string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// GoogleEmail is a compatibility alias used by existing Google Backup call sites.
func (c *BackupCredential) GoogleEmail() string {
	if c == nil {
		return ""
	}
	return c.Email
}

// BackupCredentials exposes persistence for shared backup OAuth credentials.
//
// architecture: Database
type BackupCredentials interface {
	Create(ctx context.Context, credential BackupCredential) (*BackupCredential, error)
	GetByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (*BackupCredential, error)
	GetByUserIDProviderEmail(ctx context.Context, userID uuid.UUID, provider, email string) (*BackupCredential, error)
	UpdateAccountType(ctx context.Context, id uuid.UUID, accountType string) error
	UpdateMicrosoftTenant(ctx context.Context, id uuid.UUID, tenantID, tenantName string) error
	UpdateTokens(ctx context.Context, id uuid.UUID, accessToken, refreshToken string, accessTokenExpiry *time.Time) error
	ClearTokens(ctx context.Context, id uuid.UUID) error
}

// GoogleBackupCredential is kept as an alias type name for Google-facing docs/callers.
// Prefer BackupCredential + BackupProviderGoogle for new code.
type GoogleBackupCredential = BackupCredential

// GoogleBackupCredentials is a compatibility alias for the shared BackupCredentials store.
type GoogleBackupCredentials = BackupCredentials

// ValidateForBackup checks fields required before Backup-Tools onboarding.
func (c *BackupCredential) ValidateForBackup() error {
	if c == nil {
		return ErrCredentialsInvalid.New("credential is nil")
	}
	if strings.TrimSpace(c.Email) == "" {
		return ErrCredentialsInvalid.New("email is required")
	}
	if strings.TrimSpace(c.AccessToken) == "" && strings.TrimSpace(c.RefreshToken) == "" {
		return ErrCredentialsInvalid.New("access token or refresh token is required")
	}
	return nil
}

// ValidateForMicrosoftBackup requires a non-JWT refresh token for Backup-Tools cron.
func (c *BackupCredential) ValidateForMicrosoftBackup() error {
	if err := c.ValidateForBackup(); err != nil {
		return err
	}
	refresh := strings.TrimSpace(c.RefreshToken)
	if refresh == "" {
		return ErrCredentialsInvalid.New("microsoft refresh token is required")
	}
	if looksLikeOAuthJWT(refresh) {
		return ErrCredentialsInvalid.New("microsoft refresh token looks like an access/id token (JWT); re-authenticate with offline_access")
	}
	return nil
}

func looksLikeOAuthJWT(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	return strings.HasPrefix(token, "eyJ") && strings.Count(token, ".") == 2
}
