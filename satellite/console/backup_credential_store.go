// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/StorXNetwork/common/uuid"
)

// MicrosoftCredentialInput is a Microsoft sign-in to store in backup_credentials.
type MicrosoftCredentialInput struct {
	// AccountID is the home-tenant object ID (oid); it identifies the credential.
	AccountID         string
	Email             string
	AccessToken       string
	RefreshToken      string
	AccessTokenExpiry time.Time
	// AccountType, HomeTenantID and HomeTenantName are kept from the stored row when empty.
	AccountType    string
	HomeTenantID   string
	HomeTenantName string
}

// StoreMicrosoftBackupCredential upserts a Microsoft sign-in into shared backup_credentials, keyed by
// the home object ID. One Microsoft sign-in is one credential, whatever tenants it can reach.
func (s *Service) StoreMicrosoftBackupCredential(ctx context.Context, userID uuid.UUID, input MicrosoftCredentialInput) (_ *BackupCredential, err error) {
	defer mon.Task()(&ctx)(&err)

	input.AccountID = strings.ToLower(strings.TrimSpace(input.AccountID))
	input.Email = strings.TrimSpace(input.Email)
	if input.AccountID == "" {
		return nil, ErrValidation.New("microsoft account id (oid) is required")
	}
	if input.Email == "" {
		return nil, ErrValidation.New("microsoft email is required")
	}
	if looksLikeOAuthJWT(input.RefreshToken) {
		return nil, ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
	}

	var expiryPtr *time.Time
	if !input.AccessTokenExpiry.IsZero() {
		expiryPtr = &input.AccessTokenExpiry
	}

	store := s.store.BackupCredentials()
	existing, err := store.GetByUserIDProviderAndAccount(ctx, userID, BackupProviderMicrosoft, input.AccountID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, Error.Wrap(err)
	}

	if existing == nil {
		credentialID, err := uuid.New()
		if err != nil {
			return nil, Error.Wrap(err)
		}
		created, err := store.Create(ctx, BackupCredential{
			ID:                credentialID,
			UserID:            userID,
			Provider:          BackupProviderMicrosoft,
			Email:             input.Email,
			ExternalAccountID: input.AccountID,
			AccessToken:       input.AccessToken,
			RefreshToken:      input.RefreshToken,
			AccessTokenExpiry: expiryPtr,
			AccountType:       input.AccountType,
			TenantID:          input.HomeTenantID,
			TenantName:        input.HomeTenantName,
		})
		return created, Error.Wrap(err)
	}

	accessToken := input.AccessToken
	if accessToken == "" {
		accessToken = existing.AccessToken
	}
	if err := store.UpdateTokens(ctx, existing.ID, accessToken, input.RefreshToken, expiryPtr); err != nil {
		return nil, Error.Wrap(err)
	}
	if !strings.EqualFold(input.Email, existing.Email) {
		if err := store.UpdateEmail(ctx, existing.ID, input.Email); err != nil {
			return nil, Error.Wrap(err)
		}
	}
	if input.AccountType != "" && input.AccountType != existing.AccountType {
		if err := store.UpdateAccountType(ctx, existing.ID, input.AccountType); err != nil {
			return nil, Error.Wrap(err)
		}
	}
	if input.HomeTenantID != "" || input.HomeTenantName != "" {
		if err := store.UpdateMicrosoftTenant(ctx, existing.ID, input.HomeTenantID, input.HomeTenantName); err != nil {
			return nil, Error.Wrap(err)
		}
	}

	updated, err := store.GetByID(ctx, existing.ID)
	return updated, Error.Wrap(err)
}

// updateMicrosoftCredentialTokens stores fresh tokens on an existing credential.
func (s *Service) updateMicrosoftCredentialTokens(ctx context.Context, credential *BackupCredential, accessToken, refreshToken string, accessTokenExpiry time.Time) error {
	if looksLikeOAuthJWT(refreshToken) {
		return ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
	}
	if accessToken == "" {
		accessToken = credential.AccessToken
	}
	var expiryPtr *time.Time
	if !accessTokenExpiry.IsZero() {
		expiryPtr = &accessTokenExpiry
	}
	if err := s.store.BackupCredentials().UpdateTokens(ctx, credential.ID, accessToken, refreshToken, expiryPtr); err != nil {
		return Error.Wrap(err)
	}
	credential.AccessToken = accessToken
	if refreshToken != "" {
		credential.RefreshToken = refreshToken
	}
	credential.AccessTokenExpiry = expiryPtr
	return nil
}

// updateMicrosoftTokensByEmail stores fresh tokens on the user's existing Microsoft credential with this
// email. Without a token carrying `oid` a new credential cannot be created.
func (s *Service) updateMicrosoftTokensByEmail(ctx context.Context, userID uuid.UUID, email, accessToken, refreshToken string, accessTokenExpiry time.Time) error {
	credential, err := s.store.BackupCredentials().GetByUserIDProviderEmail(ctx, userID, BackupProviderMicrosoft, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound.New("microsoft backup credentials not found for %s; connect the Microsoft account first", email)
		}
		return Error.Wrap(err)
	}
	return s.updateMicrosoftCredentialTokens(ctx, credential, accessToken, refreshToken, accessTokenExpiry)
}

func microsoftTenantFromDomainUsers(domainUsers map[string]interface{}) (tenantID, tenantName string) {
	if domainUsers == nil {
		return "", ""
	}
	if v, ok := domainUsers["tenant_id"].(string); ok {
		tenantID = strings.TrimSpace(v)
	}
	if v, ok := domainUsers["tenant_name"].(string); ok {
		tenantName = strings.TrimSpace(v)
	}
	return tenantID, tenantName
}
