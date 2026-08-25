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

// StoreMicrosoftBackupCredential upserts Microsoft OAuth tokens into shared backup_credentials.
func (s *Service) StoreMicrosoftBackupCredential(ctx context.Context, userID uuid.UUID, email, accessToken, refreshToken string, accessTokenExpiry time.Time, accountType, tenantID, tenantName string) error {
	return s.storeBackupCredential(ctx, userID, BackupProviderMicrosoft, email, accessToken, refreshToken, accessTokenExpiry, accountType, tenantID, tenantName)
}

func (s *Service) storeBackupCredential(ctx context.Context, userID uuid.UUID, provider, email, accessToken, refreshToken string, accessTokenExpiry time.Time, accountType, tenantID, tenantName string) error {
	provider = strings.TrimSpace(strings.ToLower(provider))
	email = strings.TrimSpace(email)
	if provider == "" || email == "" {
		return ErrValidation.New("provider and email are required")
	}
	if looksLikeOAuthJWT(refreshToken) {
		return ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
	}

	var expiryPtr *time.Time
	if !accessTokenExpiry.IsZero() {
		expiryPtr = &accessTokenExpiry
	}

	existing, err := s.store.BackupCredentials().GetByUserIDProviderEmail(ctx, userID, provider, email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Error.Wrap(err)
	}

	if existing != nil {
		if accessToken == "" {
			accessToken = existing.AccessToken
		}
		if err := s.store.BackupCredentials().UpdateTokens(ctx, existing.ID, accessToken, refreshToken, expiryPtr); err != nil {
			return Error.Wrap(err)
		}
		if accountType != "" && accountType != existing.AccountType {
			if err := s.store.BackupCredentials().UpdateAccountType(ctx, existing.ID, accountType); err != nil {
				return Error.Wrap(err)
			}
		}
		if tenantID != "" || tenantName != "" {
			if err := s.store.BackupCredentials().UpdateMicrosoftTenant(ctx, existing.ID, tenantID, tenantName); err != nil {
				return Error.Wrap(err)
			}
		}
		return nil
	}

	credentialID, err := uuid.New()
	if err != nil {
		return Error.Wrap(err)
	}
	_, err = s.store.BackupCredentials().Create(ctx, BackupCredential{
		ID:                credentialID,
		UserID:            userID,
		Provider:          provider,
		Email:             email,
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AccessTokenExpiry: expiryPtr,
		AccountType:       accountType,
		TenantID:          tenantID,
		TenantName:        tenantName,
	})
	return Error.Wrap(err)
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
