// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// RegisterMicrosoftBackupResult is returned after microsoft-backup auth stores credentials.
type RegisterMicrosoftBackupResult struct {
	MicrosoftEmail  string
	AccountType     string
	HasRefreshToken bool
}

// RegisterMicrosoftBackupCredential stores Microsoft OAuth tokens in backup_credentials.
// No scope validation or Backup-Tools detect on login/register — UI builds authorize URL with all scopes (Google parity);
// account_type for consumer mail is set locally; org detect uses GET /microsoft-backup/domain-users when needed.
func (s *Service) RegisterMicrosoftBackupCredential(ctx context.Context, microsoftEmail, accessToken, refreshToken, scopeFromExchange string, accessTokenExpiry time.Time, tokenKey string) (result RegisterMicrosoftBackupResult, err error) {
	defer mon.Task()(&ctx)(&err)
	_ = scopeFromExchange
	_ = tokenKey

	result = RegisterMicrosoftBackupResult{
		MicrosoftEmail:  strings.TrimSpace(microsoftEmail),
		HasRefreshToken: strings.TrimSpace(refreshToken) != "" && !looksLikeOAuthJWT(refreshToken),
	}

	if result.MicrosoftEmail == "" {
		return result, Error.New("microsoft email is required")
	}

	user, err := GetUser(ctx)
	if err != nil {
		return result, Error.Wrap(err)
	}

	if !result.HasRefreshToken {
		s.log.Warn("microsoft-backup register: missing or invalid refresh_token; skip credential store",
			zap.String("email", result.MicrosoftEmail),
			zap.Bool("has_access_token", strings.TrimSpace(accessToken) != ""),
		)
		return result, nil
	}

	result.AccountType = InferMicrosoftAccountTypeFromEmail(result.MicrosoftEmail)
	if storeErr := s.StoreMicrosoftBackupCredential(ctx, user.ID, result.MicrosoftEmail, accessToken, refreshToken, accessTokenExpiry, result.AccountType, "", ""); storeErr != nil {
		s.log.Warn("failed to store microsoft backup credentials during registration", zap.Error(storeErr))
	}

	return result, nil
}

// LoadMicrosoftBackupAtLogin returns stored microsoft_backup credentials (no scope validation or BT detect).
func (s *Service) LoadMicrosoftBackupAtLogin(ctx context.Context, sessionToken string) (microsoftBackup map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)
	_ = sessionToken

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	credential, err := s.store.BackupCredentials().GetByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, Error.Wrap(err)
	}

	result := RegisterMicrosoftBackupResult{
		MicrosoftEmail:  credential.Email,
		AccountType:     credential.AccountType,
		HasRefreshToken: strings.TrimSpace(credential.RefreshToken) != "" && !looksLikeOAuthJWT(credential.RefreshToken),
	}
	if result.AccountType == "" && InferMicrosoftAccountTypeFromEmail(credential.Email) != "" {
		result.AccountType = "personal"
	}
	return MicrosoftBackupRegistrationPayload(result), nil
}

func (s *Service) fetchMicrosoftCorporateDomainUsers(ctx context.Context, tokenKey, refreshToken string) (map[string]interface{}, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, ErrValidation.New("refresh token is required")
	}
	body, status, err := s.backupToolsRequestWithHeaders(ctx, http.MethodGet, "/microsoft/outlook/corporate/domain-users", tokenKey, "", refreshToken, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, Error.New("Backup-Tools microsoft domain-users returned status %d: %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// resolveMicrosoftRefreshToken returns a client-supplied refresh token, or loads from backup_credentials.
func (s *Service) resolveMicrosoftRefreshToken(ctx context.Context, refreshToken, microsoftEmail string) (resolved string, credential *BackupCredential, err error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken != "" {
		if looksLikeOAuthJWT(refreshToken) {
			return "", nil, ErrValidation.New("refresh_token looks like an access/id token (JWT); use the OAuth refresh_token from the token response")
		}
		return refreshToken, nil, nil
	}

	user, err := GetUser(ctx)
	if err != nil {
		return "", nil, Error.Wrap(err)
	}

	microsoftEmail = strings.TrimSpace(microsoftEmail)
	if microsoftEmail != "" {
		credential, err = s.store.BackupCredentials().GetByUserIDProviderEmail(ctx, user.ID, BackupProviderMicrosoft, microsoftEmail)
	} else {
		credential, err = s.store.BackupCredentials().GetByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth with a real OAuth refresh_token")
		}
		return "", nil, Error.Wrap(err)
	}
	if err := credential.ValidateForMicrosoftBackup(); err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(credential.RefreshToken), credential, nil
}

// GetMicrosoftBackupDomainUsers loads refresh from DB (or optional header), calls Backup-Tools,
// updates account_type, and returns microsoft_backup payload — same role as GetGoogleBackupDomainUsers.
func (s *Service) GetMicrosoftBackupDomainUsers(ctx context.Context, tokenKey, refreshToken, microsoftEmail string) (microsoftBackup map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, ErrUnauthorized.New("session token is required")
	}

	resolved, credential, err := s.resolveMicrosoftRefreshToken(ctx, refreshToken, microsoftEmail)
	if err != nil {
		return nil, err
	}

	email := strings.TrimSpace(microsoftEmail)
	if credential != nil && email == "" {
		email = credential.Email
	}
	if InferMicrosoftAccountTypeFromEmail(email) == "personal" {
		return microsoftBackupDomainUsersPayload(MicrosoftPersonalBackupDomainUsers(email), ""), nil
	}

	domainUsers, domainErr := s.fetchMicrosoftCorporateDomainUsers(ctx, tokenKey, resolved)
	var domainError string
	if domainErr != nil {
		s.log.Warn("microsoft domain-users call failed", zap.Error(domainErr))
		domainError = domainErr.Error()
	} else if credential != nil {
		if accountType, ok := domainUsers["account_type"].(string); ok && accountType != "" && accountType != credential.AccountType {
			if err := s.store.BackupCredentials().UpdateAccountType(ctx, credential.ID, accountType); err != nil {
				s.log.Warn("failed to update microsoft backup account type from domain-users", zap.Error(err))
			}
		}
		tenantID, tenantName := microsoftTenantFromDomainUsers(domainUsers)
		if tenantID != "" || tenantName != "" {
			if err := s.store.BackupCredentials().UpdateMicrosoftTenant(ctx, credential.ID, tenantID, tenantName); err != nil {
				s.log.Warn("failed to update microsoft backup tenant metadata from domain-users", zap.Error(err))
			}
		}
	}

	return microsoftBackupDomainUsersPayload(domainUsers, domainError), nil
}

func microsoftBackupDomainUsersPayload(domainUsers map[string]interface{}, domainError string) map[string]interface{} {
	if domainUsers != nil {
		out := make(map[string]interface{}, len(domainUsers)+1)
		for k, v := range domainUsers {
			out[k] = v
		}
		if domainError != "" {
			out["domain_users_error"] = domainError
		}
		return out
	}
	if domainError != "" {
		return map[string]interface{}{
			"domain_users_error": domainError,
		}
	}
	return nil
}

// MicrosoftBackupRegistrationPayload is the microsoft_backup block on auth responses.
func MicrosoftBackupRegistrationPayload(result RegisterMicrosoftBackupResult) map[string]interface{} {
	out := make(map[string]interface{})
	if result.MicrosoftEmail != "" {
		out["email"] = result.MicrosoftEmail
	}
	if result.AccountType != "" {
		out["account_type"] = result.AccountType
	}
	out["has_refresh_token"] = result.HasRefreshToken
	return out
}
