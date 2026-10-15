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

// MicrosoftBackupSignIn is the Microsoft identity and tokens from a microsoft-backup OAuth sign-in.
type MicrosoftBackupSignIn struct {
	// AccountID is the home-tenant object ID (oid); it identifies the stored credential.
	AccountID string
	Email     string
	// TenantID is the home tenant (tid) of the sign-in.
	TenantID          string
	AccessToken       string
	RefreshToken      string
	AccessTokenExpiry time.Time
}

// RegisterMicrosoftBackupResult is returned after microsoft-backup auth stores credentials.
type RegisterMicrosoftBackupResult struct {
	// CredentialID is the stored backup_credentials ID, used to select this account later.
	CredentialID string
	// Created is true when this sign-in stored a new credential (not an update).
	Created         bool
	MicrosoftEmail  string
	AccountType     string
	TenantID        string
	TenantName      string
	HasRefreshToken bool
	// Detection is the Backup-Tools account detection contract (is_admin, admin_roles, ...), when called.
	Detection      map[string]interface{}
	DetectionError string
}

// RegisterMicrosoftBackupCredential stores the Microsoft tokens in backup_credentials and classifies the
// account through Backup-Tools account detection (same role as RegisterGoogleBackupCredential calling
// domain-users), which reports personal vs work/school, the tenant, and admin roles.
// Detection never grants admin_workspace; only admin consent does.
func (s *Service) RegisterMicrosoftBackupCredential(ctx context.Context, signIn MicrosoftBackupSignIn, tokenKey string) (result RegisterMicrosoftBackupResult, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return result, Error.Wrap(err)
	}
	return s.storeMicrosoftSignIn(ctx, user, signIn, tokenKey)
}

func (s *Service) storeMicrosoftSignIn(ctx context.Context, user *User, signIn MicrosoftBackupSignIn, tokenKey string) (result RegisterMicrosoftBackupResult, err error) {
	signIn.AccountID = strings.ToLower(strings.TrimSpace(signIn.AccountID))
	signIn.Email = strings.TrimSpace(signIn.Email)
	signIn.TenantID = strings.TrimSpace(signIn.TenantID)
	signIn.RefreshToken = strings.TrimSpace(signIn.RefreshToken)

	result = RegisterMicrosoftBackupResult{
		MicrosoftEmail:  signIn.Email,
		TenantID:        signIn.TenantID,
		HasRefreshToken: signIn.RefreshToken != "" && !looksLikeOAuthJWT(signIn.RefreshToken),
	}
	if result.MicrosoftEmail == "" {
		return result, Error.New("microsoft email is required")
	}
	if signIn.AccountID == "" {
		return result, Error.New("microsoft account id (oid) is required")
	}

	if !result.HasRefreshToken {
		s.log.Warn("microsoft-backup register: missing or invalid refresh_token; skip credential store",
			zap.String("email", result.MicrosoftEmail),
			zap.Bool("has_access_token", strings.TrimSpace(signIn.AccessToken) != ""),
		)
		return result, nil
	}

	existing, err := s.store.BackupCredentials().GetByUserIDProviderAndAccount(ctx, user.ID, BackupProviderMicrosoft, signIn.AccountID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, Error.Wrap(err)
	}
	existingAccountType := ""
	if existing != nil {
		existingAccountType = existing.AccountType
		if result.TenantID == "" {
			result.TenantID = existing.TenantID
		}
		result.TenantName = existing.TenantName
	}

	detection, detectErr := s.detectMicrosoftAccount(ctx, tokenKey, signIn.RefreshToken, microsoftBackupToolsHeaders(&BackupCredential{
		ExternalAccountID: signIn.AccountID,
		TenantID:          result.TenantID,
	}, ""))
	if detectErr != nil {
		s.log.Warn("microsoft-backup: Backup-Tools account detection failed", zap.String("email", result.MicrosoftEmail), zap.Error(detectErr))
		result.DetectionError = detectErr.Error()
	} else {
		result.Detection = detection
		result.AccountType, _ = detection["account_type"].(string)
		tenantID, tenantName := microsoftTenantFromDomainUsers(detection)
		if tenantID != "" {
			result.TenantID = tenantID
		}
		if tenantName != "" {
			result.TenantName = tenantName
		}
	}
	result.AccountType = microsoftAccountTypeFromDetection(result.AccountType, existingAccountType)
	if result.AccountType == MicrosoftAccountTypePersonal {
		result.TenantID, result.TenantName = "", ""
	}

	stored, err := s.StoreMicrosoftBackupCredential(ctx, user.ID, MicrosoftCredentialInput{
		AccountID:         signIn.AccountID,
		Email:             result.MicrosoftEmail,
		AccessToken:       signIn.AccessToken,
		RefreshToken:      signIn.RefreshToken,
		AccessTokenExpiry: signIn.AccessTokenExpiry,
		AccountType:       result.AccountType,
		HomeTenantID:      result.TenantID,
		HomeTenantName:    result.TenantName,
	})
	if err != nil {
		return result, err
	}
	result.CredentialID = stored.ID.String()
	result.Created = existing == nil
	return result, nil
}

// detectMicrosoftAccount calls Backup-Tools GET /microsoft/account/detect with the delegated refresh token
// and the Microsoft credential/tenant headers.
func (s *Service) detectMicrosoftAccount(ctx context.Context, tokenKey, refreshToken string, headers map[string]string) (map[string]interface{}, error) {
	if strings.TrimSpace(tokenKey) == "" {
		return nil, ErrUnauthorized.New("session token is required for account detection")
	}
	return s.getMicrosoftAccountJSON(ctx, "/microsoft/account/detect", "account detection", tokenKey, refreshToken, headers)
}

// getMicrosoftAccountJSON GETs a Backup-Tools Microsoft account route with the delegated refresh token.
func (s *Service) getMicrosoftAccountJSON(ctx context.Context, path, what, tokenKey, refreshToken string, headers map[string]string) (map[string]interface{}, error) {
	body, status, err := s.backupToolsRequestWithExtraHeaders(ctx, http.MethodGet, path, tokenKey, "", refreshToken, headers, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, Error.New("Backup-Tools microsoft %s returned status %d: %s", what, status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, Error.Wrap(err)
	}
	return result, nil
}

// LoadMicrosoftBackupAtLogin returns stored microsoft_backup credentials (no scope validation or BT detect).
func (s *Service) LoadMicrosoftBackupAtLogin(ctx context.Context) (microsoftBackup map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Without fresh tokens the signed-in account is unknown: report the most recently used one,
	// plus all accounts so the UI can select by credential_id.
	credentials, err := s.store.BackupCredentials().ListByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	credential := latestMicrosoftCredential(credentials)
	if credential == nil {
		return nil, nil
	}

	result := RegisterMicrosoftBackupResult{
		CredentialID:    credential.ID.String(),
		MicrosoftEmail:  credential.Email,
		AccountType:     credential.AccountType,
		TenantID:        credential.HomeTenantID(),
		TenantName:      credential.HomeTenantName(),
		HasRefreshToken: hasUsableRefreshToken(credential),
	}
	payload := MicrosoftBackupRegistrationPayload(result)
	accounts := make([]MicrosoftBackupAccount, 0, len(credentials))
	for i := range credentials {
		accounts = append(accounts, microsoftBackupAccountFromCredential(&credentials[i]))
	}
	payload["accounts"] = accounts
	return payload, nil
}

func (s *Service) fetchMicrosoftCorporateDomainUsers(ctx context.Context, tokenKey, refreshToken string, headers map[string]string) (map[string]interface{}, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, ErrValidation.New("refresh token is required")
	}
	return s.getMicrosoftAccountJSON(ctx, "/microsoft/outlook/corporate/domain-users", "domain-users", tokenKey, refreshToken, headers)
}

// resolveMicrosoftRefreshToken returns a client-supplied refresh token, or the stored token of the
// Microsoft credential selected by credentialID (or microsoftEmail, or the only credential).
func (s *Service) resolveMicrosoftRefreshToken(ctx context.Context, refreshToken, credentialID, microsoftEmail string) (resolved string, credential *BackupCredential, err error) {
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

	credentialID = strings.TrimSpace(credentialID)
	microsoftEmail = strings.TrimSpace(microsoftEmail)
	if credentialID == "" && microsoftEmail != "" {
		credential, err = s.store.BackupCredentials().GetByUserIDProviderEmail(ctx, user.ID, BackupProviderMicrosoft, microsoftEmail)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", nil, ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth with a real OAuth refresh_token")
			}
			return "", nil, Error.Wrap(err)
		}
	} else {
		credential, err = s.resolveMicrosoftCredential(ctx, user.ID, credentialID)
		if err != nil {
			return "", nil, err
		}
	}
	if err := credential.ValidateForMicrosoftBackup(); err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(credential.RefreshToken), credential, nil
}

// GetMicrosoftBackupDomainUsers loads refresh from DB (or optional header), calls Backup-Tools,
// updates account_type, and returns microsoft_backup payload — same role as GetGoogleBackupDomainUsers.
// Domain users describe the account's home tenant.
func (s *Service) GetMicrosoftBackupDomainUsers(ctx context.Context, tokenKey, refreshToken, credentialID, microsoftEmail string) (microsoftBackup map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, ErrUnauthorized.New("session token is required")
	}

	resolved, credential, err := s.resolveMicrosoftRefreshToken(ctx, refreshToken, credentialID, microsoftEmail)
	if err != nil {
		return nil, err
	}

	email := strings.TrimSpace(microsoftEmail)
	if credential != nil && email == "" {
		email = credential.Email
	}
	if credential != nil && credential.AccountType == MicrosoftAccountTypePersonal {
		return microsoftBackupDomainUsersPayload(MicrosoftPersonalBackupDomainUsers(email), ""), nil
	}

	domainUsers, domainErr := s.fetchMicrosoftCorporateDomainUsers(ctx, tokenKey, resolved, microsoftBackupToolsHeaders(credential, ""))
	var domainError string
	if domainErr != nil {
		s.log.Warn("microsoft domain-users call failed", zap.Error(domainErr))
		domainError = domainErr.Error()
	} else if credential != nil {
		// Delegated detection must not change app-only authorization state: it can neither grant nor
		// revoke admin_workspace.
		detected, _ := domainUsers["account_type"].(string)
		merged := microsoftAccountTypeFromDetection(detected, credential.AccountType)
		if merged != "" && merged != credential.AccountType {
			if err := s.store.BackupCredentials().UpdateAccountType(ctx, credential.ID, merged); err != nil {
				s.log.Warn("failed to update microsoft backup account type from domain-users", zap.Error(err))
			}
		}
		if merged != "" {
			domainUsers["account_type"] = merged
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

// MicrosoftBackupRegistrationPayload is the microsoft_backup block on auth responses: the stored
// classification, with the Backup-Tools detection filling what is not stored (personal accounts keep
// the consumer tenant id) plus is_admin, admin_roles and can_personal_backup. Consent, capabilities,
// access_state and directory entities are served by GET /microsoft-backup/status and the tenants routes.
func MicrosoftBackupRegistrationPayload(result RegisterMicrosoftBackupResult) map[string]interface{} {
	detection := result.Detection
	out := make(map[string]interface{}, 12)
	storedOrDetected := func(key, stored string) {
		if stored != "" {
			out[key] = stored
		} else if v, ok := detection[key]; ok {
			out[key] = v
		}
	}
	storedOrDetected("account_type", result.AccountType)
	storedOrDetected("tenant_id", result.TenantID)
	storedOrDetected("tenant_name", result.TenantName)
	for _, k := range []string{"is_admin", "admin_roles"} {
		if v, ok := detection[k]; ok {
			out[k] = v
		}
	}
	if state, ok := detection["access_state"].(map[string]interface{}); ok {
		if v, ok := state["can_personal_backup"].(bool); ok {
			out["can_personal_backup"] = v
		}
	}
	if result.AccountType != "" {
		workspaceKind := "organization"
		if result.AccountType == MicrosoftAccountTypePersonal {
			workspaceKind = "personal"
		}
		out["workspace_kind"] = workspaceKind
	}
	if result.CredentialID != "" {
		out["credential_id"] = result.CredentialID
	}
	if result.MicrosoftEmail != "" {
		out["email"] = result.MicrosoftEmail
	}
	if result.DetectionError != "" {
		out["detection_error"] = result.DetectionError
	}
	out["has_refresh_token"] = result.HasRefreshToken
	return out
}
