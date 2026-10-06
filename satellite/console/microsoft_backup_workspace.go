// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// BackupToolsStatusError is a non-2xx Backup-Tools response. Handlers pass 4xx responses through
// unchanged (status and body) instead of turning them into 500.
type BackupToolsStatusError struct {
	Path   string
	Status int
	Body   []byte
}

// Error implements error.
func (e *BackupToolsStatusError) Error() string {
	return fmt.Sprintf("Backup-Tools %s returned status %d: %s", e.Path, e.Status, string(e.Body))
}

// backupToolsJSON sends a JSON request to Backup-Tools, checks the status and decodes the JSON object body.
// Non-2xx responses return *BackupToolsStatusError.
func (s *Service) backupToolsJSON(ctx context.Context, method, path, tokenKey string, payload interface{}) (map[string]interface{}, error) {
	return s.backupToolsJSONWithRefresh(ctx, method, path, tokenKey, "", payload)
}

// backupToolsTenantJSON calls a Backup-Tools /microsoft/tenants/{tid} route with the caller's delegated
// refresh token. Backup-Tools accepts it as proof of tenant membership before any backup credential
// exists there (e.g. admin consent during onboarding).
func (s *Service) backupToolsTenantJSON(ctx context.Context, method, path, tokenKey string, credential *BackupCredential, payload interface{}) (map[string]interface{}, error) {
	refreshToken := ""
	if credential != nil {
		if rt := strings.TrimSpace(credential.RefreshToken); rt != "" && !looksLikeOAuthJWT(rt) {
			refreshToken = rt
		}
	}
	return s.backupToolsJSONWithRefresh(ctx, method, path, tokenKey, refreshToken, payload)
}

func (s *Service) backupToolsJSONWithRefresh(ctx context.Context, method, path, tokenKey, refreshToken string, payload interface{}) (map[string]interface{}, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}
	respBody, status, err := s.backupToolsRequestWithHeaders(ctx, method, path, tokenKey, "", refreshToken, body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &BackupToolsStatusError{Path: path, Status: status, Body: respBody}
	}
	out := map[string]interface{}{}
	if len(strings.TrimSpace(string(respBody))) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, Error.New("Backup-Tools %s returned invalid JSON: %v", path, err)
	}
	return out, nil
}

// microsoftOrgCredential loads the caller's Microsoft credential and its tenant ID.
// The tenant ID always comes from the stored credential, never from the client.
func (s *Service) microsoftOrgCredential(ctx context.Context) (*BackupCredential, string, error) {
	user, err := GetUser(ctx)
	if err != nil {
		return nil, "", Error.Wrap(err)
	}
	credential, err := s.store.BackupCredentials().GetByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth first")
		}
		return nil, "", Error.Wrap(err)
	}
	if credential.AccountType == MicrosoftAccountTypePersonal {
		return credential, "", ErrValidation.New("organization features require a work or school Microsoft account")
	}
	tenantID := strings.TrimSpace(credential.TenantID)
	if tenantID == "" {
		return credential, "", ErrValidation.New("microsoft tenant is unknown; sign in again with your work or school account")
	}
	return credential, tenantID, nil
}

func microsoftTenantPath(tenantID, suffix string) string {
	return "/microsoft/tenants/" + url.PathEscape(tenantID) + suffix
}

// syncMicrosoftAccountTypeFromWorkspace stores the account_type reported by the Backup-Tools workspace
// contract. Backup-Tools is the authority for app-only authorization, so this may promote to or
// demote from admin_workspace.
func (s *Service) syncMicrosoftAccountTypeFromWorkspace(ctx context.Context, credential *BackupCredential, contract map[string]interface{}) {
	if credential == nil || contract == nil {
		return
	}
	accountType, _ := contract["account_type"].(string)
	accountType = strings.TrimSpace(accountType)
	if accountType == "" || accountType == credential.AccountType {
		return
	}
	if err := s.store.BackupCredentials().UpdateAccountType(ctx, credential.ID, accountType); err != nil {
		s.log.Warn("failed to sync microsoft account type from Backup-Tools workspace", zap.Error(err))
		return
	}
	credential.AccountType = accountType
}

// GetMicrosoftBackupStatus returns the Backup-Tools workspace contract for the caller's Microsoft credential
// (GET /microsoft/workspace) plus has_refresh_token. The delegated refresh token is sent because
// Backup-Tools has no credential row for the user until backup jobs are created (e.g. during onboarding).
func (s *Service) GetMicrosoftBackupStatus(ctx context.Context, tokenKey string) (contract map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	credential, err := s.store.BackupCredentials().GetByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth first")
		}
		return nil, Error.Wrap(err)
	}

	hasRefreshToken := strings.TrimSpace(credential.RefreshToken) != "" && !looksLikeOAuthJWT(credential.RefreshToken)
	if credential.AccountType == MicrosoftAccountTypePersonal {
		return MicrosoftBackupRegistrationPayload(RegisterMicrosoftBackupResult{
			MicrosoftEmail:  credential.Email,
			AccountType:     credential.AccountType,
			HasRefreshToken: hasRefreshToken,
		}), nil
	}

	query := url.Values{}
	query.Set("email", credential.Email)
	if credential.TenantID != "" {
		query.Set("tenant_id", credential.TenantID)
	}
	contract, err = s.backupToolsTenantJSON(ctx, http.MethodGet, "/microsoft/workspace?"+query.Encode(), tokenKey, credential, nil)
	if err != nil {
		return nil, err
	}
	s.syncMicrosoftAccountTypeFromWorkspace(ctx, credential, contract)
	contract["has_refresh_token"] = hasRefreshToken
	return contract, nil
}

// RefreshMicrosoftBackupCapabilities asks Backup-Tools to re-run the capability engine for the caller's tenant.
func (s *Service) RefreshMicrosoftBackupCapabilities(ctx context.Context, tokenKey string) (contract map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftOrgCredential(ctx)
	if err != nil {
		return nil, err
	}
	contract, err = s.backupToolsTenantJSON(ctx, http.MethodPost, microsoftTenantPath(tenantID, "/capabilities/refresh"), tokenKey, credential, nil)
	if err != nil {
		return nil, err
	}
	s.syncMicrosoftAccountTypeFromWorkspace(ctx, credential, contract)
	return contract, nil
}

// ListMicrosoftBackupDirectoryUsers lists the tenant directory stored by Backup-Tools.
// Allowed query parameters: search, department, page, page_size.
func (s *Service) ListMicrosoftBackupDirectoryUsers(ctx context.Context, tokenKey string, query url.Values) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftOrgCredential(ctx)
	if err != nil {
		return nil, err
	}
	forwarded := url.Values{}
	for _, key := range []string{"search", "department", "page", "page_size"} {
		if v := strings.TrimSpace(query.Get(key)); v != "" {
			forwarded.Set(key, v)
		}
	}
	path := microsoftTenantPath(tenantID, "/directory/users")
	if encoded := forwarded.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return s.backupToolsTenantJSON(ctx, http.MethodGet, path, tokenKey, credential, nil)
}

// GetMicrosoftBackupOrgStructure returns the StorX organization structure (org-unit tree) for the tenant.
func (s *Service) GetMicrosoftBackupOrgStructure(ctx context.Context, tokenKey string) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftOrgCredential(ctx)
	if err != nil {
		return nil, err
	}
	return s.backupToolsTenantJSON(ctx, http.MethodGet, microsoftTenantPath(tenantID, "/org-structure"), tokenKey, credential, nil)
}
