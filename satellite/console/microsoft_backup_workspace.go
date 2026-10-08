// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
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
	return s.backupToolsJSONWithHeaders(ctx, method, path, tokenKey, "", nil, payload)
}

// backupToolsTenantJSON calls a Backup-Tools Microsoft route for the credential with its delegated
// refresh token and the credential/tenant headers. selectedTenantID is empty on account-level routes.
// Backup-Tools accepts the refresh token as proof of identity before it stores any credential
// (e.g. admin consent during onboarding).
func (s *Service) backupToolsTenantJSON(ctx context.Context, method, path, tokenKey string, credential *BackupCredential, selectedTenantID string, payload interface{}) (map[string]interface{}, error) {
	return s.backupToolsJSONWithHeaders(ctx, method, path, tokenKey, microsoftCredentialRefreshToken(credential), microsoftBackupToolsHeaders(credential, selectedTenantID), payload)
}

func (s *Service) backupToolsJSONWithHeaders(ctx context.Context, method, path, tokenKey, refreshToken string, headers map[string]string, payload interface{}) (map[string]interface{}, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}
	respBody, status, err := s.backupToolsRequestWithExtraHeaders(ctx, method, path, tokenKey, "", refreshToken, headers, body)
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

func microsoftTenantPath(tenantID, suffix string) string {
	return "/microsoft/tenants/" + url.PathEscape(tenantID) + suffix
}

// syncMicrosoftAccountTypeFromWorkspace stores the account_type reported by the Backup-Tools workspace
// contract for the credential's home tenant. Backup-Tools is the authority for app-only authorization,
// so this may promote to or demote from admin_workspace. Contracts for other tenants are not stored:
// account_type describes the home tenant only.
func (s *Service) syncMicrosoftAccountTypeFromWorkspace(ctx context.Context, credential *BackupCredential, tenantID string, contract map[string]interface{}) {
	if credential == nil || contract == nil || !strings.EqualFold(tenantID, credential.HomeTenantID()) {
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

// GetMicrosoftBackupStatus returns the Backup-Tools workspace contract (GET /microsoft/workspace) for the
// selected credential and tenant, plus has_refresh_token. Personal accounts are answered locally.
// The delegated refresh token is sent because Backup-Tools may have no credential row for the user
// until backup jobs are created (e.g. during onboarding).
func (s *Service) GetMicrosoftBackupStatus(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection) (contract map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	sel = sel.normalized()
	credential, err := s.resolveMicrosoftCredentialForUser(ctx, sel.CredentialID)
	if err != nil {
		return nil, err
	}

	hasRefreshToken := hasUsableRefreshToken(credential)
	if credential.AccountType == MicrosoftAccountTypePersonal {
		payload := MicrosoftBackupRegistrationPayload(RegisterMicrosoftBackupResult{
			MicrosoftEmail:  credential.Email,
			AccountType:     credential.AccountType,
			HasRefreshToken: hasRefreshToken,
		})
		payload["credential_id"] = credential.ID.String()
		return payload, nil
	}
	if sel.TenantID == "" {
		return nil, ErrMicrosoftTenantRequired.New("tenant_id is required")
	}

	query := url.Values{}
	query.Set("email", credential.Email)
	query.Set("tenant_id", sel.TenantID)
	contract, err = s.backupToolsTenantJSON(ctx, http.MethodGet, "/microsoft/workspace?"+query.Encode(), tokenKey, credential, sel.TenantID, nil)
	if err != nil {
		return nil, err
	}
	s.syncMicrosoftAccountTypeFromWorkspace(ctx, credential, sel.TenantID, contract)
	contract["has_refresh_token"] = hasRefreshToken
	contract["credential_id"] = credential.ID.String()
	return contract, nil
}

// RefreshMicrosoftBackupCapabilities asks Backup-Tools to re-run the capability engine for the selected tenant.
func (s *Service) RefreshMicrosoftBackupCapabilities(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection) (contract map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftTenantContext(ctx, sel)
	if err != nil {
		return nil, err
	}
	contract, err = s.backupToolsTenantJSON(ctx, http.MethodPost, microsoftTenantPath(tenantID, "/capabilities/refresh"), tokenKey, credential, tenantID, nil)
	if err != nil {
		return nil, err
	}
	s.syncMicrosoftAccountTypeFromWorkspace(ctx, credential, tenantID, contract)
	return contract, nil
}

// ListMicrosoftBackupDirectoryUsers lists the selected tenant's directory users via Backup-Tools.
// Allowed query parameters: search, department, page, page_size.
func (s *Service) ListMicrosoftBackupDirectoryUsers(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection, query url.Values) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftTenantContext(ctx, sel)
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
	return s.backupToolsTenantJSON(ctx, http.MethodGet, path, tokenKey, credential, tenantID, nil)
}

// GetMicrosoftBackupOrgStructure returns the StorX organization structure (org-unit tree) for the selected tenant.
func (s *Service) GetMicrosoftBackupOrgStructure(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftTenantContext(ctx, sel)
	if err != nil {
		return nil, err
	}
	return s.backupToolsTenantJSON(ctx, http.MethodGet, microsoftTenantPath(tenantID, "/org-structure"), tokenKey, credential, tenantID, nil)
}

// ListMicrosoftBackupTenants returns the tenant access state of every tenant the selected account can
// reach (Backup-Tools GET /microsoft/accounts/tenants). This is an account-level route: no tenant is selected.
func (s *Service) ListMicrosoftBackupTenants(ctx context.Context, tokenKey, credentialID string) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, err := s.resolveMicrosoftCredentialForUser(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	result, err = s.backupToolsTenantJSON(ctx, http.MethodGet, "/microsoft/accounts/tenants", tokenKey, credential, "", nil)
	if err != nil {
		return nil, err
	}
	result["credential_id"] = credential.ID.String()
	return result, nil
}

// ConnectMicrosoftBackupTenant marks the selected account's link to tenantID connected in Backup-Tools.
// backupMode is personal or organization; Backup-Tools never changes it from access state.
func (s *Service) ConnectMicrosoftBackupTenant(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection, backupMode string) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	backupMode = strings.ToLower(strings.TrimSpace(backupMode))
	switch backupMode {
	case "personal", "organization":
	case "":
		return nil, ErrValidation.New("backup_mode is required")
	default:
		return nil, ErrValidation.New("unsupported backup_mode: %s", backupMode)
	}
	credential, tenantID, err := s.microsoftTenantLinkContext(ctx, sel)
	if err != nil {
		return nil, err
	}
	return s.backupToolsTenantJSON(ctx, http.MethodPost, microsoftAccountTenantPath(tenantID, "/connect"), tokenKey, credential, tenantID, map[string]interface{}{
		"backup_mode": backupMode,
	})
}

// DisconnectMicrosoftBackupTenant disconnects the selected account's link to tenantID in Backup-Tools.
// Backups are kept; backup, browse and restore are blocked until reconnect.
func (s *Service) DisconnectMicrosoftBackupTenant(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftTenantLinkContext(ctx, sel)
	if err != nil {
		return nil, err
	}
	return s.backupToolsTenantJSON(ctx, http.MethodPost, microsoftAccountTenantPath(tenantID, "/disconnect"), tokenKey, credential, tenantID, nil)
}

// RefreshMicrosoftBackupTenantRoles re-reads the account's directory roles in tenantID via Backup-Tools.
func (s *Service) RefreshMicrosoftBackupTenantRoles(ctx context.Context, tokenKey string, sel MicrosoftTenantSelection) (result map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	credential, tenantID, err := s.microsoftTenantLinkContext(ctx, sel)
	if err != nil {
		return nil, err
	}
	return s.backupToolsTenantJSON(ctx, http.MethodPost, microsoftAccountTenantPath(tenantID, "/roles/refresh"), tokenKey, credential, tenantID, nil)
}

// microsoftTenantLinkContext resolves the credential and tenant for tenant-link routes. Unlike
// organization routes, personal accounts are allowed (their only link is the personal tenant).
func (s *Service) microsoftTenantLinkContext(ctx context.Context, sel MicrosoftTenantSelection) (*BackupCredential, string, error) {
	sel = sel.normalized()
	if sel.TenantID == "" {
		return nil, "", ErrMicrosoftTenantRequired.New("tenant_id is required")
	}
	credential, err := s.resolveMicrosoftCredentialForUser(ctx, sel.CredentialID)
	if err != nil {
		return nil, "", err
	}
	return credential, sel.TenantID, nil
}

func microsoftAccountTenantPath(tenantID, suffix string) string {
	return "/microsoft/accounts/tenants/" + url.PathEscape(tenantID) + suffix
}
