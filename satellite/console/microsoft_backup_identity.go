// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

// Headers carrying the Microsoft credential and tenant context to Backup-Tools.
const (
	// BackupToolsHeaderMicrosoftAccountID is the credential's home object ID (external_account_id).
	BackupToolsHeaderMicrosoftAccountID = "MICROSOFT_ACCOUNT_ID"
	// BackupToolsHeaderMicrosoftHomeTenantID is the credential's home tenant.
	BackupToolsHeaderMicrosoftHomeTenantID = "MICROSOFT_HOME_TENANT_ID"
	// BackupToolsHeaderMicrosoftTenantID is the tenant selected for the request.
	BackupToolsHeaderMicrosoftTenantID = "MICROSOFT_TENANT_ID"
)

var (
	// ErrMicrosoftCredentialRequired means the user has several Microsoft accounts and none was selected.
	ErrMicrosoftCredentialRequired = errs.Class("microsoft_credential_required")
	// ErrMicrosoftCredentialNotFound means the selected Microsoft account does not exist for the user.
	ErrMicrosoftCredentialNotFound = errs.Class("microsoft_credential_not_found")
	// ErrMicrosoftTenantRequired means a tenant-scoped request did not select a tenant.
	ErrMicrosoftTenantRequired = errs.Class("tenant_id_required")
)

// MicrosoftTenantSelection is the Microsoft account and tenant a request targets.
// CredentialID is the Satellite backup_credentials ID; TenantID is the selected Entra tenant,
// passed through to Backup-Tools, which checks that the account is linked to it.
type MicrosoftTenantSelection struct {
	CredentialID string
	TenantID     string
}

func (sel MicrosoftTenantSelection) normalized() MicrosoftTenantSelection {
	return MicrosoftTenantSelection{
		CredentialID: strings.TrimSpace(sel.CredentialID),
		TenantID:     strings.ToLower(strings.TrimSpace(sel.TenantID)),
	}
}

// MicrosoftBackupAccount is one Microsoft sign-in connected by the user.
type MicrosoftBackupAccount struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	ExternalAccountID string `json:"external_account_id"`
	HomeTenantID      string `json:"home_tenant_id,omitempty"`
	HomeTenantName    string `json:"home_tenant_name,omitempty"`
	AccountType       string `json:"account_type,omitempty"`
	HasRefreshToken   bool   `json:"has_refresh_token"`
}

// ListMicrosoftBackupAccounts returns the caller's Microsoft sign-ins, oldest first.
func (s *Service) ListMicrosoftBackupAccounts(ctx context.Context) (accounts []MicrosoftBackupAccount, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	credentials, err := s.store.BackupCredentials().ListByUserIDAndProvider(ctx, user.ID, BackupProviderMicrosoft)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	accounts = make([]MicrosoftBackupAccount, 0, len(credentials))
	for i := range credentials {
		accounts = append(accounts, microsoftBackupAccountFromCredential(&credentials[i]))
	}
	return accounts, nil
}

func microsoftBackupAccountFromCredential(credential *BackupCredential) MicrosoftBackupAccount {
	return MicrosoftBackupAccount{
		ID:                credential.ID.String(),
		Email:             credential.Email,
		ExternalAccountID: credential.ExternalAccountID,
		HomeTenantID:      credential.HomeTenantID(),
		HomeTenantName:    credential.HomeTenantName(),
		AccountType:       credential.AccountType,
		HasRefreshToken:   hasUsableRefreshToken(credential),
	}
}

func hasUsableRefreshToken(credential *BackupCredential) bool {
	rt := strings.TrimSpace(credential.RefreshToken)
	return rt != "" && !looksLikeOAuthJWT(rt)
}

// resolveMicrosoftCredential returns the user's Microsoft credential selected by credentialID.
// Without a credentialID the only Microsoft credential is used; with several it fails with
// ErrMicrosoftCredentialRequired. A credential of another user is reported as not found.
func (s *Service) resolveMicrosoftCredential(ctx context.Context, userID uuid.UUID, credentialID string) (*BackupCredential, error) {
	credentialID = strings.TrimSpace(credentialID)
	store := s.store.BackupCredentials()

	if credentialID != "" {
		id, err := uuid.FromString(credentialID)
		if err != nil {
			return nil, ErrValidation.New("invalid credential_id")
		}
		credential, err := store.GetByID(ctx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrMicrosoftCredentialNotFound.New("microsoft account not found")
			}
			return nil, Error.Wrap(err)
		}
		if credential.UserID != userID || credential.Provider != BackupProviderMicrosoft {
			return nil, ErrMicrosoftCredentialNotFound.New("microsoft account not found")
		}
		return credential, nil
	}

	credentials, err := store.ListByUserIDAndProvider(ctx, userID, BackupProviderMicrosoft)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	switch len(credentials) {
	case 0:
		return nil, ErrNotFound.New("microsoft backup credentials not found; complete microsoft-backup auth first")
	case 1:
		return &credentials[0], nil
	default:
		return nil, ErrMicrosoftCredentialRequired.New("several Microsoft accounts are connected; select one with credential_id")
	}
}

// resolveMicrosoftCredentialForUser is resolveMicrosoftCredential for the context user.
func (s *Service) resolveMicrosoftCredentialForUser(ctx context.Context, credentialID string) (*BackupCredential, error) {
	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return s.resolveMicrosoftCredential(ctx, user.ID, credentialID)
}

// latestMicrosoftCredential returns the most recently updated Microsoft credential, or nil.
func latestMicrosoftCredential(credentials []BackupCredential) *BackupCredential {
	if len(credentials) == 0 {
		return nil
	}
	sorted := append([]BackupCredential(nil), credentials...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].UpdatedAt.After(sorted[j].UpdatedAt)
	})
	return &sorted[0]
}

// microsoftTenantContext resolves the selected credential and the selected tenant for a tenant-scoped
// organization route. The home tenant is never substituted for a missing selection.
func (s *Service) microsoftTenantContext(ctx context.Context, sel MicrosoftTenantSelection) (*BackupCredential, string, error) {
	sel = sel.normalized()
	credential, err := s.resolveMicrosoftCredentialForUser(ctx, sel.CredentialID)
	if err != nil {
		return nil, "", err
	}
	if credential.AccountType == MicrosoftAccountTypePersonal {
		return credential, "", ErrValidation.New("organization features require a work or school Microsoft account")
	}
	if sel.TenantID == "" {
		return credential, "", ErrMicrosoftTenantRequired.New("tenant_id is required")
	}
	return credential, sel.TenantID, nil
}

// microsoftBackupToolsHeaders identifies the credential (and the selected tenant, when set) to Backup-Tools.
func microsoftBackupToolsHeaders(credential *BackupCredential, selectedTenantID string) map[string]string {
	headers := map[string]string{}
	if credential != nil {
		if v := strings.TrimSpace(credential.ExternalAccountID); v != "" {
			headers[BackupToolsHeaderMicrosoftAccountID] = v
		}
		if v := strings.TrimSpace(credential.HomeTenantID()); v != "" {
			headers[BackupToolsHeaderMicrosoftHomeTenantID] = v
		}
	}
	if v := strings.TrimSpace(selectedTenantID); v != "" {
		headers[BackupToolsHeaderMicrosoftTenantID] = v
	}
	return headers
}

// microsoftCredentialRefreshToken is the stored delegated refresh token, or "" when unusable.
func microsoftCredentialRefreshToken(credential *BackupCredential) string {
	if credential == nil || !hasUsableRefreshToken(credential) {
		return ""
	}
	return strings.TrimSpace(credential.RefreshToken)
}
