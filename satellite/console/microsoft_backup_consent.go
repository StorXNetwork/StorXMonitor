// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

const (
	microsoftAdminConsentStatePurpose = "microsoft_admin_consent"
	microsoftAdminConsentStateTTL     = 15 * time.Minute
	microsoftAdminConsentBaseURL      = "https://login.microsoftonline.com/"
)

// microsoftAdminConsentState is the HMAC-signed OAuth state for the admin-consent redirect.
// It only protects the redirect (who started it, for which tenant and app); it says nothing about
// whether consent was granted. Backup-Tools decides that from the app-only token.
type microsoftAdminConsentState struct {
	Purpose      string `json:"p"`
	UserID       string `json:"uid"`
	CredentialID string `json:"crid"`
	// TenantID is the tenant selected for consent, not necessarily the account's home tenant.
	TenantID  string `json:"tid"`
	ClientID  string `json:"cid"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"n"`
}

// MicrosoftAdminConsentCallback is the query Microsoft appends to the admin-consent redirect URI,
// forwarded by the frontend callback page.
type MicrosoftAdminConsentCallback struct {
	State            string
	Tenant           string
	AdminConsent     string
	Error            string
	ErrorDescription string
}

func (s *Service) signMicrosoftAdminConsentState(state microsoftAdminConsentState) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", Error.Wrap(err)
	}
	token := consoleauth.Token{Payload: payload}
	signature, err := s.tokens.SignToken(token)
	if err != nil {
		return "", Error.Wrap(err)
	}
	token.Signature = signature
	return token.String(), nil
}

func (s *Service) verifyMicrosoftAdminConsentState(raw string, now time.Time) (state microsoftAdminConsentState, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return state, ErrValidation.New("admin consent state is required")
	}
	token, err := consoleauth.FromBase64URLString(raw)
	if err != nil {
		return state, ErrValidation.New("invalid admin consent state")
	}
	valid, err := s.tokens.ValidateToken(token)
	if err != nil {
		return state, Error.Wrap(err)
	}
	if !valid {
		return state, ErrValidation.New("invalid admin consent state signature")
	}
	if err := json.Unmarshal(token.Payload, &state); err != nil {
		return state, ErrValidation.New("invalid admin consent state payload")
	}
	if state.Purpose != microsoftAdminConsentStatePurpose {
		return state, ErrValidation.New("invalid admin consent state purpose")
	}
	if now.Unix() > state.ExpiresAt {
		return state, ErrValidation.New("admin consent state expired; start admin consent again")
	}
	return state, nil
}

// GetMicrosoftAdminConsentURL builds the admin-consent URL of the selected tenant for the selected work or
// school account. Only accounts that Backup-Tools detection reports as Entra administrators (is_admin) in
// that tenant may start it. admin_workspace is not required: that label only exists after consent.
func (s *Service) GetMicrosoftAdminConsentURL(ctx context.Context, tokenKey, redirectURI string, sel MicrosoftTenantSelection) (consentURL string, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return "", Error.Wrap(err)
	}
	credential, tenantID, err := s.microsoftTenantContext(ctx, sel)
	if err != nil {
		return "", err
	}
	clientID := strings.TrimSpace(socialmedia.GetConfig().OutlookClientID)
	if clientID == "" {
		return "", Error.New("microsoft client id is not configured")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return "", Error.New("microsoft admin consent redirect URI is not configured")
	}

	refreshToken := strings.TrimSpace(credential.RefreshToken)
	if refreshToken == "" || looksLikeOAuthJWT(refreshToken) {
		return "", ErrReauthRequired.New("sign in with Microsoft again before starting admin consent")
	}
	detection, err := s.detectMicrosoftAccount(ctx, tokenKey, refreshToken, microsoftBackupToolsHeaders(credential, tenantID))
	if err != nil {
		return "", err
	}
	if isAdmin, _ := detection["is_admin"].(bool); !isAdmin {
		return "", ErrForbidden.New("only a Microsoft Entra administrator can start organization onboarding")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", Error.Wrap(err)
	}
	state, err := s.signMicrosoftAdminConsentState(microsoftAdminConsentState{
		Purpose:      microsoftAdminConsentStatePurpose,
		UserID:       user.ID.String(),
		CredentialID: credential.ID.String(),
		TenantID:     tenantID,
		ClientID:     clientID,
		ExpiresAt:    s.nowFn().Add(microsoftAdminConsentStateTTL).Unix(),
		Nonce:        hex.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	return microsoftAdminConsentBaseURL + url.PathEscape(tenantID) + "/adminconsent?" + params.Encode(), nil
}

// CompleteMicrosoftAdminConsent verifies the callback state and asks Backup-Tools to evaluate tenant consent
// (POST /microsoft/tenants/{tid}/consent). The Backup-Tools contract is returned unchanged; the Satellite
// only stores account_type, and only when Backup-Tools reports admin_workspace.
func (s *Service) CompleteMicrosoftAdminConsent(ctx context.Context, tokenKey string, callback MicrosoftAdminConsentCallback) (contract map[string]interface{}, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	state, err := s.verifyMicrosoftAdminConsentState(callback.State, s.nowFn())
	if err != nil {
		return nil, err
	}
	if state.UserID != user.ID.String() {
		return nil, ErrForbidden.New("admin consent was started by a different user")
	}
	if clientID := strings.TrimSpace(socialmedia.GetConfig().OutlookClientID); state.ClientID != clientID {
		return nil, ErrValidation.New("admin consent state was issued for a different Microsoft app")
	}
	if tenant := strings.TrimSpace(callback.Tenant); tenant != "" && !strings.EqualFold(tenant, state.TenantID) {
		return nil, ErrValidation.New("admin consent was completed for a different tenant")
	}

	// The account and tenant come from the signed state, so the callback targets exactly what was started.
	credential, tenantID, err := s.microsoftTenantContext(ctx, MicrosoftTenantSelection{
		CredentialID: state.CredentialID,
		TenantID:     state.TenantID,
	})
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"consented_by":  credential.Email,
		"admin_consent": strings.EqualFold(strings.TrimSpace(callback.AdminConsent), "true"),
	}
	if v := strings.TrimSpace(callback.Error); v != "" {
		payload["error"] = v
	}
	if v := strings.TrimSpace(callback.ErrorDescription); v != "" {
		payload["error_description"] = v
	}

	contract, err = s.backupToolsTenantJSON(ctx, http.MethodPost, microsoftTenantPath(tenantID, "/consent"), tokenKey, credential, tenantID, payload)
	if err != nil {
		return nil, err
	}
	// account_type describes the home tenant only; consent in another tenant is tracked by Backup-Tools.
	if accountType, _ := contract["account_type"].(string); accountType == MicrosoftAccountTypeAdminWorkspace &&
		strings.EqualFold(tenantID, credential.HomeTenantID()) && credential.AccountType != accountType {
		if err := s.store.BackupCredentials().UpdateAccountType(ctx, credential.ID, accountType); err != nil {
			return nil, Error.Wrap(err)
		}
	}
	return contract, nil
}
