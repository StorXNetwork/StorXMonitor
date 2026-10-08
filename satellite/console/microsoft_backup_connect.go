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

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

// ConnectMicrosoftBackupResult is returned after POST /microsoft-backup/connect.
type ConnectMicrosoftBackupResult struct {
	CredentialID    string
	HomeTenantID    string
	MicrosoftEmail  string
	Created         bool
	HasRefreshToken bool
	AccountType     string
}

// ConnectMicrosoftBackupCredential exchanges a Microsoft OAuth code for an already logged-in user
// and stores tokens in shared backup_credentials (provider=microsoft).
// Same role as ConnectGoogleBackupCredential (POST /google-backup/connect).
// Also pushes the new refresh_token to Backup-Tools so restore/prepare sees updated scopes.
func (s *Service) ConnectMicrosoftBackupCredential(ctx context.Context, code, redirectURI, tokenKey string) (result ConnectMicrosoftBackupResult, err error) {
	defer mon.Task()(&ctx)(&err)

	code = strings.TrimSpace(code)
	if code == "" {
		return result, ErrValidation.New("code is required")
	}
	if looksLikeOAuthJWT(code) {
		return result, ErrValidation.New("code must be a Microsoft OAuth authorization code, not an access/id token JWT")
	}

	user, err := GetUser(ctx)
	if err != nil {
		return result, Error.Wrap(err)
	}

	tokenRes, err := socialmedia.GetMicrosoftOauthTokenWithRedirect(code, redirectURI)
	if err != nil {
		return result, ErrValidation.New("failed to exchange microsoft oauth code: %v", err)
	}
	if strings.TrimSpace(tokenRes.Refresh_token) == "" {
		return result, ErrValidation.New("microsoft did not return a refresh token; re-authorize with consent and offline_access scopes")
	}
	if looksLikeOAuthJWT(tokenRes.Refresh_token) {
		return result, ErrValidation.New("microsoft refresh_token looks like a JWT; check OUTLOOK client and offline_access scope")
	}

	msUser, err := socialmedia.GetMicrosoftUserByAccessToken(tokenRes.Access_token)
	if err != nil {
		claims, idErr := socialmedia.VerifyMicrosoftIDToken(tokenRes.Id_token)
		if idErr != nil {
			return result, Error.Wrap(err)
		}
		msUser = &socialmedia.MicrosoftUserResult{
			Id:       claims.Oid,
			Email:    claims.Email,
			Name:     claims.Name,
			TenantID: claims.Tid,
		}
	}
	if msUser == nil || strings.TrimSpace(msUser.Email) == "" {
		return result, ErrValidation.New("microsoft user email is required")
	}
	if msUser.TenantID == "" {
		msUser.TenantID = socialmedia.MicrosoftTenantIDFromTokens(tokenRes)
	}
	accountID := socialmedia.MicrosoftAccountIDFromTokens(tokenRes, msUser.Id)
	if accountID == "" {
		return result, ErrValidation.New("microsoft account id (oid) could not be determined; sign in again")
	}

	existing, lookupErr := s.store.BackupCredentials().GetByUserIDProviderAndAccount(ctx, user.ID, BackupProviderMicrosoft, accountID)
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		return result, Error.Wrap(lookupErr)
	}
	result.Created = existing == nil
	result.MicrosoftEmail = msUser.Email
	result.HasRefreshToken = true

	stored, err := s.storeMicrosoftSignIn(ctx, user, MicrosoftBackupSignIn{
		AccountID:         accountID,
		Email:             msUser.Email,
		TenantID:          msUser.TenantID,
		AccessToken:       tokenRes.Access_token,
		RefreshToken:      tokenRes.Refresh_token,
		AccessTokenExpiry: tokenRes.ExpiresAt,
	}, tokenKey)
	if err != nil {
		return result, err
	}
	result.AccountType = stored.AccountType
	result.CredentialID = stored.CredentialID
	result.HomeTenantID = stored.TenantID

	// restore/prepare reads Backup-Tools credentials — push RT so write scopes stick.
	if tk := strings.TrimSpace(tokenKey); tk != "" {
		headers := microsoftBackupToolsHeaders(&BackupCredential{ExternalAccountID: accountID, TenantID: stored.TenantID}, "")
		if syncErr := s.syncMicrosoftRefreshTokenToBackupTools(ctx, tk, msUser.Email, tokenRes.Refresh_token, headers); syncErr != nil {
			s.log.Warn("microsoft-backup connect: Backup-Tools refresh_token sync failed",
				zap.String("email", msUser.Email),
				zap.Error(syncErr),
			)
		}
	}
	return result, nil
}

// syncMicrosoftRefreshTokenToBackupTools updates BT credentials for each owned project (PUT /auto-sync/job/project).
func (s *Service) syncMicrosoftRefreshTokenToBackupTools(ctx context.Context, tokenKey, email, refreshToken string, headers map[string]string) error {
	user, err := GetUser(ctx)
	if err != nil {
		return err
	}
	projects, err := s.store.Projects().GetOwnActive(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}
	email = strings.TrimSpace(email)
	refreshToken = strings.TrimSpace(refreshToken)
	if email == "" || refreshToken == "" {
		return ErrValidation.New("email and refresh_token required for Backup-Tools sync")
	}
	var lastErr error
	synced := 0
	for i := range projects {
		payload, mErr := json.Marshal(map[string]interface{}{
			"project_id":    projects[i].PublicID.String(),
			"google_email":  email, // BT mailbox field (shared Google/MS shape)
			"refresh_token": refreshToken,
		})
		if mErr != nil {
			lastErr = mErr
			continue
		}
		_, status, reqErr := s.backupToolsRequestWithExtraHeaders(ctx, http.MethodPut, "/auto-sync/job/project", tokenKey, "", "", headers, payload)
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		if status >= 200 && status < 300 {
			synced++
		} else {
			lastErr = Error.New("Backup-Tools PUT /auto-sync/job/project returned status %d", status)
		}
	}
	if synced == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}
