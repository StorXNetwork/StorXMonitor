// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

// MicrosoftBackupAuth handles combined Microsoft OAuth register-or-login for Microsoft Backup.
//
// @Summary      Microsoft Backup auth (register or login)
// @Description  **Route:** `GET /api/v0/auth/microsoft-backup`. Same pattern as `GET /auth/google-backup`: UI builds the Microsoft authorize URL client-side (`OUTLOOK_CLIENT_ID`, frontend origin as `redirect_uri`, `MicrosoftBackupScopes`, `prompt=consent`, `offline_access`), then redirects here with OAuth `code`. `redirect_uri` on token exchange is derived server-side from request Host (or `OUTLOOK_OAUTH_REDIRECT_URL_MICROSOFT_BACKUP`). MSAL JWT-as-code still works for login but will not yield refresh_token. Returns `action`, `token`, `onboarding`, and `microsoft_backup` (`email`, `account_type` for consumer mail, `has_refresh_token`). Sets session cookie.
// @Tags         microsoft-backup-onboarding
// @Produce      json
// @Param        code         query  string  true   "Microsoft OAuth authorization code (preferred) or MSAL idToken/accessToken"
// @Param        state        query  string  false  "OAuth state (UTM / verifier payload)"
// @Param        zoho-insert  query  bool    false  "When true, inserts CRM lead in Zoho"
// @Success      200          {object}  MicrosoftBackupAuthSuccess  "Set-Cookie: _tokenKey"
// @Failure      500          {object}  MicrosoftBackupAuthError
// @Router       /auth/microsoft-backup [get]
func (a *Auth) MicrosoftBackupAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	code := r.URL.Query().Get("code")
	if code == "" {
		a.writeMicrosoftBackupAuthError(w, "Authorization code not provided!")
		return
	}

	redirectURI := socialmedia.ResolveMicrosoftBackupOrigin(r)
	session, err := socialmedia.ResolveMicrosoftAuth(code, redirectURI)
	if err != nil {
		a.log.Error("microsoft-backup: microsoft token resolve failed",
			zap.Bool("zoho_insert", r.URL.Query().Has("zoho-insert")),
			zap.Int("code_len", len(code)),
			zap.Error(err),
		)
		a.writeMicrosoftBackupAuthError(w, "Error getting token from Microsoft!")
		return
	}

	a.microsoftBackupAuthFromMicrosoft(w, r, session)
}

func (a *Auth) microsoftBackupAuthFromMicrosoft(w http.ResponseWriter, r *http.Request, session *socialmedia.MicrosoftAuthSession) {
	ctx := r.Context()

	if session == nil || session.User == nil || session.User.Email == "" {
		a.writeMicrosoftBackupAuthError(w, "Error getting user details from Microsoft!")
		return
	}

	msUser := session.User
	tokens := session.Tokens
	if tokens == nil {
		tokens = &socialmedia.MicrosoftOauthToken{}
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, msUser.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.writeMicrosoftBackupAuthError(w, "Error getting user details from system!")
		return
	}

	if verified != nil {
		a.completeMicrosoftBackupLogin(w, r, ctx, verified, msUser, tokens)
		return
	}

	a.completeMicrosoftBackupRegister(w, r, ctx, msUser, tokens, unverified)
}

func (a *Auth) completeMicrosoftBackupRegister(w http.ResponseWriter, r *http.Request, ctx context.Context, msUser *socialmedia.MicrosoftUserResult, tokens *socialmedia.MicrosoftOauthToken, unverified []console.User) {
	state := r.URL.Query().Get("state")
	verifier := socialmedia.NewVerifierDataFromString(state)
	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		go zohoInsertLead(context.Background(), msUser.Name, msUser.Email, a.log, verifier)
	}

	var user *console.User
	if len(unverified) > 0 {
		user = &unverified[0]
	} else {
		secret, err := console.RegistrationSecretFromBase64("")
		if err != nil {
			a.writeMicrosoftBackupAuthError(w, "Error creating secret!")
			return
		}

		ip, err := web.GetRequestIP(r)
		if err != nil {
			a.writeMicrosoftBackupAuthError(w, "Error getting IP!")
			return
		}

		var utmParams *console.UtmParams
		if verifier != nil {
			utmParams = &console.UtmParams{
				UtmTerm:     verifier.UTMTerm,
				UtmContent:  verifier.UTMContent,
				UtmSource:   verifier.UTMSource,
				UtmMedium:   verifier.UTMMedium,
				UtmCampaign: verifier.UTMCampaign,
			}
		}

		user, err = a.service.CreateUser(ctx,
			console.CreateUser{
				FullName:  msUser.Name,
				Email:     msUser.Email,
				Status:    1,
				IP:        ip,
				Source:    "Microsoft",
				UtmParams: utmParams,
			},
			secret, true,
		)
		if err != nil {
			a.writeMicrosoftBackupAuthError(w, "Error creating user!")
			return
		}

		referrer := r.URL.Query().Get("referrer")
		if referrer == "" {
			referrer = r.Referer()
		}
		hubspotUTK := ""
		hubspotCookie, err := r.Cookie("hubspotutk")
		if err == nil {
			hubspotUTK = hubspotCookie.Value
		}

		trackCreateUserFields := analytics.TrackCreateUserFields{
			ID:           user.ID,
			AnonymousID:  loadSession(r),
			FullName:     user.FullName,
			Email:        user.Email,
			Type:         analytics.Personal,
			OriginHeader: r.Header.Get("Origin"),
			Referrer:     referrer,
			HubspotUTK:   hubspotUTK,
			UserAgent:    string(user.UserAgent),
		}
		if user.IsProfessional {
			trackCreateUserFields.Type = analytics.Professional
			trackCreateUserFields.EmployeeCount = user.EmployeeCount
			trackCreateUserFields.CompanyName = user.CompanyName
			trackCreateUserFields.JobTitle = user.Position
			trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
		}
		a.analytics.TrackCreateUser(trackCreateUserFields)
	}

	sessionToken, err := a.issueSessionTokenForGoogleUser(ctx, msUser.Email, "", w, r)
	if err != nil {
		a.writeMicrosoftBackupAuthError(w, "Error creating session token!")
		return
	}

	if a.mailService != nil {
		a.sendRegistrationWelcomeEmail(ctx, user.Email, user.FullName)
	}

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name:             "My Project",
		ManagePassphrase: true,
	})
	if err != nil {
		a.writeMicrosoftBackupAuthError(w, "Error creating default project!")
		return
	}
	a.log.Info("Default Project Name: " + project.Name)

	if err := a.service.InitMicrosoftBackupOnboarding(authed); err != nil {
		a.log.Warn("failed to init microsoft backup onboarding status", zap.Error(err))
	}

	var microsoftBackup map[string]interface{}
	if tokens == nil {
		tokens = &socialmedia.MicrosoftOauthToken{}
	}
	backupResult, backupErr := a.service.RegisterMicrosoftBackupCredential(
		authed,
		msUser.Email,
		tokens.Access_token,
		tokens.Refresh_token,
		tokens.Scope,
		tokens.ExpiresAt,
		sessionToken,
	)
	if backupErr != nil {
		a.log.Warn("failed to register microsoft backup credentials", zap.Error(backupErr))
		microsoftBackup = microsoftBackupPayload(msUser.Email, tokens)
	} else {
		microsoftBackup = console.MicrosoftBackupRegistrationPayload(backupResult)
	}

	onboarding, err := a.service.GetMicrosoftBackupOnboarding(authed)
	if err != nil {
		a.log.Warn("failed to read onboarding after microsoft registration", zap.Error(err))
		onboarding = console.MicrosoftBackupOnboardingAPI{
			OnboardingStart:  true,
			OnboardingEnd:    false,
			OnboardingStep:   console.OnboardingStepMicrosoftBackupPending,
			OnboardingStatus: console.OnboardingStatusPending,
		}
	}

	a.service.RecordUserAudit(authed, "AUTH_MICROSOFT_BACKUP", "Microsoft Backup", "Microsoft Backup registration completed", nil)
	a.writeMicrosoftBackupAuthSuccess(w, socialmedia.MicrosoftAuthActionRegistered, sessionToken, onboarding, microsoftBackup)
}

func (a *Auth) completeMicrosoftBackupLogin(w http.ResponseWriter, r *http.Request, ctx context.Context, user *console.User, msUser *socialmedia.MicrosoftUserResult, tokens *socialmedia.MicrosoftOauthToken) {
	sessionToken, err := a.issueSessionTokenForGoogleUser(ctx, msUser.Email, "", w, r)
	if err != nil {
		a.writeMicrosoftBackupAuthError(w, "Error creating session token!")
		return
	}

	authed := console.WithUser(ctx, user)

	var microsoftBackup map[string]interface{}
	if tokens == nil {
		tokens = &socialmedia.MicrosoftOauthToken{}
	}
	hasFreshTokens := strings.TrimSpace(tokens.Access_token) != "" || strings.TrimSpace(tokens.Refresh_token) != ""
	if hasFreshTokens {
		backupResult, backupErr := a.service.RegisterMicrosoftBackupCredential(
			authed,
			msUser.Email,
			tokens.Access_token,
			tokens.Refresh_token,
			tokens.Scope,
			tokens.ExpiresAt,
			sessionToken,
		)
		if backupErr != nil {
			a.log.Warn("failed to register microsoft backup credentials at login", zap.Error(backupErr))
			microsoftBackup = microsoftBackupPayload(msUser.Email, tokens)
		} else {
			microsoftBackup = console.MicrosoftBackupRegistrationPayload(backupResult)
		}
	} else {
		backupPayload, backupErr := a.service.LoadMicrosoftBackupAtLogin(authed, sessionToken)
		if backupErr != nil {
			a.log.Warn("failed to load microsoft backup credentials at login", zap.Error(backupErr))
		} else {
			microsoftBackup = backupPayload
		}
	}

	onboarding, err := a.service.GetMicrosoftBackupOnboarding(authed)
	if err != nil {
		a.log.Warn("failed to read onboarding at microsoft login", zap.Error(err))
		onboarding = console.MicrosoftBackupOnboardingAPI{}
	}

	a.service.RecordUserAudit(authed, "AUTH_MICROSOFT_BACKUP", "Microsoft Backup", "Microsoft Backup login completed", nil)
	a.writeMicrosoftBackupAuthSuccess(w, socialmedia.MicrosoftAuthActionLoggedIn, sessionToken, onboarding, microsoftBackup)
}

func microsoftBackupPayload(email string, tokens *socialmedia.MicrosoftOauthToken) map[string]interface{} {
	payload := map[string]interface{}{
		"email": email,
	}
	if accountType := console.InferMicrosoftAccountTypeFromEmail(email); accountType != "" {
		payload["account_type"] = accountType
	}
	if tokens == nil {
		payload["has_refresh_token"] = false
		return payload
	}
	payload["has_refresh_token"] = strings.TrimSpace(tokens.Refresh_token) != ""
	return payload
}

func (a *Auth) writeMicrosoftBackupAuthSuccess(w http.ResponseWriter, action, sessionToken string, onboarding console.MicrosoftBackupOnboardingAPI, microsoftBackup map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	payload := map[string]interface{}{
		"success":    true,
		"action":     action,
		"token":      sessionToken,
		"onboarding": onboarding,
	}
	if microsoftBackup != nil {
		payload["microsoft_backup"] = microsoftBackup
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *Auth) writeMicrosoftBackupAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
