// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// SellerAuth exposes seller authentication endpoints.
type SellerAuth struct {
	log                   *zap.Logger
	service               *Service
	cookieAuth            *consolewebauth.CookieAuth
	externalAddr          string
	badPasswords          map[string]struct{}
	badPasswordsEncoded   string
}

// NewSellerAuth creates a seller auth controller.
func NewSellerAuth(log *zap.Logger, service *Service, cookieAuth *consolewebauth.CookieAuth, externalAddress string, badPasswords map[string]struct{}, badPasswordsEncoded string) *SellerAuth {
	return &SellerAuth{
		log:                 log,
		service:             service,
		cookieAuth:          cookieAuth,
		externalAddr:        externalAddress,
		badPasswords:        badPasswords,
		badPasswordsEncoded: badPasswordsEncoded,
	}
}

// GoogleAuth handles combined Google OAuth register-or-login for sellers.
//
// @Summary      Reseller Google auth (register or login)
// @Description  **Route:** `GET /api/v0/seller/auth/google`. Exchanges OAuth code (redirect_uri = GOOGLE_OAUTH_REDIRECT_URL_SELLER). If email exists as an active reseller, logs in; otherwise registers a reseller and empty `reseller_configs`. Returns JSON with `action` and `reseller`. Sets session cookie `_seller_tokenKey`. Does not call Backup-Tools or console onboarding.
// @Tags         reseller-auth
// @Produce      json
// @Param        code        query  string  true   "Fresh Google OAuth code (single-use)"
// @Param        zoho-insert query  bool    false  "When true, appends zoho-insert to OAuth redirect URL"
// @Success      200         {object}  SellerGoogleAuthSuccess  "Set-Cookie: _seller_tokenKey"
// @Failure      500         {object}  SellerGoogleAuthError
// @Router       /seller/auth/google [get]
func (a *SellerAuth) GoogleAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	code := r.URL.Query().Get("code")
	session, err := socialmedia.ExchangeGoogleAuthCode(code, "seller", r.URL.Query().Has("zoho-insert"))
	if err != nil {
		a.log.Error("seller google auth: token exchange failed",
			zap.Bool("zoho_insert", r.URL.Query().Has("zoho-insert")),
			zap.Int("code_len", len(code)),
			zap.Error(err),
		)
		socialmedia.WriteCombinedGoogleAuthError(w, "Error getting token from Google!")
		return
	}

	verified, _, err := a.service.GetResellerByEmailWithUnverified(ctx, session.User.Email)
	if err != nil && !ErrEmailNotFound.Has(err) {
		socialmedia.WriteCombinedGoogleAuthError(w, "Error getting reseller details from system!")
		return
	}

	ip, _ := web.GetRequestIP(r)
	if verified != nil {
		a.completeGoogleLogin(w, ctx, verified, ip)
		return
	}

	a.completeGoogleRegister(w, ctx, session, ip)
}

// Token authenticates reseller by email and password.
//
// @Summary      Reseller email + password login
// @Description  **Route:** `POST /api/v0/seller/auth/token`. Sets `_seller_tokenKey` session cookie.
// @Tags         reseller-auth
// @Accept       json
// @Produce      json
// @Param        body  body  SellerAuthTokenSwaggerRequest  true  "Email, password, captcha"
// @Success      200   {object}  SellerAuthTokenSwaggerResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Security     SellerCSRFAuth
// @Router       /seller/auth/token [post]
func (a *SellerAuth) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var tokenRequest AuthReseller
	if err = json.NewDecoder(r.Body).Decode(&tokenRequest); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenRequest.IP, err = web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	tokenRequest.UserAgent = r.UserAgent()

	tokenInfo, err := a.service.TokenReseller(ctx, tokenRequest)
	if err != nil {
		if console.ErrMFAMissing.Has(err) {
			web.ServeCustomJSONError(ctx, a.log, w, http.StatusOK, err, err.Error())
		} else {
			a.serveJSONError(ctx, w, err)
		}
		return
	}

	a.writeTokenResponse(w, tokenInfo)
}

// Register creates a new reseller account with email and password.
//
// @Summary      Register reseller
// @Description  **Route:** `POST /api/v0/seller/auth/register`. Sends activation email when signup activation code is enabled.
// @Tags         reseller-auth
// @Accept       json
// @Produce      json
// @Param        body  body  SellerRegisterSwaggerRequest  true  "Registration payload"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Router       /seller/auth/register [post]
func (a *SellerAuth) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var registerData struct {
		FullName        string `json:"fullName"`
		Email           string `json:"email"`
		Password        string `json:"password"`
		CompanyName     string `json:"companyName"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	if err = json.NewDecoder(r.Body).Decode(&registerData); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if a.badPasswords != nil {
		if _, exists := a.badPasswords[registerData.Password]; exists {
			a.serveJSONError(ctx, w, ErrValidation.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one."))
			return
		}
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if captchaErr := a.service.VerifyRegistrationCaptcha(ctx, registerData.CaptchaResponse, ip); captchaErr != nil {
		a.serveJSONError(ctx, w, captchaErr)
		return
	}

	_, err = a.service.RegisterReseller(ctx, CreateResellerRequest{
		FullName:    registerData.FullName,
		Email:       strings.TrimSpace(registerData.Email),
		Password:    registerData.Password,
		CompanyName: registerData.CompanyName,
	})
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// ForgotPassword sends password recovery email.
//
// @Summary      Request password reset email
// @Description  **Route:** `POST /api/v0/seller/auth/forgot-password`. Always returns HTTP 200 on valid captcha.
// @Tags         reseller-auth-password
// @Accept       json
// @Produce      json
// @Param        body  body  SellerForgotPasswordSwaggerRequest  true  "Email and captcha"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Router       /seller/auth/forgot-password [post]
func (a *SellerAuth) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body struct {
		Email           string `json:"email"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.ForgotPasswordReseller(ctx, body.Email, body.CaptchaResponse, ip); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// ResetPassword resets password using recovery token from email.
//
// @Summary      Reset password with recovery token
// @Description  **Route:** `POST /api/v0/seller/auth/reset-password`. Clears session cookie on success.
// @Tags         reseller-auth-password
// @Accept       json
// @Produce      json
// @Param        body  body  SellerResetPasswordSwaggerRequest  true  "Recovery token and new password"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Router       /seller/auth/reset-password [post]
func (a *SellerAuth) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body struct {
		Token           string `json:"token"`
		Password        string `json:"password"`
		MFAPasscode     string `json:"mfaPasscode"`
		MFARecoveryCode string `json:"mfaRecoveryCode"`
	}
	if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if a.badPasswords != nil {
		if _, exists := a.badPasswords[body.Password]; exists {
			a.serveJSONError(ctx, w, ErrValidation.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one."))
			return
		}
	}

	if err = a.service.ResetPasswordReseller(ctx, body.Token, body.Password, body.MFAPasscode, body.MFARecoveryCode, time.Now()); err != nil {
		if console.ErrTooManyAttempts.Has(err) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
				"code":  "too_many_attempts",
			})
			return
		}
		a.serveJSONError(ctx, w, err)
		return
	}
	a.cookieAuth.RemoveTokenCookie(w)
}

// Logout removes auth cookie and session.
//
// @Summary      Logout reseller
// @Description  **Route:** `POST /api/v0/seller/auth/logout`
// @Tags         reseller-auth
// @Security     SellerCookieAuth
// @Success      200
// @Failure      401  {object}  SellerAuthErrorResponse
// @Router       /seller/auth/logout [post]
func (a *SellerAuth) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if err = a.service.DeleteSessionReseller(ctx, sessionID); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	a.cookieAuth.RemoveTokenCookie(w)
}

// RefreshSession refreshes the reseller session.
//
// @Summary      Refresh login session
// @Description  **Route:** `POST /api/v0/seller/auth/refresh-session`
// @Tags         reseller-auth
// @Security     SellerCookieAuth
// @Produce      json
// @Success      200  {string}  string  "New session expiresAt (RFC3339)"
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCSRFAuth
// @Router       /seller/auth/refresh-session [post]
func (a *SellerAuth) RefreshSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenInfo, err := a.cookieAuth.GetToken(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	sessionID, err := uuid.FromBytes(tokenInfo.Token.Payload)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo.ExpiresAt, err = a.service.RefreshSessionReseller(ctx, sessionID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	a.cookieAuth.SetTokenCookie(w, tokenInfo)
	_ = json.NewEncoder(w).Encode(tokenInfo.ExpiresAt)
}

// ActivateAccount verifies signup activation code.
//
// @Summary      Activate reseller account
// @Description  **Route:** `PATCH /api/v0/seller/auth/code-activation`
// @Tags         reseller-auth
// @Accept       json
// @Produce      json
// @Param        body  body  SellerActivateAccountSwaggerRequest  true  "Email and activation code"
// @Success      200   {object}  SellerAuthTokenSwaggerResponse
// @Failure      400   {object}  SellerAuthErrorResponse
// @Router       /seller/auth/code-activation [patch]
func (a *SellerAuth) ActivateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		SignupID string `json:"signupId"`
	}
	if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo, err := a.service.ActivateAccountReseller(ctx, body.Email, body.Code, body.SignupID, ip)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	a.writeTokenResponse(w, tokenInfo)
}

// ResendEmail resends activation or password reset email.
//
// @Summary      Resend activation or reset email
// @Description  **Route:** `POST /api/v0/seller/auth/resend-email`
// @Tags         reseller-auth
// @Accept       json
// @Produce      json
// @Param        body  body  SellerResendEmailSwaggerRequest  true  "Email"
// @Success      200
// @Router       /seller/auth/resend-email [post]
func (a *SellerAuth) ResendEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body struct {
		Email string `json:"email"`
	}
	if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if err = a.service.ResendActivationEmailReseller(ctx, body.Email); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// GetAccount returns authenticated reseller profile.
//
// @Summary      Get reseller account
// @Description  **Route:** `GET /api/v0/seller/auth/account`
// @Tags         reseller-account
// @Security     SellerCookieAuth
// @Produce      json
// @Success      200  {object}  SellerAccountSwaggerResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Router       /seller/auth/account [get]
func (a *SellerAuth) GetAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	account, err := a.service.GetAccountReseller(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(account)
}

// UpdateAccount updates authenticated reseller profile.
//
// @Summary      Update reseller account
// @Description  **Route:** `PATCH /api/v0/seller/auth/account`
// @Tags         reseller-account
// @Security     SellerCookieAuth
// @Accept       json
// @Success      200
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCSRFAuth
// @Router       /seller/auth/account [patch]
func (a *SellerAuth) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		FullName string `json:"fullName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if err := a.service.UpdateAccountReseller(ctx, body.FullName); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// ChangePassword changes password for authenticated reseller.
//
// @Summary      Change password
// @Description  **Route:** `POST /api/v0/seller/auth/account/change-password`
// @Tags         reseller-account
// @Security     SellerCookieAuth
// @Accept       json
// @Param        body  body  SellerChangePasswordSwaggerRequest  true  "Current and new password"
// @Success      200
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCSRFAuth
// @Router       /seller/auth/account/change-password [post]
func (a *SellerAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Password    string `json:"password"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if a.badPasswords != nil {
		if _, exists := a.badPasswords[body.NewPassword]; exists {
			a.serveJSONError(ctx, w, ErrValidation.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one."))
			return
		}
	}
	if err := a.service.ChangePasswordReseller(ctx, body.Password, body.NewPassword); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// SetPassword sets initial password when none is configured.
//
// @Summary      Set initial password
// @Description  **Route:** `POST /api/v0/seller/auth/account/set-password`. Use when `hasPassword` is false.
// @Tags         reseller-account
// @Security     SellerCookieAuth
// @Accept       json
// @Param        body  body  SellerSetPasswordSwaggerRequest  true  "New password"
// @Success      200
// @Failure      409  {object}  SellerAuthErrorResponse
// @Security     SellerCSRFAuth
// @Router       /seller/auth/account/set-password [post]
func (a *SellerAuth) SetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if a.badPasswords != nil {
		if _, exists := a.badPasswords[body.NewPassword]; exists {
			a.serveJSONError(ctx, w, ErrValidation.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one."))
			return
		}
	}
	if err := a.service.SetPasswordReseller(ctx, body.NewPassword); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// GetBadPasswords returns a list of encoded bad passwords.
//
// @Summary      Get bad passwords list
// @Description  **Route:** `GET /api/v0/seller/auth/bad-passwords`
// @Tags         reseller-auth-password
// @Produce      plain
// @Success      200  {string}  string
// @Router       /seller/auth/bad-passwords [get]
func (a *SellerAuth) GetBadPasswords(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"bad-passwords.txt\"")

	if _, err := w.Write([]byte(a.badPasswordsEncoded)); err != nil {
		a.log.Error("could not write encoded bad passwords", zap.Error(err))
	}
}

// EnableUserMFA enables multi-factor authentication for the reseller.
//
// @Summary      Enable MFA
// @Description  **Route:** `POST /api/v0/seller/auth/mfa/enable`. Verifies TOTP passcode, enables MFA, invalidates other sessions, returns new recovery codes.
// @Tags         reseller-mfa
// @Accept       json
// @Produce      json
// @Param        body  body  SellerMFAEnableSwaggerRequest  true  "TOTP passcode"
// @Success      200   {array}  string  "Recovery codes"
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/mfa/enable [post]
func (a *SellerAuth) EnableUserMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		Passcode string `json:"passcode"`
	}
	if err = json.NewDecoder(r.Body).Decode(&data); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.EnableResellerMFA(ctx, data.Passcode, time.Now()); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	reseller, err := GetReseller(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.DeleteAllSessionsByResellerIDExcept(ctx, reseller.ID, sessionID); err != nil {
		a.log.Error("could not delete all other sessions", zap.Error(err))
	}

	codes, err := a.service.ResetResellerMFARecoveryCodes(ctx, false, "", "")
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(codes); err != nil {
		a.log.Error("could not encode MFA recovery codes", zap.Error(err))
	}
}

// DisableUserMFA disables multi-factor authentication for the reseller.
//
// @Summary      Disable MFA
// @Description  **Route:** `POST /api/v0/seller/auth/mfa/disable`
// @Tags         reseller-mfa
// @Accept       json
// @Produce      json
// @Param        body  body  SellerMFADisableSwaggerRequest  true  "Passcode or recovery code"
// @Success      200   "OK"
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/mfa/disable [post]
func (a *SellerAuth) DisableUserMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		Passcode     string `json:"passcode"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if err = json.NewDecoder(r.Body).Decode(&data); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.DisableResellerMFA(ctx, data.Passcode, time.Now(), data.RecoveryCode); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	reseller, err := GetReseller(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.DeleteAllSessionsByResellerIDExcept(ctx, reseller.ID, sessionID); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// GenerateMFASecretKey creates a new TOTP secret key for the reseller.
//
// @Summary      Generate MFA secret key
// @Description  **Route:** `POST /api/v0/seller/auth/mfa/generate-secret-key`. Returns TOTP secret for authenticator app setup (MFA must not already be enabled).
// @Tags         reseller-mfa
// @Produce      json
// @Success      200  {string}  string  "TOTP secret key string"
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/mfa/generate-secret-key [post]
func (a *SellerAuth) GenerateMFASecretKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	key, err := a.service.ResetResellerMFASecretKey(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(key); err != nil {
		a.log.Error("could not encode MFA secret key", zap.Error(err))
	}
}

// GenerateMFARecoveryCodes creates a new set of MFA recovery codes for the reseller.
//
// @Summary      Generate MFA recovery codes
// @Description  **Route:** `POST /api/v0/seller/auth/mfa/generate-recovery-codes`
// @Tags         reseller-mfa
// @Produce      json
// @Success      200  {array}  string  "Recovery codes"
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/mfa/generate-recovery-codes [post]
func (a *SellerAuth) GenerateMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	codes, err := a.service.ResetResellerMFARecoveryCodes(ctx, false, "", "")
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(codes); err != nil {
		a.log.Error("could not encode MFA recovery codes", zap.Error(err))
	}
}

// RegenerateMFARecoveryCodes requires MFA code to create a new set of MFA recovery codes.
//
// @Summary      Regenerate MFA recovery codes
// @Description  **Route:** `POST /api/v0/seller/auth/mfa/regenerate-recovery-codes`
// @Tags         reseller-mfa
// @Accept       json
// @Produce      json
// @Param        body  body  SellerMFARegenerateRecoveryCodesSwaggerRequest  true  "Passcode or recovery code"
// @Success      200   {array}  string  "New recovery codes"
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/mfa/regenerate-recovery-codes [post]
func (a *SellerAuth) RegenerateMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		Passcode     string `json:"passcode"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if err = json.NewDecoder(r.Body).Decode(&data); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	codes, err := a.service.ResetResellerMFARecoveryCodes(ctx, true, data.Passcode, data.RecoveryCode)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(codes); err != nil {
		a.log.Error("could not encode MFA recovery codes", zap.Error(err))
	}
}

// GetActiveSessions gets reseller's active sessions.
//
// @Summary      List active sessions
// @Description  **Route:** `GET /api/v0/seller/auth/sessions`. Query params: `limit`, `page`, `order`, `orderDirection` (all required).
// @Tags         reseller-sessions
// @Produce      json
// @Param        limit            query  int  true  "Page size"
// @Param        page             query  int  true  "Page number (1-based)"
// @Param        order            query  int  true  "Sort field"
// @Param        orderDirection   query  int  true  "Sort direction"
// @Success      200  {object}  SellerWebappSessionsPageSwagger
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/auth/sessions [get]
func (a *SellerAuth) GetActiveSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	query := r.URL.Query()
	limitParam := query.Get("limit")
	if limitParam == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("parameter 'limit' can't be empty"))
		return
	}
	limit, err := strconv.ParseUint(limitParam, 10, 32)
	if err != nil {
		a.serveJSONError(ctx, w, ErrValidation.Wrap(err))
		return
	}

	pageParam := query.Get("page")
	if pageParam == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("parameter 'page' can't be empty"))
		return
	}
	page, err := strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		a.serveJSONError(ctx, w, ErrValidation.Wrap(err))
		return
	}

	orderParam := query.Get("order")
	if orderParam == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("parameter 'order' can't be empty"))
		return
	}
	order, err := strconv.ParseUint(orderParam, 10, 32)
	if err != nil {
		a.serveJSONError(ctx, w, ErrValidation.Wrap(err))
		return
	}

	orderDirectionParam := query.Get("orderDirection")
	if orderDirectionParam == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("parameter 'orderDirection' can't be empty"))
		return
	}
	orderDirection, err := strconv.ParseUint(orderDirectionParam, 10, 32)
	if err != nil {
		a.serveJSONError(ctx, w, ErrValidation.Wrap(err))
		return
	}

	cursor := ResellerWebappSessionsCursor{
		Limit:          uint(limit),
		Page:           uint(page),
		Order:          int8(order),
		OrderDirection: uint8(orderDirection),
	}

	sessionsPage, err := a.service.GetPagedActiveSessionsReseller(ctx, cursor)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	currentSessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	for i, session := range sessionsPage.Sessions {
		if session.ID == currentSessionID {
			sessionsPage.Sessions[i].IsRequesterCurrentSession = true
			break
		}
	}

	if err = json.NewEncoder(w).Encode(sessionsPage); err != nil {
		a.log.Error("failed to write json paged active webapp sessions response", zap.Error(err))
	}
}

// InvalidateSessionByID invalidates reseller session by ID.
//
// @Summary      Invalidate session
// @Description  **Route:** `POST /api/v0/seller/auth/invalidate-session/{id}`
// @Tags         reseller-sessions
// @Produce      json
// @Param        id  path  string  true  "Session ID"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/invalidate-session/{id} [post]
func (a *SellerAuth) InvalidateSessionByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	sessionIDStr, ok := mux.Vars(r)["id"]
	if !ok {
		a.serveJSONError(ctx, w, ErrValidation.New("id parameter is missing"))
		return
	}

	sessionID, err := uuid.FromString(sessionIDStr)
	if err != nil {
		a.serveJSONError(ctx, w, ErrValidation.Wrap(err))
		return
	}

	if err = a.service.InvalidateSessionReseller(ctx, sessionID); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// AccountActionData holds data needed to perform change email actions.
type AccountActionData struct {
	Step console.AccountActionStep `json:"step"`
	Data string                    `json:"data"`
}

// ChangeEmail handles change email flow requests.
//
// @Summary      Change email
// @Description  **Route:** `POST /api/v0/seller/auth/change-email`. Multi-step flow using `step` and `data` (same steps as console change email).
// @Tags         reseller-account
// @Accept       json
// @Produce      json
// @Param        body  body  SellerAccountActionSwaggerRequest  true  "Step and payload"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/change-email [post]
func (a *SellerAuth) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data AccountActionData
	if err = json.NewDecoder(r.Body).Decode(&data); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if data.Step < console.VerifyAccountPasswordStep || data.Step > console.VerifyNewAccountEmailStep {
		a.serveJSONError(ctx, w, ErrValidation.New("step value is out of range"))
		return
	}
	if data.Data == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("data value can't be empty"))
		return
	}

	if err = a.service.ChangeEmailReseller(ctx, data.Step, data.Data); err != nil {
		a.serveJSONError(ctx, w, err)
	}
}

// DeleteAccountRequest starts the account deletion workflow.
//
// @Summary      Request account deletion
// @Description  **Route:** `POST /api/v0/seller/auth/account/delete-request`. Sends confirmation email when self-serve delete is enabled.
// @Tags         reseller-account
// @Produce      json
// @Success      202
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/auth/account/delete-request [post]
func (a *SellerAuth) DeleteAccountRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if err = a.service.DeleteAccountRequestReseller(ctx); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// DeleteAccount deletes a reseller account by email with admin verification password.
//
// @Summary      Delete account (admin)
// @Description  **Route:** `DELETE /api/v0/seller/auth/account`. Requires admin verification password in body.
// @Tags         reseller-account
// @Accept       json
// @Produce      json
// @Param        body  body  SellerDeleteAccountSwaggerRequest  true  "Email and admin password"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/auth/account [delete]
func (a *SellerAuth) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var requestData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = json.Unmarshal(body, &requestData); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if requestData.Email == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("email is required"))
		return
	}
	if requestData.Password == "" {
		a.serveJSONError(ctx, w, ErrValidation.New("password is required"))
		return
	}

	const hardcodedPassword = "StorX@2024#Secure!Admin"
	if requestData.Password != hardcodedPassword {
		a.serveJSONError(ctx, w, console.ErrUnauthorized.New("invalid password"))
		return
	}

	if err = a.service.DeleteAccountReseller(ctx, requestData.Email); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Account deleted successfully",
	})
}

func (a *SellerAuth) completeGoogleLogin(w http.ResponseWriter, ctx context.Context, reseller *Reseller, ip string) {
	tokenInfo, err := a.service.GenerateSessionTokenForReseller(ctx, reseller.ID, reseller.Email, ip, nil)
	if err != nil {
		socialmedia.WriteCombinedGoogleAuthError(w, "Error creating session!")
		return
	}

	a.cookieAuth.SetTokenCookie(w, *tokenInfo)
	socialmedia.WriteCombinedGoogleAuthSuccess(w, socialmedia.GoogleAuthActionLoggedIn, map[string]interface{}{
		"token":    tokenInfo.Token.String(),
		"reseller": resellerResponse(reseller),
	})
}

func (a *SellerAuth) completeGoogleRegister(w http.ResponseWriter, ctx context.Context, session *socialmedia.GoogleAuthSession, ip string) {
	reseller, err := a.service.CreateResellerFromGoogle(ctx, session.User.Name, session.User.Email, session.User.Name)
	if err != nil {
		a.log.Error("seller google auth: failed to register reseller", zap.Error(err))
		socialmedia.WriteCombinedGoogleAuthError(w, "Error creating reseller!")
		return
	}

	tokenInfo, err := a.service.GenerateSessionTokenForReseller(ctx, reseller.ID, reseller.Email, ip, nil)
	if err != nil {
		socialmedia.WriteCombinedGoogleAuthError(w, "Error creating session!")
		return
	}

	a.cookieAuth.SetTokenCookie(w, *tokenInfo)
	socialmedia.WriteCombinedGoogleAuthSuccess(w, socialmedia.GoogleAuthActionRegistered, map[string]interface{}{
		"token":    tokenInfo.Token.String(),
		"reseller": resellerResponse(reseller),
	})
}

func (a *SellerAuth) writeTokenResponse(w http.ResponseWriter, tokenInfo *console.TokenInfo) {
	a.cookieAuth.SetTokenCookie(w, *tokenInfo)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		console.TokenInfo
		Token string `json:"token"`
	}{*tokenInfo, tokenInfo.Token.String()})
}

func (a *SellerAuth) getSessionID(r *http.Request) (uuid.UUID, error) {
	tokenInfo, err := a.cookieAuth.GetToken(r)
	if err != nil {
		return uuid.UUID{}, err
	}
	return uuid.FromBytes(tokenInfo.Token.Payload)
}

func (a *SellerAuth) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	switch {
	case ErrValidation.Has(err), ErrCaptcha.Has(err), ErrActivationCode.Has(err):
		status = http.StatusBadRequest
	case ErrAlreadyMember.Has(err):
		status = http.StatusConflict
	case ErrPasswordAlreadySet.Has(err):
		status = http.StatusConflict
	case console.ErrMFAMissing.Has(err):
		status = http.StatusOK
	case console.ErrMFAPasscode.Has(err), console.ErrMFARecoveryCode.Has(err), console.ErrMFAConflict.Has(err):
		status = http.StatusBadRequest
	case console.ErrForbidden.Has(err):
		status = http.StatusForbidden
	case console.ErrConflict.Has(err):
		status = http.StatusConflict
	case console.ErrTooManyAttempts.Has(err):
		status = http.StatusBadRequest
	case ErrTokenExpiration.Has(err):
		status = http.StatusUnauthorized
	case ErrLoginCredentials.Has(err), ErrChangePassword.Has(err):
		status = http.StatusUnauthorized
	default:
		if !Error.Has(err) && !errs.Is(err, context.Canceled) {
			status = http.StatusBadRequest
		}
	}
	web.ServeCustomJSONError(ctx, a.log, w, status, err, err.Error())
}

func resellerResponse(reseller *Reseller) map[string]interface{} {
	return map[string]interface{}{
		"id":    reseller.ID,
		"email": reseller.Email,
		"name":  reseller.Name,
	}
}

func serveAuthJSONError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// withAuthSeller validates seller session cookie.
func (server *Server) withAuthSeller(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx := r.Context()
		defer mon.Task()(&ctx)(&err)

		defer func() {
			if err != nil {
				serveAuthJSONError(w, Error.Wrap(err))
				if server.cookieAuth != nil {
					server.cookieAuth.RemoveTokenCookie(w)
				}
			}
		}()

		tokenInfo, err := server.cookieAuth.GetToken(r)
		if err != nil {
			return
		}

		newCtx, err := server.service.TokenAuthForReseller(ctx, tokenInfo.Token, time.Now())
		if err != nil {
			return
		}

		handler.ServeHTTP(w, r.Clone(newCtx))
	})
}
