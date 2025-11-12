// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

// This file has been moved to satellite/developer/auth_controller.go
// All developer endpoints are now handled by the separate developer server
// Commenting out to prevent accidental usage

package consoleapi

/*

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"storj.io/common/http/requestid"
	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consoleapi/utils"
	"storj.io/storj/satellite/console/consoleweb/consolewebauth"
	"storj.io/storj/satellite/developer"

	"storj.io/storj/satellite/mailservice"
)

var (
	ErrDeveloperAuthAPI = errs.Class("consoleapi developer auth")
)

// DeveloperAuth is an api controller that exposes all auth functionality.
type DeveloperAuth struct {
	log                       *zap.Logger
	ExternalAddress           string
	LetUsKnowURL              string
	TermsAndConditionsURL     string
	ContactInfoURL            string
	GeneralRequestURL         string
	PasswordRecoveryURL       string
	CancelPasswordRecoveryURL string
	ActivateAccountURL        string
	ActivationCodeEnabled     bool
	SatelliteName             string
	badPasswords              map[string]struct{}
	service                   *console.Service
	accountFreezeService      *console.AccountFreezeService
	analytics                 *analytics.Service
	mailService               *mailservice.Service
	cookieAuth                *consolewebauth.CookieAuth
	developerRegisterAPIKey   string
	developerService          *developer.Service
}

// DeveloperDetails is struct used for developer details
type DeveloperDetails struct {
	Name     string
	Email    string
	Password string
}

// NewDeveloperAuth is a constructor for api auth controller.
func NewDeveloperAuth(log *zap.Logger, service *console.Service, developerService *developer.Service, accountFreezeService *console.AccountFreezeService,
	mailService *mailservice.Service, cookieAuth *consolewebauth.CookieAuth, analytics *analytics.Service, satelliteName,
	externalAddress, letUsKnowURL, termsAndConditionsURL, contactInfoURL, generalRequestURL, developerRegisterAPIKey string,
	activationCodeEnabled bool, badPasswords map[string]struct{}) *DeveloperAuth {
	return &DeveloperAuth{
		log:                       log,
		ExternalAddress:           externalAddress,
		LetUsKnowURL:              letUsKnowURL,
		TermsAndConditionsURL:     termsAndConditionsURL,
		ContactInfoURL:            contactInfoURL,
		GeneralRequestURL:         generalRequestURL,
		SatelliteName:             satelliteName,
		PasswordRecoveryURL:       externalAddress + "password-recovery",
		CancelPasswordRecoveryURL: externalAddress + "cancel-password-recovery",
		ActivateAccountURL:        externalAddress + "activation",
		ActivationCodeEnabled:     activationCodeEnabled,
		service:                   service,
		developerService:          developerService,
		accountFreezeService:      accountFreezeService,
		mailService:               mailService,
		cookieAuth:                cookieAuth,
		analytics:                 analytics,
		badPasswords:              badPasswords,
		developerRegisterAPIKey:   developerRegisterAPIKey,
	}
}

// Token authenticates developer by credentials and returns auth token.
func (a *DeveloperAuth) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenRequest := console.AuthDeveloper{}
	err = json.NewDecoder(r.Body).Decode(&tokenRequest)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenRequest.UserAgent = r.UserAgent()
	tokenRequest.IP, err = web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo, err := a.developerService.TokenDeveloper(ctx, tokenRequest)
	if err != nil {
		if console.ErrMFAMissing.Has(err) {
			web.ServeCustomJSONError(ctx, a.log, w, http.StatusOK, err, a.getDeveloperErrorMessage(err))
		} else {
			a.log.Info("Error authenticating token request", zap.String("email", tokenRequest.Email), zap.Error(ErrAuthAPI.Wrap(err)))
			a.serveJSONError(ctx, w, err)
		}
		return
	}

	a.cookieAuth.SetTokenCookie(w, *tokenInfo)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(struct {
		console.TokenInfo
		Token string `json:"token"`
	}{*tokenInfo, tokenInfo.Token.String()})
	if err != nil {
		a.log.Error("token handler could not encode token response", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// getSessionID gets the session ID from the request.
func (a *DeveloperAuth) getSessionID(r *http.Request) (id uuid.UUID, err error) {

	tokenInfo, err := a.cookieAuth.GetToken(r)
	if err != nil {
		return uuid.UUID{}, err
	}

	sessionID, err := uuid.FromBytes(tokenInfo.Token.Payload)
	if err != nil {
		return uuid.UUID{}, err
	}

	return sessionID, nil
}

// Logout removes auth cookie.
func (a *DeveloperAuth) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	w.Header().Set("Content-Type", "application/json")

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = a.developerService.DeleteSessionDeveloper(ctx, sessionID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	a.cookieAuth.RemoveTokenCookie(w)
}

// Register creates new developer, sends activation e-mail.
// If a user with the given e-mail address already exists, a password reset e-mail is sent instead.
func (a *DeveloperAuth) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if a.developerRegisterAPIKey != "" && r.Header.Get("API-KEY") != a.developerRegisterAPIKey {
		a.serveJSONError(ctx, w, console.ErrUnauthorized.Wrap(errs.New("Invalid API key.")))
		return
	}

	var registerData struct {
		FullName    string `json:"fullName"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		SecretInput string `json:"secret"`
		CompanyName string `json:"companyName"`
	}

	err = json.NewDecoder(r.Body).Decode(&registerData)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// trim leading and trailing spaces of email address.
	registerData.Email = strings.TrimSpace(registerData.Email)

	isValidEmail := utils.ValidateEmail(registerData.Email)
	if !isValidEmail {
		a.serveJSONError(ctx, w, console.ErrValidation.Wrap(errs.New("Invalid email.")))
		return
	}

	if a.badPasswords != nil {
		_, exists := a.badPasswords[registerData.Password]
		if exists {
			a.serveJSONError(ctx, w, console.ErrValidation.Wrap(errs.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one.")))
			return
		}
	}

	verified, unverified, err := a.developerService.GetDeveloperByEmailWithUnverified(ctx, registerData.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.serveJSONError(ctx, w, err)
		return
	}

	if verified != nil {
		// satelliteAddress := a.ExternalAddress
		// if !strings.HasSuffix(satelliteAddress, "/") {
		// 	satelliteAddress += "/"
		// }
		// a.mailService.SendRenderedAsync(
		// 	ctx,
		// 	[]post.Address{{Address: verified.Email}},
		// 	&console.AccountAlreadyExistsEmail{
		// 		Origin:            satelliteAddress,
		// 		SatelliteName:     a.SatelliteName,
		// 		SignInLink:        satelliteAddress + "login",
		// 		ResetPasswordLink: satelliteAddress + "forgot-password",
		// 		CreateAccountLink: satelliteAddress + "signup",
		// 	},
		// )

		a.serveJSONError(ctx, w, console.ErrAlreadyMember.Wrap(errs.New("The requested Email ID is already registered. Please try again using a different email address.")))
		return
	}

	// var developer *console.Developer
	if len(unverified) > 0 {
		// developer = &unverified[0]
		a.serveJSONError(ctx, w, fmt.Errorf("unverfied developer found"))
	} else {
		secret, err := console.RegistrationSecretFromBase64(registerData.SecretInput)
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}

		var code string
		var requestID string
		if a.ActivationCodeEnabled {
			randNum, err := rand.Int(rand.Reader, big.NewInt(900000))
			if err != nil {
				a.serveJSONError(ctx, w, console.Error.Wrap(err))
				return
			}
			randNum = randNum.Add(randNum, big.NewInt(100000))
			code = randNum.String()

			requestID = requestid.FromContext(ctx)
		}

		_, err = a.developerService.CreateDeveloper(ctx,
			console.CreateDeveloper{
				FullName:       registerData.FullName,
				Email:          registerData.Email,
				Password:       registerData.Password,
				CompanyName:    registerData.CompanyName,
				ActivationCode: code,
				SignupId:       requestID,
			}, secret,
		)
		if err != nil {
			if !console.ErrEmailUsed.Has(err) {
				a.serveJSONError(ctx, w, err)
			}
			return
		}

	}

	// if a.ActivationCodeEnabled {
	// 	*developer, err = a.service.SetActivationCodeAndSignupIDForDeveloper(ctx, *developer)
	// 	if err != nil {
	// 		a.serveJSONError(ctx, w, err)
	// 		return
	// 	}

	// 	a.mailService.SendRenderedAsync(
	// 		ctx,
	// 		[]post.Address{{Address: developer.Email}},
	// 		&console.AccountActivationCodeEmail{
	// 			ActivationCode: developer.ActivationCode,
	// 		},
	// 	)

	// 	return
	// }
	// token, err := a.service.GenerateActivationToken(ctx, developer.ID, developer.Email)
	// if err != nil {
	// 	a.serveJSONError(ctx, w, err)
	// 	return
	// }

	// link := a.ActivateAccountURL + "?token=" + token

	// a.mailService.SendRenderedAsync(
	// 	ctx,
	// 	[]post.Address{{Address: developer.Email}},
	// 	&console.AccountActivationEmail{
	// 		ActivationLink: link,
	// 		Origin:         a.ExternalAddress,
	// 	},
	// )

}

// ActivateAccount verifies a signup activation code.
func (a *DeveloperAuth) ActivateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var activateData struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		SignupId string `json:"signupId"`
	}
	err = json.NewDecoder(r.Body).Decode(&activateData)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	verified, unverified, err := a.developerService.GetDeveloperByEmailWithUnverified(ctx, activateData.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.serveJSONError(ctx, w, err)
		return
	}

	if verified != nil {
		// satelliteAddress := a.ExternalAddress
		// if !strings.HasSuffix(satelliteAddress, "/") {
		// 	satelliteAddress += "/"
		// }
		// a.mailService.SendRenderedAsync(
		// 	ctx,
		// 	[]post.Address{{Address: verified.Email}},
		// 	&console.AccountAlreadyExistsEmail{
		// 		Origin:            satelliteAddress,
		// 		SatelliteName:     a.SatelliteName,
		// 		SignInLink:        satelliteAddress + "login",
		// 		ResetPasswordLink: satelliteAddress + "forgot-password",
		// 		CreateAccountLink: satelliteAddress + "signup",
		// 	},
		// )
		// return error since verified developer already exists.
		a.serveJSONError(ctx, w, console.ErrUnauthorized.New("developer already verified"))
		return
	}

	var developer *console.Developer
	if len(unverified) == 0 {
		a.serveJSONError(ctx, w, console.ErrEmailNotFound.New("no unverified developer found"))
		return
	}
	developer = &unverified[0]

	now := time.Now()

	if developer.LoginLockoutExpiration.After(now) {
		a.serveJSONError(ctx, w, console.ErrActivationCode.New("invalid activation code or account locked"))
		return
	}

	if developer.ActivationCode != activateData.Code || developer.SignupId != activateData.SignupId {
		lockoutDuration, err := a.developerService.UpdateDevelopersFailedLoginState(ctx, developer)
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}
		if lockoutDuration > 0 {
			// a.mailService.SendRenderedAsync(
			// 	ctx,
			// 	[]post.Address{{Address: developer.Email, Name: developer.FullName}},
			// 	&console.ActivationLockAccountEmail{
			// 		LockoutDuration: lockoutDuration,
			// 		SupportURL:      a.GeneralRequestURL,
			// 	},
			// )
		}

		mon.Counter("developer_account_activation_failed").Inc(1)                                                    //mon:locked
		mon.IntVal("developer_account_activation_developer_failed_count").Observe(int64(developer.FailedLoginCount)) //mon:locked
		penaltyThreshold := a.developerService.GetLoginAttemptsWithoutPenalty()

		if developer.FailedLoginCount == penaltyThreshold {
			mon.Counter("developer_account_activation_lockout_initiated").Inc(1) //mon:locked
		}

		if developer.FailedLoginCount > penaltyThreshold {
			mon.Counter("developer_account_activation_lockout_reinitiated").Inc(1) //mon:locked
		}

		a.serveJSONError(ctx, w, console.ErrActivationCode.New("invalid activation code or account locked"))
		return
	}

	if developer.FailedLoginCount != 0 {
		if err := a.developerService.ResetAccountLockDeveloper(ctx, developer); err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}
	}

	err = a.developerService.SetAccountActiveDeveloper(ctx, developer)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo, err := a.developerService.GenerateSessionTokenForDeveloper(ctx, developer.ID, developer.Email, ip, nil)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	a.cookieAuth.SetTokenCookie(w, *tokenInfo)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(struct {
		console.TokenInfo
		Token string `json:"token"`
	}{*tokenInfo, tokenInfo.Token.String()})
	if err != nil {
		a.log.Error("could not encode token response", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// UpdateAccount updates developers's full name and short name.
func (a *DeveloperAuth) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var updatedInfo struct {
		FullName string `json:"fullName"`
	}

	err = json.NewDecoder(r.Body).Decode(&updatedInfo)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.developerService.UpdateAccountDeveloper(ctx, updatedInfo.FullName); err != nil {
		a.serveJSONError(ctx, w, err)
	}
}

// GetAccount gets authorized developer and take it's params.
func (a *DeveloperAuth) GetAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var developer struct {
		ID                  uuid.UUID `json:"id"`
		FullName            string    `json:"fullName"`
		Email               string    `json:"email"`
		CompanyName         string    `json:"companyName"`
		CreatedAt           time.Time `json:"createdAt"`
		PendingVerification bool      `json:"pendingVerification"`
	}

	consoleDeveloper, err := console.GetDeveloper(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	developer.FullName = consoleDeveloper.FullName
	developer.Email = consoleDeveloper.Email
	developer.ID = consoleDeveloper.ID

	developer.CompanyName = consoleDeveloper.CompanyName
	developer.CreatedAt = consoleDeveloper.CreatedAt
	developer.PendingVerification = consoleDeveloper.Status == console.PendingBotVerification

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&developer)
	if err != nil {
		a.log.Error("could not encode developer info", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// ChangePassword auth developer, changes developers password for a new one.
func (a *DeveloperAuth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var passwordChange struct {
		CurrentPassword string `json:"password"`
		NewPassword     string `json:"newPassword"`
	}

	err = json.NewDecoder(r.Body).Decode(&passwordChange)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if a.badPasswords != nil {
		_, exists := a.badPasswords[passwordChange.NewPassword]
		if exists {
			a.serveJSONError(ctx, w, console.ErrValidation.Wrap(errs.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one.")))
			return
		}
	}

	err = a.developerService.ChangePasswordDeveloper(ctx, passwordChange.CurrentPassword, passwordChange.NewPassword)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// RefreshSession refreshes the developer's session.
func (a *DeveloperAuth) RefreshSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenInfo, err := a.cookieAuth.GetToken(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	id, err := uuid.FromBytes(tokenInfo.Token.Payload)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo.ExpiresAt, err = a.developerService.RefreshSessionDeveloper(ctx, id)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	a.cookieAuth.SetTokenCookie(w, tokenInfo)

	err = json.NewEncoder(w).Encode(tokenInfo.ExpiresAt)
	if err != nil {
		a.log.Error("could not encode refreshed session expiration date", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// serveJSONError writes JSON error to response output stream.
func (a *DeveloperAuth) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	status := a.getStatusCode(err)
	web.ServeCustomJSONError(ctx, a.log, w, status, err, a.getDeveloperErrorMessage(err))
}

// getStatusCode returns http.StatusCode depends on console error class.
func (a *DeveloperAuth) getStatusCode(err error) int {
	var maxBytesError *http.MaxBytesError

	switch {
	case console.ErrValidation.Has(err), console.ErrCaptcha.Has(err), console.ErrMFAMissing.Has(err), console.ErrMFAPasscode.Has(err), console.ErrMFARecoveryCode.Has(err), console.ErrChangePassword.Has(err), console.ErrInvalidProjectLimit.Has(err):
		return http.StatusBadRequest
	case console.ErrUnauthorized.Has(err), console.ErrTokenExpiration.Has(err), console.ErrRecoveryToken.Has(err), console.ErrLoginCredentials.Has(err), console.ErrActivationCode.Has(err):
		return http.StatusUnauthorized
	case console.ErrEmailUsed.Has(err), console.ErrMFAConflict.Has(err):
		return http.StatusConflict
	case console.ErrLoginRestricted.Has(err):
		return http.StatusForbidden
	case errors.Is(err, errNotImplemented):
		return http.StatusNotImplemented
	case console.ErrNotPaidTier.Has(err):
		return http.StatusPaymentRequired
	case errors.As(err, &maxBytesError):
		return http.StatusRequestEntityTooLarge
	case console.ErrAlreadyMember.Has(err):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// getDeveloperErrorMessage returns a user-friendly representation of the error.
func (a *DeveloperAuth) getDeveloperErrorMessage(err error) string {
	var maxBytesError *http.MaxBytesError

	switch {
	case console.ErrCaptcha.Has(err):
		return "Validation of captcha was unsuccessful"
	case console.ErrRegToken.Has(err):
		return "We are unable to create your account. This is an invite-only alpha, please join our waitlist to receive an invitation"
	case console.ErrEmailUsed.Has(err):
		return "This email is already in use; try another"
	case console.ErrRecoveryToken.Has(err):
		if console.ErrTokenExpiration.Has(err) {
			return "The recovery token has expired"
		}
		return "The recovery token is invalid"
	case console.ErrMFAMissing.Has(err):
		return "A MFA passcode or recovery code is required"
	case console.ErrMFAConflict.Has(err):
		return "Expected either passcode or recovery code, but got both"
	case console.ErrMFAPasscode.Has(err):
		return "The MFA passcode is not valid or has expired"
	case console.ErrMFARecoveryCode.Has(err):
		return "The MFA recovery code is not valid or has been previously used"
	case console.ErrLoginCredentials.Has(err):
		return "Your login credentials are incorrect, please try again"
	case console.ErrLoginRestricted.Has(err):
		return "You can't be authenticated. Please contact support"
	case console.ErrValidation.Has(err), console.ErrChangePassword.Has(err), console.ErrInvalidProjectLimit.Has(err), console.ErrNotPaidTier.Has(err):
		return err.Error()
	case errors.Is(err, errNotImplemented):
		return "The server is incapable of fulfilling the request"
	case errors.As(err, &maxBytesError):
		return "Request body is too large"
	case console.ErrActivationCode.Has(err):
		return "The activation code is invalid"
	default:
		return "There was an error processing your request" + err.Error()
	}
}

func (a *DeveloperAuth) CreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	var req console.CreateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// TODO: Get developerID from auth context/session if needed
	client, err := a.developerService.CreateDeveloperOAuthClient(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]string{
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
	}
	json.NewEncoder(w).Encode(resp)
}

func (a *DeveloperAuth) ListOAuthClients(w http.ResponseWriter, r *http.Request) {
	// TODO: Get developerID from auth context/session
	clients, err := a.developerService.ListDeveloperOAuthClients(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(clients)
}

func (a *DeveloperAuth) DeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := a.developerService.DeleteDeveloperOAuthClient(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DeveloperAuth) UpdateOAuthClientStatus(w http.ResponseWriter, r *http.Request) {
	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct{ Status int }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := a.developerService.UpdateDeveloperOAuthClientStatus(r.Context(), id, req.Status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// VerifyResetToken verifies the JWT token from email link for password reset.
func (a *DeveloperAuth) VerifyResetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	token := r.URL.Query().Get("token")
	if token == "" {
		a.serveJSONError(ctx, w, console.ErrValidation.New("token is required"))
		return
	}

	developer, err := a.developerService.VerifyTokenForDeveloper(ctx, token)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Return developer info (without sensitive data)
	response := struct {
		Email    string `json:"email"`
		FullName string `json:"fullName"`
		Valid    bool   `json:"valid"`
	}{
		Email:    developer.Email,
		FullName: developer.FullName,
		Valid:    true,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		a.log.Error("could not encode token verification response", zap.Error(ErrDeveloperAuthAPI.Wrap(err)))
		return
	}
}

// ResetPasswordWithToken resets developer password using JWT token from email.
func (a *DeveloperAuth) ResetPasswordWithToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var resetData struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	err = json.NewDecoder(r.Body).Decode(&resetData)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if resetData.Token == "" {
		a.serveJSONError(ctx, w, console.ErrValidation.New("token is required"))
		return
	}

	if resetData.NewPassword == "" {
		a.serveJSONError(ctx, w, console.ErrValidation.New("new password is required"))
		return
	}

	if a.badPasswords != nil {
		_, exists := a.badPasswords[resetData.NewPassword]
		if exists {
			a.serveJSONError(ctx, w, console.ErrValidation.Wrap(errs.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one.")))
			return
		}
	}

	err = a.developerService.ResetPasswordWithToken(ctx, resetData.Token, resetData.NewPassword)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Success bool `json:"success"`
	}{Success: true})
}

// ResetPasswordAfterFirstLogin resets password for developer with ResetPass status after first login.
func (a *DeveloperAuth) ResetPasswordAfterFirstLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Get developer from context (must be authenticated)
	developer, err := console.GetDeveloper(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Only allow if status is ResetPass
	if developer.Status != console.ResetPass {
		a.serveJSONError(ctx, w, console.ErrValidation.New("password reset is only allowed for accounts in reset password status"))
		return
	}

	var passwordData struct {
		NewPassword string `json:"newPassword"`
	}

	err = json.NewDecoder(r.Body).Decode(&passwordData)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if passwordData.NewPassword == "" {
		a.serveJSONError(ctx, w, console.ErrValidation.New("new password is required"))
		return
	}

	if a.badPasswords != nil {
		_, exists := a.badPasswords[passwordData.NewPassword]
		if exists {
			a.serveJSONError(ctx, w, console.ErrValidation.Wrap(errs.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one.")))
			return
		}
	}

	// Validate new password
	if err := console.ValidateNewPassword(passwordData.NewPassword); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(passwordData.NewPassword), 0)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Update password and set status to Active
	activeStatus := console.Active
	_, err = a.developerService.UpdateDeveloperAdmin(ctx, developer.Email, console.UpdateDeveloperRequest{
		PasswordHash: hash,
		Status:       &activeStatus,
	})
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Delete all existing sessions to force re-login
	// Get session ID from request
	sessionID, err := a.getSessionID(r)
	if err == nil {
		// Delete this session and all others
		_ = a.developerService.DeleteSessionDeveloper(ctx, sessionID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Success bool `json:"success"`
	}{Success: true})
}
*/
