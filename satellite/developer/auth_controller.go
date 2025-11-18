// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
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
	"storj.io/storj/satellite/console/consoleweb/consolewebauth"
	"storj.io/storj/satellite/mailservice"
)

var (
	ErrDeveloperAuthAPI = errs.Class("developer auth api")
	errNotImplemented   = errs.New("not implemented")
)

// validateEmail validates email to have correct form and syntax.
func validateEmail(email string) bool {
	// This regular expression was built according to RFC 5322 and then extended to include international characters.
	re := regexp.MustCompile(`^(?:[a-z0-9\p{L}!#$%&'*+/=?^_{|}~\x60-]+(?:\.[a-z0-9\p{L}!#$%&'*+/=?^_{|}~\x60-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9\p{L}](?:[a-z0-9\p{L}-]*[a-z0-9\p{L}])?\.)+[a-z0-9\p{L}](?:[a-z\p{L}]*[a-z\p{L}])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9\p{L}-]*[a-z0-9\p{L}]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$`)
	match := re.MatchString(email)
	return match
}

// DeveloperAuth is an api controller that exposes all auth functionality.
type DeveloperAuth struct {
	log                     *zap.Logger
	ExternalAddress         string
	LetUsKnowURL            string
	TermsAndConditionsURL   string
	ContactInfoURL          string
	GeneralRequestURL       string
	ActivationCodeEnabled   bool
	SatelliteName           string
	badPasswords            map[string]struct{}
	service                 *console.Service
	accountFreezeService    *console.AccountFreezeService
	analytics               *analytics.Service
	mailService             *mailservice.Service
	cookieAuth              *consolewebauth.CookieAuth
	developerRegisterAPIKey string
	developerService        *Service
}

// NewDeveloperAuth is a constructor for api auth controller.
func NewDeveloperAuth(log *zap.Logger, service *console.Service, developerService *Service, accountFreezeService *console.AccountFreezeService,
	mailService *mailservice.Service, cookieAuth *consolewebauth.CookieAuth, analytics *analytics.Service, satelliteName,
	externalAddress, letUsKnowURL, termsAndConditionsURL, contactInfoURL, generalRequestURL, developerRegisterAPIKey string,
	activationCodeEnabled bool, badPasswords map[string]struct{}) *DeveloperAuth {
	return &DeveloperAuth{
		log:                     log,
		ExternalAddress:         externalAddress,
		LetUsKnowURL:            letUsKnowURL,
		TermsAndConditionsURL:   termsAndConditionsURL,
		ContactInfoURL:          contactInfoURL,
		GeneralRequestURL:       generalRequestURL,
		SatelliteName:           satelliteName,
		ActivationCodeEnabled:   activationCodeEnabled,
		service:                 service,
		developerService:        developerService,
		accountFreezeService:    accountFreezeService,
		mailService:             mailService,
		cookieAuth:              cookieAuth,
		analytics:               analytics,
		badPasswords:            badPasswords,
		developerRegisterAPIKey: developerRegisterAPIKey,
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
			a.log.Info("Error authenticating token request", zap.String("email", tokenRequest.Email), zap.Error(ErrDeveloperAuthAPI.Wrap(err)))
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
		a.log.Error("token handler could not encode token response", zap.Error(ErrDeveloperAuthAPI.Wrap(err)))
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

	isValidEmail := validateEmail(registerData.Email)
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
		a.serveJSONError(ctx, w, console.ErrAlreadyMember.Wrap(errs.New("The requested Email ID is already registered. Please try again using a different email address.")))
		return
	}

	if len(unverified) > 0 {
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
				a.serveJSONError(ctx, w, Error.Wrap(err))
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
			// Lockout email can be sent here if needed
		}

		mon.Counter("developer_account_activation_failed").Inc(1)
		mon.IntVal("developer_account_activation_developer_failed_count").Observe(int64(developer.FailedLoginCount))
		penaltyThreshold := a.developerService.GetLoginAttemptsWithoutPenalty()

		if developer.FailedLoginCount == penaltyThreshold {
			mon.Counter("developer_account_activation_lockout_initiated").Inc(1)
		}

		if developer.FailedLoginCount > penaltyThreshold {
			mon.Counter("developer_account_activation_lockout_reinitiated").Inc(1)
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
		a.log.Error("could not encode token response", zap.Error(ErrDeveloperAuthAPI.Wrap(err)))
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
		Status              int       `json:"status"`
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
	developer.Status = int(consoleDeveloper.Status)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&developer)
	if err != nil {
		a.log.Error("could not encode developer info", zap.Error(ErrDeveloperAuthAPI.Wrap(err)))
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
		a.log.Error("could not encode refreshed session expiration date", zap.Error(ErrDeveloperAuthAPI.Wrap(err)))
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

func (a *DeveloperAuth) GetOAuthClient(w http.ResponseWriter, r *http.Request) {
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

	client, err := a.developerService.GetDeveloperOAuthClient(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

func (a *DeveloperAuth) RegenerateOAuthClientSecret(w http.ResponseWriter, r *http.Request) {
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

	client, err := a.developerService.RegenerateDeveloperOAuthClientSecret(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *DeveloperAuth) UpdateOAuthClient(w http.ResponseWriter, r *http.Request) {
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

	var req console.UpdateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	client, err := a.developerService.UpdateDeveloperOAuthClient(r.Context(), id, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// AddRedirectURI adds a redirect URI to an OAuth client.
func (a *DeveloperAuth) AddRedirectURI(w http.ResponseWriter, r *http.Request) {
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

	var req console.AddRedirectURIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	client, err := a.developerService.AddRedirectURI(r.Context(), id, req.URI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// UpdateRedirectURI updates a redirect URI in an OAuth client.
func (a *DeveloperAuth) UpdateRedirectURI(w http.ResponseWriter, r *http.Request) {
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

	var req console.UpdateRedirectURIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	client, err := a.developerService.UpdateRedirectURI(r.Context(), id, req.OldURI, req.NewURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// DeleteRedirectURI removes a redirect URI from an OAuth client.
func (a *DeveloperAuth) DeleteRedirectURI(w http.ResponseWriter, r *http.Request) {
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

	var req console.DeleteRedirectURIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	client, err := a.developerService.DeleteRedirectURI(r.Context(), id, req.URI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
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

	// Check if new password is the same as current temporary password
	err = bcrypt.CompareHashAndPassword(developer.PasswordHash, []byte(passwordData.NewPassword))
	if err == nil {
		a.serveJSONError(ctx, w, console.ErrValidation.New("new password must be different from your current temporary password"))
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
	sessionID, err := a.getSessionID(r)
	if err == nil {
		_ = a.developerService.DeleteSessionDeveloper(ctx, sessionID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Success bool `json:"success"`
	}{Success: true})
}

// ListAccessLogs handles GET /api/v0/developer/auth/access-logs
// parseAccessLogFilters parses and validates all query parameters for access log listing
func (a *DeveloperAuth) parseAccessLogFilters(r *http.Request) (*AccessLogFilters, error) {
	query := r.URL.Query()
	filters := &AccessLogFilters{}

	// Parse pagination - use local variables first
	var limitValue uint64
	var pageValue uint64
	var fetchAll bool

	limitParam := query.Get("limit")
	if limitParam == "" {
		limitParam = "50" // Default limit
	}

	if limitParam == "-1" || limitParam == "0" {
		fetchAll = true
	} else {
		var err error
		limitValue, err = strconv.ParseUint(limitParam, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parameter 'limit' must be a valid number: %w", err)
		}
	}

	pageParam := query.Get("page")
	if pageParam == "" {
		pageParam = "1"
	}
	var err error
	pageValue, err = strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parameter 'page' must be a valid number: %w", err)
	}

	// Store in struct fields
	filters.FetchAll = fetchAll
	if !fetchAll {
		filters.Limit = int(limitValue)
		filters.Page = pageValue
	} else {
		filters.Limit = 0
		filters.Page = 1
	}

	// Parse date range filters
	if startDateStr := query.Get("start_date"); startDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filters.StartDate = &parsed
		} else {
			return nil, fmt.Errorf("invalid 'start_date' format: %w", err)
		}
	}
	if endDateStr := query.Get("end_date"); endDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filters.EndDate = &parsed
		} else {
			return nil, fmt.Errorf("invalid 'end_date' format: %w", err)
		}
	}

	// Parse status filter
	if statusStr := query.Get("status"); statusStr != "" {
		if parsed, err := strconv.Atoi(statusStr); err == nil {
			filters.Status = &parsed
		} else {
			return nil, fmt.Errorf("parameter 'status' must be a valid number: %w", err)
		}
	}

	filters.ClientID = query.Get("client_id")
	filters.IPAddress = query.Get("ip_address") // Kept for backend optimization
	// UserID filter removed for security reasons

	return filters, nil
}

func (a *DeveloperAuth) ListAccessLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	// Parse all filters from query parameters
	filters, err := a.parseAccessLogFilters(r)
	if err != nil {
		a.serveJSONError(ctx, w, fmt.Errorf("bad request: %w", err))
		return
	}

	// Calculate pagination parameters
	var actualLimit, actualOffset int
	if filters.FetchAll {
		// For "All", pass 0 as limit to skip LIMIT clause in SQL query
		actualLimit = 0
		actualOffset = 0
	} else {
		actualLimit = filters.Limit
		actualOffset = int((filters.Page - 1) * uint64(filters.Limit))
	}

	// Convert to service layer format
	serviceFilters := AccessLogFilters{
		StartDate: filters.StartDate,
		EndDate:   filters.EndDate,
		Status:    filters.Status,
		ClientID:  filters.ClientID,
		IPAddress: filters.IPAddress,
		Limit:     actualLimit,
		Offset:    actualOffset,
	}

	logs, err := a.developerService.ListAccessLogs(ctx, serviceFilters)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Get total count for pagination (with same filters but no limit/offset)
	countFilters := AccessLogFilters{
		StartDate: filters.StartDate,
		EndDate:   filters.EndDate,
		Status:    filters.Status,
		ClientID:  filters.ClientID,
		IPAddress: filters.IPAddress,
		Limit:     0,
		Offset:    0,
	}
	totalCount, err := a.developerService.CountAccessLogs(ctx, countFilters)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Calculate pagination metadata
	var totalPages uint64
	finalTotalCount := uint64(totalCount)

	if filters.FetchAll {
		totalPages = 1
	} else {
		limitValue := uint64(filters.Limit)
		if limitValue > 0 {
			totalPages = (finalTotalCount + limitValue - 1) / limitValue
		} else {
			totalPages = 1
		}
	}

	// Return response matching user listing format
	response := struct {
		Logs        []AccessLogEntry `json:"logs"`
		PageCount   uint             `json:"pageCount"`
		CurrentPage uint             `json:"currentPage"`
		TotalCount  uint64           `json:"totalCount"`
		HasMore     bool             `json:"hasMore"`
		Limit       uint             `json:"limit"`
		Offset      uint64           `json:"offset"`
	}{
		Logs:        logs,
		PageCount:   uint(totalPages),
		CurrentPage: uint(filters.Page),
		TotalCount:  finalTotalCount,
		HasMore:     !filters.FetchAll && filters.Page < totalPages,
		Limit:       uint(actualLimit),
		Offset:      uint64(actualOffset),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetAccessLogStatistics handles GET /api/v0/developer/auth/access-logs/statistics
// Returns total, approved, pending, and rejected counts (no filters, all time statistics)
func (a *DeveloperAuth) GetAccessLogStatistics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	stats, err := a.developerService.GetAccessLogStatistics(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// ExportAccessLogs handles GET /api/v0/developer/auth/access-logs/export
func (a *DeveloperAuth) ExportAccessLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	// Parse all filters from query parameters (same as ListAccessLogs - includes pagination)
	filters, err := a.parseAccessLogFilters(r)
	if err != nil {
		a.serveJSONError(ctx, w, fmt.Errorf("bad request: %w", err))
		return
	}

	// Calculate pagination parameters (same logic as ListAccessLogs)
	var actualLimit, actualOffset int
	if filters.FetchAll {
		actualLimit = 0 // 0 = no limit, get all results
		actualOffset = 0
	} else {
		actualLimit = filters.Limit
		if actualLimit <= 0 {
			actualLimit = 50 // Default limit
		}
		actualOffset = (int(filters.Page) - 1) * actualLimit
		if actualOffset < 0 {
			actualOffset = 0
		}
	}

	// Build service filters with pagination
	serviceFilters := AccessLogFilters{
		StartDate: filters.StartDate,
		EndDate:   filters.EndDate,
		Status:    filters.Status,
		ClientID:  filters.ClientID,
		IPAddress: filters.IPAddress,
		Limit:     actualLimit,
		Offset:    actualOffset,
	}

	logs, err := a.developerService.ListAccessLogs(ctx, serviceFilters)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Generate CSV
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=access-logs-%s.csv", time.Now().Format("2006-01-02")))

	// Write CSV header
	w.Write([]byte("Timestamp,Client ID,Client Name,Status,Redirect URI,Scopes,Approved Scopes,Rejected Scopes,Rejection Reason\n"))

	// Write CSV rows
	for _, log := range logs {
		line := fmt.Sprintf("%s,%s,%s,%s,%s,\"%s\",\"%s\",\"%s\",\"%s\"\n",
			log.Timestamp.Format(time.RFC3339),
			log.ClientID,
			log.ClientName,
			log.AccessStatus,
			log.RedirectURI,
			strings.Join(log.Scopes, ","),
			strings.Join(log.ApprovedScopes, ","),
			strings.Join(log.RejectedScopes, ","),
			log.RejectionReason,
		)
		w.Write([]byte(line))
	}
}
