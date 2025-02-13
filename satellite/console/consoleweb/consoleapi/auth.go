// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/storj"
	"storj.io/common/testrand"
	"storj.io/common/uuid"

	"golang.org/x/oauth2"
	"storj.io/storj/private/post"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consoleapi/socialmedia"
	"storj.io/storj/satellite/console/consoleweb/consolewebauth"
	"storj.io/storj/satellite/mailservice"
)

var (
	// ErrAuthAPI - console auth api error type.
	ErrAuthAPI = errs.Class("consoleapi auth")

	// errNotImplemented is the error value used by handlers of this package to
	// response with status Not Implemented.
	errNotImplemented = errs.New("not implemented")
)

var mainPageURL string = "/project-dashboard"
var signupPageURL string = "/signup"
var loginPageURL string = "/login"
var signupSuccessURL string = "/project-dashboard"

// Auth is an api controller that exposes all auth functionality.
type Auth struct {
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
}

// ErrorResponse is struct for sending error message with code.
type ErrorResponse struct {
	Code    int
	Message string
}

// SuccessResponse is struct for sending error message with code.
type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

// Claims is  a struct that will be encoded to a JWT.
// jwt.StandardClaims is an embedded type to provide expiry time
type Claims struct {
	Email string
	jwt.RegisteredClaims
}

// UserDetails is struct used for user details
type UserDetails struct {
	Name     string
	Email    string
	Password string
}

// NewAuth is a constructor for api auth controller.
func NewAuth(log *zap.Logger, service *console.Service, accountFreezeService *console.AccountFreezeService, mailService *mailservice.Service, cookieAuth *consolewebauth.CookieAuth, analytics *analytics.Service, satelliteName, externalAddress, letUsKnowURL, termsAndConditionsURL, contactInfoURL, generalRequestURL string, activationCodeEnabled bool, badPasswords map[string]struct{}) *Auth {
	return &Auth{
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
		accountFreezeService:      accountFreezeService,
		mailService:               mailService,
		cookieAuth:                cookieAuth,
		analytics:                 analytics,
		badPasswords:              badPasswords,
	}
}

func (a *Auth) MigrateToWeb3(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cnf := socialmedia.GetConfig()

	var body struct {
		AccessToken string `json:"access_token"`
		WalletID    string `json:"wallet_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.sendJsonResponse(w, err.Error(), fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	googleuser, err := socialmedia.GetGoogleUserByAccessToken(body.AccessToken)
	if err != nil {
		a.sendJsonResponse(w, "Error getting user details from Google!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error getting user details from Google!", http.StatusTemporaryRedirect)
		return
	}

	state := r.URL.Query().Get("state")
	verifier := socialmedia.NewVerifierDataFromString(state)
	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		// Inserting lead in Zoho CRM

		go zohoInsertLead(context.Background(), googleuser.Name, googleuser.Email, a.log, verifier)
	}

	userFromDB, err := a.service.GetUsers().GetByEmail(ctx, googleuser.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.sendJsonResponse(w, "Error getting user details from system!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error getting user details from system!", http.StatusTemporaryRedirect)
		return
	}
	if userFromDB == nil {
		a.sendJsonResponse(w, "User not found!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=User not found!", http.StatusTemporaryRedirect)
		return
	}

	err = a.service.GetUsers().Update(ctx, userFromDB.ID, console.UpdateUserRequest{
		WalletID: &body.WalletID,
	})
	if err != nil {
		a.sendJsonResponse(w, "Error creating user!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating user!", http.StatusTemporaryRedirect)
		return
	}

	a.TokenGoogleWrapper(ctx, googleuser.Email, w, r)
	// Set up a test project and bucket

	a.sendJsonResponse(w, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
	// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupSuccessURL), http.StatusTemporaryRedirect)
}

// Token authenticates user by credentials and returns auth token.
func (a *Auth) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenRequest := console.AuthUser{}
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

	tokenInfo, err := a.service.Token(ctx, tokenRequest)
	if err != nil {
		if console.ErrMFAMissing.Has(err) {
			web.ServeCustomJSONError(ctx, a.log, w, http.StatusOK, err, a.getUserErrorMessage(err))
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

// UsersToken authenticate users without password for developers.
func (a *Auth) UsersToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenRequest := console.AuthWithoutPassword{}
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

	tokenInfo, err := a.service.TokenWithoutPassword(ctx, tokenRequest)
	if err != nil {
		if console.ErrMFAMissing.Has(err) {
			web.ServeCustomJSONError(ctx, a.log, w, http.StatusOK, err, a.getUserErrorMessage(err))
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

// TokenByAPIKey authenticates user by API key and returns auth token.
func (a *Auth) TokenByAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	authToken := r.Header.Get("Authorization")
	if !(strings.HasPrefix(authToken, "Bearer ")) {
		a.log.Info("authorization key format is incorrect. Should be 'Bearer <key>'")
		a.serveJSONError(ctx, w, err)
		return
	}

	apiKey := strings.TrimPrefix(authToken, "Bearer ")

	userAgent := r.UserAgent()
	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo, err := a.service.TokenByAPIKey(ctx, userAgent, ip, apiKey)
	if err != nil {
		a.log.Info("Error authenticating token request", zap.Error(ErrAuthAPI.Wrap(err)))
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
		a.log.Error("token handler could not encode token response", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// getSessionID gets the session ID from the request.
func (a *Auth) getSessionID(r *http.Request) (id uuid.UUID, err error) {

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
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	w.Header().Set("Content-Type", "application/json")

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = a.service.DeleteSession(ctx, sessionID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	a.cookieAuth.RemoveTokenCookie(w)
}

func CreateToken(ttl time.Duration, payload interface{}, privateKey string) (string, error) {
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)

	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["sub"] = payload
	claims["exp"] = now.Add(ttl).Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)

	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

const clientID = "220941885214-8mv3upmgkvbgbnntua98m4gded4i8hmb.apps.googleusercontent.com" // Replace with your actual client ID

type UserInfo struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (a *Auth) RegisterGoogleForApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		AccessToken string `json:"access_token"`
		WalletID    string `json:"wallet_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	cnf := socialmedia.GetConfig()

	googleuser, err := socialmedia.GetGoogleUserByAccessToken(body.AccessToken)
	if err != nil {
		a.SendResponse(w, r, "Error getting user details from Google!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error getting user details from Google!", http.StatusTemporaryRedirect)
		return
	}

	state := r.URL.Query().Get("state")
	verifier := socialmedia.NewVerifierDataFromString(state)
	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		// Inserting lead in Zoho CRM

		go zohoInsertLead(context.Background(), googleuser.Name, googleuser.Email, a.log, verifier)
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, googleuser.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error getting user details from system!", http.StatusTemporaryRedirect)
		return
	}

	var user *console.User
	if verified != nil {
		satelliteAddress := a.ExternalAddress
		if !strings.HasSuffix(satelliteAddress, "/") {
			satelliteAddress += "/"
		}
		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: verified.Email}},
			&console.AccountAlreadyExistsEmail{
				Origin:            satelliteAddress,
				SatelliteName:     a.SatelliteName,
				SignInLink:        satelliteAddress + "login",
				ResetPasswordLink: satelliteAddress + "forgot-password",
				CreateAccountLink: satelliteAddress + "signup",
			},
		)
		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		// http.Redirect(w, r, fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL)+"?error=You are already registerted!", http.StatusTemporaryRedirect)
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating secret!", http.StatusTemporaryRedirect)
				return
			}

			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error getting IP!", http.StatusTemporaryRedirect)
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
					FullName:  googleuser.Name,
					Email:     googleuser.Email,
					Status:    1,
					IP:        ip,
					Source:    "Google",
					WalletId:  body.WalletID,
					UtmParams: utmParams,
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating user!", http.StatusTemporaryRedirect)
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
				// trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	a.TokenGoogleWrapper(ctx, googleuser.Email, w, r)
	// Set up a test project and bucket

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})
	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating default project!", http.StatusTemporaryRedirect)
		return
	}

	a.log.Info("Default Project Name: " + project.Name)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
	// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupSuccessURL), http.StatusTemporaryRedirect)
}

func (a *Auth) SendResponse(w http.ResponseWriter, r *http.Request, errorMessage, redirectUri string) {
	if !r.URL.Query().Has("json") {
		if errorMessage != "" {
			redirectUri += "?error=" + errorMessage
		}
		http.Redirect(w, r, redirectUri, http.StatusTemporaryRedirect)
		return
	}

	a.sendJsonResponse(w, errorMessage, redirectUri)
}

// sendJsonResponse is a helper function to send a JSON response with a given status code
func (a *Auth) sendJsonResponse(w http.ResponseWriter, errorMessage, redirectUri string) {
	w.Header().Set("Content-Type", "application/json")
	if errorMessage != "" {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":        errorMessage,
			"redirect_url": redirectUri,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"redirect_url": redirectUri,
		"success":      true,
	})
}

func (a *Auth) InitUnstoppableDomainRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)
	// Create Unstoppable Request Instance
	state, err := socialmedia.EncodeState(nil)
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating state! ", http.StatusTemporaryRedirect)
		return
	}
	nonce, err := socialmedia.GenerateNonce()
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating nonce! ", http.StatusTemporaryRedirect)
		return
	}
	verifier, challenge, err := socialmedia.GenerateCodeChallengeAndVerifier(43, "S256")
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating verifier and challenge!", http.StatusTemporaryRedirect)
		return
	}

	socialmedia.SaveReqOptions(state, socialmedia.NewVerifierData(r).SetVerifier(verifier))
	redirectURL := cnf.UnstoppableDomainRedirectUrl_register
	if r.URL.Query().Has("zoho-insert") {
		redirectURL += "?zoho-insert"
	}

	options := socialmedia.ReqOptions{
		BaseURL: "https://auth.unstoppabledomains.com/oauth2/auth",
		QueryParams: socialmedia.QueryParams{
			CodeChallenge:       challenge,
			Nonce:               nonce,
			State:               state,
			FlowID:              "login",
			ClientID:            cnf.UnstoppableDomainClientID,
			ClientSecret:        cnf.UnstoppableDomainClientSecret,
			ClientAuthMethod:    "client_secret_basic",
			MaxAge:              "300000",
			Prompt:              "login",
			RedirectURI:         redirectURL,
			ResponseMode:        "query",
			Scope:               socialmedia.UnstoppableDomainScope,
			CodeChallengeMethod: "S256",
			ResponseType:        "code",
			PackageName:         "@uauth/js",
			PackageVersion:      "3.0.1",
		},
		Headers: map[string]string{
			"User-Agent":                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "cross-site",
			"Sec-Fetch-User":            "?1",
		},
	}
	// Parse the base URL
	parsedURL, err := url.Parse(options.BaseURL)
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error parsing URL!", http.StatusTemporaryRedirect)
		return
	}

	params, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error parsing URL!", http.StatusTemporaryRedirect)
		return
	}
	for key, value := range options.QueryParams.ToMap() {
		params.Set(key, value)
		//return
	}
	parsedURL.RawQuery = params.Encode()
	http.Redirect(w, r, parsedURL.String(), http.StatusTemporaryRedirect)
}

func (a *Auth) InitUnstoppableDomainLogin(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)
	// Create Unstoppable Request Instance
	state, err := socialmedia.EncodeState(nil)
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating state! ", http.StatusTemporaryRedirect)
		return
	}
	nonce, err := socialmedia.GenerateNonce()
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating nonce!", http.StatusTemporaryRedirect)
		return
	}
	verifier, challenge, err := socialmedia.GenerateCodeChallengeAndVerifier(43, "S256")
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating verifier and challenge!", http.StatusTemporaryRedirect)
		return
	}

	socialmedia.SaveReqOptions(state, socialmedia.NewVerifierData(r).SetVerifier(verifier))
	options := socialmedia.ReqOptions{
		BaseURL: "https://auth.unstoppabledomains.com/oauth2/auth",
		QueryParams: socialmedia.QueryParams{
			CodeChallenge:       challenge,
			Nonce:               nonce,
			State:               state,
			FlowID:              "login",
			ClientID:            cnf.UnstoppableDomainClientID,
			ClientSecret:        cnf.UnstoppableDomainClientSecret,
			ClientAuthMethod:    "client_secret_basic",
			MaxAge:              "300000",
			Prompt:              "login",
			RedirectURI:         cnf.UnstoppableDomainRedirectUrl_login,
			ResponseMode:        "query",
			Scope:               socialmedia.UnstoppableDomainScope,
			CodeChallengeMethod: "S256",
			ResponseType:        "code",
			PackageName:         "@uauth/js",
			PackageVersion:      "3.0.1",
		},
		Headers: map[string]string{
			"User-Agent":                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "cross-site",
			"Sec-Fetch-User":            "?1",
		},
	}
	// Parse the base URL
	parsedURL, err := url.Parse(options.BaseURL)
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error parsing URL!", http.StatusTemporaryRedirect)
		return
	}

	params, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error parsing URL!", http.StatusTemporaryRedirect)
		return
	}
	for key, value := range options.QueryParams.ToMap() {
		params.Set(key, value)
		//return
	}
	parsedURL.RawQuery = params.Encode()
	http.Redirect(w, r, parsedURL.String(), http.StatusTemporaryRedirect)
}

func (a *Auth) InitXRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)
	requestUrl, err := socialmedia.RedirectURL("r", r)
	if err != nil {
		a.SendResponse(w, r, "Error creating state!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.SendResponse(w, r, "", requestUrl)
}

func (a *Auth) InitXLogin(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)
	requestUrl, err := socialmedia.RedirectURL("login", r)
	if err != nil {
		a.SendResponse(w, r, "Error creating state!", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	a.SendResponse(w, r, "", requestUrl)
}

func (a *Auth) HandleXLogin(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	reqOps, err := socialmedia.GetReqOptions(state)
	if err != nil {
		a.SendResponse(w, r, err.Error(), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, loginPageURL)+"?error="+err.Error(), http.StatusTemporaryRedirect)
		return
	}
	userI, err := socialmedia.GetXUser(ctx, code, reqOps.Verifier, "login", r)
	if err != nil {
		a.SendResponse(w, r, "Error code verifier loading failed "+err.Error(), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, loginPageURL)+"?error=Error code verifier loading failed", http.StatusTemporaryRedirect)
		return
	}

	verified, _, err := a.service.GetUserByEmailWithUnverified_google(ctx, userI.Data.Username+"@no-email.com")

	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system!", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error getting user details from system!", http.StatusTemporaryRedirect)
		return
	}

	if verified == nil {
		a.SendResponse(w, r, "Your email id is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Your email id is not registered", http.StatusTemporaryRedirect)
		return
	}

	a.TokenGoogleWrapper(r.Context(), userI.Data.Username+"@no-email.com", w, r)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
	// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, mainPageURL), http.StatusTemporaryRedirect)
}

func (a *Auth) HandleXRegisterZoho(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("zoho-insert", "true")
	r.URL.RawQuery = q.Encode()
	a.HandleXRegister(w, r)
}

func (a *Auth) HandleXRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	walletId := r.URL.Query().Get("wallet_id")
	if walletId == "" {
		a.SendResponse(w, r, "Wallet id is required", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	reqOps, err := socialmedia.GetReqOptions(state)
	if err != nil {
		a.SendResponse(w, r, err.Error(), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	userI, err := socialmedia.GetXUser(ctx, code, reqOps.Verifier, "r", r)
	if err != nil {
		a.SendResponse(w, r, "Error code verifier loading failed "+err.Error(), fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		// Inserting lead in Zoho CRM
		go zohoInsertLead(context.Background(), userI.Data.Name, userI.Data.Username+"@no-email.com", a.log, reqOps)
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, userI.Data.Username+"@no-email.com")

	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var user *console.User
	if verified != nil {
		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL))
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}

			var utmParams *console.UtmParams
			if reqOps != nil {
				utmParams = &console.UtmParams{
					UtmTerm:     reqOps.UTMTerm,
					UtmContent:  reqOps.UTMContent,
					UtmSource:   reqOps.UTMSource,
					UtmMedium:   reqOps.UTMMedium,
					UtmCampaign: reqOps.UTMCampaign,
				}
			}

			user, err = a.service.CreateUser(ctx,
				console.CreateUser{
					FullName:  userI.Data.Name,
					ShortName: userI.Data.Username,
					Email:     userI.Data.Username + "@no-email.com",
					Status:    1,
					IP:        ip,
					WalletId:  walletId,
					Source:    "Twitter",
					UtmParams: utmParams,
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
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
				//trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	a.TokenGoogleWrapper(ctx, userI.Data.Username+"@no-email.com", w, r)

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})
	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.log.Info("Default Project Name: " + project.Name)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
}

// **** Unstopabble register ****//
func (a *Auth) HandleUnstoppableRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	walletId := r.URL.Query().Get("wallet_id")
	if walletId == "" {
		a.SendResponse(w, r, "Wallet id is required", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	reqOps, err := socialmedia.GetReqOptions(state)
	if err != nil {
		a.SendResponse(w, r, err.Error(), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	token, err := socialmedia.GetRegisterToken(code, reqOps.Verifier, r.URL.Query().Has("zoho-insert"))
	if err != nil {
		a.SendResponse(w, r, "Error code not present", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	responseBody, err := socialmedia.ParseToken(token.IDToken)
	if err != nil {
		a.SendResponse(w, r, "Error reading body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		// Inserting lead in Zoho CRM
		go zohoInsertLead(context.Background(), responseBody.Sub, responseBody.Sub+"@ud.me", a.log, reqOps)
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, responseBody.Sub+"@ud.me")

	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var user *console.User
	if verified != nil {
		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL))
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}
			var utmParams *console.UtmParams
			if reqOps != nil {
				utmParams = &console.UtmParams{
					UtmTerm:     reqOps.UTMTerm,
					UtmContent:  reqOps.UTMContent,
					UtmSource:   reqOps.UTMSource,
					UtmMedium:   reqOps.UTMMedium,
					UtmCampaign: reqOps.UTMCampaign,
				}
			}
			user, err = a.service.CreateUser(ctx,
				console.CreateUser{
					FullName:  responseBody.Sub,
					ShortName: responseBody.Sub,
					Email:     responseBody.Sub + "@ud.me",
					Status:    1,
					IP:        ip,
					WalletId:  walletId,
					Source:    "Unstoppabble",
					UtmParams: utmParams,
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
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
				//trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	a.TokenGoogleWrapper(ctx, responseBody.Sub+"@ud.me", w, r)

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})
	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.log.Info("Default Project Name: " + project.Name)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
}

func (a *Auth) LoginUserUnstoppable(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	reqOps, err := socialmedia.GetReqOptions(state)
	if err != nil {
		a.SendResponse(w, r, err.Error(), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	token, err := socialmedia.GetLoginToken(code, reqOps.Verifier)
	if err != nil {
		a.SendResponse(w, r, "Error code not present", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	responseBody, err := socialmedia.ParseToken(token.IDToken)
	if err != nil {
		a.SendResponse(w, r, "Error reading body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	verified, _, err := a.service.GetUserByEmailWithUnverified_google(ctx, responseBody.Sub+"@ud.me")

	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	if verified == nil {
		a.SendResponse(w, r, "Your email id is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.TokenGoogleWrapper(r.Context(), responseBody.Sub+"@ud.me", w, r)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
}

func (a *Auth) HandleAppleRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idToken := r.URL.Query().Get("id_token")
	if idToken == "" {
		a.SendResponse(w, r, "Error reading body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	walletId := r.URL.Query().Get("wallet_id")
	if walletId == "" {
		a.SendResponse(w, r, "Wallet id is required", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	responseBody, err := socialmedia.GetAppleUser(ctx, idToken)
	if err != nil {
		a.SendResponse(w, r, "Error reading body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, responseBody.Email)

	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var user *console.User
	if verified != nil {
		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL))
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}

			user, err = a.service.CreateUser(ctx,
				console.CreateUser{
					FullName:  responseBody.Email,
					ShortName: responseBody.Email,
					Email:     responseBody.Email,
					WalletId:  walletId,
					//UserAgent:        registerData.UserAgent,
					//Password:         registerData.Password,
					Status: 1,
					//IsProfessional:   registerData.IsProfessional,
					//Position:         registerData.Position,
					//CompanyName:      registerData.CompanyName,
					//EmployeeCount:    registerData.EmployeeCount,
					//HaveSalesContact: registerData.HaveSalesContact,
					IP: ip,
					//SignupPromoCode:  registerData.SignupPromoCode,
					Source: "Apple",
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
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
				//trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	a.TokenGoogleWrapper(ctx, responseBody.Email, w, r)

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})
	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.log.Info("Default Project Name: " + project.Name)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
}

func (a *Auth) LoginUserApple(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idToken := r.URL.Query().Get("id_token")
	if idToken == "" {
		a.SendResponse(w, r, "Invalid token", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	responseBody, err := socialmedia.GetAppleUser(ctx, idToken)
	if err != nil {
		a.SendResponse(w, r, "Error reading body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	verified, _, err := a.service.GetUserByEmailWithUnverified_google(ctx, responseBody.Email)

	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	if verified == nil {
		a.SendResponse(w, r, "Your email id is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.TokenGoogleWrapper(r.Context(), responseBody.Email, w, r)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
}

func (a *Auth) LoginUserConfirmForApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	a.loginUserConfirmFromIdtokeAndAccessToken(w, r, body.IDToken, body.AccessToken)
}

func (a *Auth) LoginUserConfirm(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)
	var mode string = "signin"

	code := r.URL.Query().Get("code")

	if code == "" {
		a.SendResponse(w, r, "Error while getting code from Google", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	// Use the code to get the id and access tokens
	tokenRes, err := socialmedia.GetGoogleOauthToken(code, mode, false)
	if err != nil {
		a.SendResponse(w, r, "Error getting token from Google", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	a.loginUserConfirmFromIdtokeAndAccessToken(w, r, tokenRes.Id_token, tokenRes.Access_token)
}

func (a *Auth) loginUserConfirmFromIdtokeAndAccessToken(w http.ResponseWriter, r *http.Request, idToken, accessToken string) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()

	googleuser, err := socialmedia.GetGoogleUser(accessToken, idToken)

	verified, _, err := a.service.GetUserByEmailWithUnverified_google(ctx, googleuser.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	if verified == nil {
		a.SendResponse(w, r, "Your email id is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.TokenGoogleWrapper(r.Context(), googleuser.Email, w, r)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
}

func (a *Auth) TokenGoogleWrapper(ctx context.Context, userGmail string, w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	var err error

	tokenRequest := console.AuthUser{}
	tokenRequest.Email = userGmail
	userGmail = ""
	tokenRequest.UserAgent = r.UserAgent()
	tokenRequest.IP, err = web.GetRequestIP(r)
	if err != nil {
		a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, loginPageURL)+"?error=Error getting IP", http.StatusTemporaryRedirect)
		return
	}

	tokenInfo, err := a.service.Token_google(ctx, tokenRequest)

	if err != nil {
		if console.ErrMFAMissing.Has(err) {
			a.SendResponse(w, r, "Error getting token from system", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
			// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, loginPageURL)+"?error=Error getting token from system", http.StatusTemporaryRedirect)
		} else {
			a.log.Info("Error authenticating token request", zap.String("email", tokenRequest.Email), zap.Error(ErrAuthAPI.Wrap(err)))
			a.SendResponse(w, r, "Error getting token from system "+err.Error(), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
			// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, loginPageURL)+"?error=Error getting token from system", http.StatusTemporaryRedirect)
		}
		return
	}

	a.cookieAuth.SetTokenCookie(w, *tokenInfo)
}

func (a *Auth) InitFacebookRegister(w http.ResponseWriter, r *http.Request) {
	var OAuth2Config = socialmedia.GetFacebookOAuthConfig_Register()

	state := socialmedia.GetRandomOAuthStateString()
	if r.URL.Query().Has("zoho-insert") {
		OAuth2Config.RedirectURL += "?zoho-insert"

		uuid, _ := uuid.New()
		state = uuid.String()

		socialmedia.SaveReqOptions(state, socialmedia.NewVerifierData(r))
	}

	url := OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Auth) InitFacebookLogin(w http.ResponseWriter, r *http.Request) {
	var OAuth2Config = socialmedia.GetFacebookOAuthConfig_Login()
	url := OAuth2Config.AuthCodeURL(socialmedia.GetRandomOAuthStateString())
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Auth) HandleFacebookRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var code = r.FormValue("code")
	var state = r.FormValue("state")

	var OAuth2Config = socialmedia.GetFacebookOAuthConfig_Register()
	if r.URL.Query().Has("zoho-insert") {
		OAuth2Config.RedirectURL += "?zoho-insert"
	}
	token, err := OAuth2Config.Exchange(context.TODO(), code)

	if err != nil || token == nil {
		a.SendResponse(w, r, "Error getting token from Facebook", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	fbUserDetails, fbUserDetailsError := socialmedia.GetUserInfoFromFacebook(token.AccessToken)

	if fbUserDetailsError != nil {
		a.SendResponse(w, r, "Error getting user details from Facebook", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	reqOps, err := socialmedia.GetReqOptions(state)
	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		if err != nil {
			a.log.Error("Error getting request options", zap.Error(err))
		}

		// Inserting lead in Zoho CRM
		go zohoInsertLead(context.Background(), fbUserDetails.Name, fbUserDetails.Email, a.log, reqOps)
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, fbUserDetails.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	var user *console.User
	if verified != nil {
		satelliteAddress := a.ExternalAddress
		if !strings.HasSuffix(satelliteAddress, "/") {
			satelliteAddress += "/"
		}
		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: verified.Email}},
			&console.AccountAlreadyExistsEmail{
				Origin:            satelliteAddress,
				SatelliteName:     a.SatelliteName,
				SignInLink:        satelliteAddress + "login",
				ResetPasswordLink: satelliteAddress + "forgot-password",
				CreateAccountLink: satelliteAddress + "signup",
			},
		)
		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL))
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}

			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}
			var utmParams *console.UtmParams
			if reqOps != nil {
				utmParams = &console.UtmParams{
					UtmTerm:     reqOps.UTMTerm,
					UtmContent:  reqOps.UTMContent,
					UtmSource:   reqOps.UTMSource,
					UtmMedium:   reqOps.UTMMedium,
					UtmCampaign: reqOps.UTMCampaign,
				}
			}
			user, err = a.service.CreateUser(ctx,
				console.CreateUser{
					FullName:  fbUserDetails.Name,
					Email:     fbUserDetails.Email,
					Status:    1,
					IP:        ip,
					Source:    "Facebook",
					UtmParams: utmParams,
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
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
				// trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	a.TokenGoogleWrapper(ctx, fbUserDetails.Email, w, r)

	// Set up a test project and bucket
	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})
	//require.NoError(t, err)
	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupPageURL)+"?error=Error creating default project!", http.StatusTemporaryRedirect)
		return
	}

	a.log.Info("Default Project Name: " + project.Name)

	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
	// http.Redirect(w, r, fmt.Sprint(cnf.ClientOrigin, signupSuccessURL), http.StatusTemporaryRedirect)
}

func (a *Auth) HandleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var state = r.FormValue("state")
	var code = r.FormValue("code")

	if state != socialmedia.GetRandomOAuthStateString() {
		a.SendResponse(w, r, "State mismatch", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	var OAuth2Config = socialmedia.GetFacebookOAuthConfig_Login()

	token, err := OAuth2Config.Exchange(context.TODO(), code)

	if err != nil || token == nil {
		a.SendResponse(w, r, "Error getting token from Facebook", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	fbUserDetails, fbUserDetailsError := socialmedia.GetUserInfoFromFacebook(token.AccessToken)

	if fbUserDetailsError != nil {
		a.SendResponse(w, r, "Error getting user details from Facebook", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	verified, _, err := a.service.GetUserByEmailWithUnverified_google(ctx, fbUserDetails.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	if verified == nil {
		a.SendResponse(w, r, "Your email id is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	a.TokenGoogleWrapper(ctx, verified.Email, w, r)

	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
}

func (a *Auth) InitLinkedInRegister(w http.ResponseWriter, r *http.Request) {
	var OAuth2Config = socialmedia.GetLinkedinOAuthConfig_Register()

	state := socialmedia.GetRandomOAuthStateString()
	if r.URL.Query().Has("zoho-insert") {
		OAuth2Config.RedirectURL += "?zoho-insert"
		uid, _ := uuid.New()
		socialmedia.SaveReqOptions(uid.String(), socialmedia.NewVerifierData(r))
		state = uid.String()
	}

	url := OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Auth) InitLinkedInLogin(w http.ResponseWriter, r *http.Request) {
	var OAuth2Config = socialmedia.GetLinkedinOAuthConfig_Login()
	url := OAuth2Config.AuthCodeURL(socialmedia.GetRandomOAuthStateString())
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Auth) HandleLinkedInRegister(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var code = r.FormValue("code")
	var state = r.FormValue("state")

	var OAuth2Config = socialmedia.GetLinkedinOAuthConfig_Register()
	if r.URL.Query().Has("zoho-insert") {
		OAuth2Config.RedirectURL += "?zoho-insert"
	}

	token, err := OAuth2Config.Exchange(context.TODO(), code)

	if err != nil || token == nil {
		a.SendResponse(w, r, "Error getting token from LinkedIn", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	client := OAuth2Config.Client(context.TODO(), token)
	req, err := http.NewRequest("GET", "https://api.linkedin.com/v2/userinfo", nil)

	if err != nil {
		a.SendResponse(w, r, "Error creating request to LinkedIn", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	req.Header.Set("Bearer", token.AccessToken)
	response, err := client.Do(req)

	if err != nil {
		a.SendResponse(w, r, "Error getting user details from LinkedIn", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	defer response.Body.Close()
	str, err := io.ReadAll(response.Body)
	if err != nil {
		a.SendResponse(w, r, "Error reading LinkedIn response body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var LinkedinUserDetails socialmedia.LinkedinUserDetails
	err = json.Unmarshal(str, &LinkedinUserDetails)
	if err != nil {
		a.SendResponse(w, r, "Error unmarshalling LinkedIn response", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	if LinkedinUserDetails.Email == "" {
		a.SendResponse(w, r, "Email not found in LinkedIn response", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	reqOps, err := socialmedia.GetReqOptions(state)
	if err != nil {
		a.log.Error("Error getting request options", zap.Error(err))
	}
	if r.URL.Query().Has("zoho-insert") {
		a.log.Debug("inserting lead in Zoho CRM")
		// Inserting lead in Zoho CRM
		go zohoInsertLead(context.Background(), LinkedinUserDetails.Name, LinkedinUserDetails.Email, a.log, reqOps)
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, LinkedinUserDetails.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var user *console.User
	if verified != nil {
		satelliteAddress := a.ExternalAddress
		if !strings.HasSuffix(satelliteAddress, "/") {
			satelliteAddress += "/"
		}
		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: verified.Email}},
			&console.AccountAlreadyExistsEmail{
				Origin:            satelliteAddress,
				SatelliteName:     a.SatelliteName,
				SignInLink:        satelliteAddress + "login",
				ResetPasswordLink: satelliteAddress + "forgot-password",
				CreateAccountLink: satelliteAddress + "signup",
			},
		)

		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL))
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}

			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}
			var utmParams *console.UtmParams
			if reqOps != nil {
				utmParams = &console.UtmParams{
					UtmTerm:     reqOps.UTMTerm,
					UtmContent:  reqOps.UTMContent,
					UtmSource:   reqOps.UTMSource,
					UtmMedium:   reqOps.UTMMedium,
					UtmCampaign: reqOps.UTMCampaign,
				}
			}
			user, err = a.service.CreateUser(ctx,
				console.CreateUser{
					FullName:  LinkedinUserDetails.Name,
					ShortName: LinkedinUserDetails.GivenName,
					Email:     LinkedinUserDetails.Email,
					Status:    1,
					IP:        ip,
					Source:    "Linkedin",
					UtmParams: utmParams,
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
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
				// trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	// a.TokenGoogleWrapper(ctx, LinkedinUserDetails.Email, w, r)

	// Set up a test project and bucket

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})

	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.log.Info("Default Project Name: " + project.Name)

	// login
	a.TokenGoogleWrapper(ctx, LinkedinUserDetails.Email, w, r)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
}

func (a *Auth) HandleLinkedInIdTokenFromCode(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var code = r.FormValue("code")

	var OAuth2Config *oauth2.Config
	if r.URL.Query().Has("register") {
		OAuth2Config = socialmedia.GetLinkedinOAuthConfig_IdToken_Register()
	} else {
		OAuth2Config = socialmedia.GetLinkedinOAuthConfig_IdToken_Login()
	}

	token, err := OAuth2Config.Exchange(context.TODO(), code)
	if err != nil || token == nil {
		a.SendResponse(w, r, "Error getting token from LinkedIn", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	idToken := token.Extra("id_token")
	if idToken == nil {
		a.SendResponse(w, r, "No id token found", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"auth_token"`
	}{idToken.(string), token.AccessToken})
	if err != nil {
		a.log.Error("token handler could not encode token response", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

func (a *Auth) HandleLinkedInRegisterWithAuthToken(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	authToken := r.FormValue("auth_token")
	if authToken == "" {
		a.SendResponse(w, r, "Invalid auth token", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	walletId := r.FormValue("wallet_id")
	if walletId == "" {
		a.SendResponse(w, r, "Wallet id is required", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var OAuth2Config = socialmedia.GetLinkedinOAuthConfig_Register()
	if r.URL.Query().Has("zoho-insert") {
		OAuth2Config.RedirectURL += "?zoho-insert"
	}

	client := OAuth2Config.Client(context.TODO(), &oauth2.Token{
		AccessToken: authToken,
		TokenType:   "bearer",
	})
	req, err := http.NewRequest("GET", "https://api.linkedin.com/v2/userinfo", nil)

	if err != nil {
		a.SendResponse(w, r, "Error creating request to LinkedIn", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	req.Header.Set("Bearer", authToken)
	response, err := client.Do(req)

	if err != nil {
		a.SendResponse(w, r, "Error getting user details from LinkedIn", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	defer response.Body.Close()
	str, err := io.ReadAll(response.Body)
	if err != nil {
		a.SendResponse(w, r, "Error reading LinkedIn response body", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var LinkedinUserDetails socialmedia.LinkedinUserDetails
	err = json.Unmarshal(str, &LinkedinUserDetails)
	if err != nil {
		a.SendResponse(w, r, "Error unmarshalling LinkedIn response", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	if LinkedinUserDetails.Email == "" {
		a.SendResponse(w, r, "Email not found in LinkedIn response "+string(str), fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	// reqOps, err := socialmedia.GetReqOptions(state)
	// if err != nil {
	// 	a.log.Error("Error getting request options", zap.Error(err))
	// }
	// if r.URL.Query().Has("zoho-insert") {
	// 	a.log.Debug("inserting lead in Zoho CRM")
	// 	// Inserting lead in Zoho CRM
	// 	go zohoInsertLead(context.Background(), LinkedinUserDetails.Name, LinkedinUserDetails.Email, a.log, reqOps)
	// }

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, LinkedinUserDetails.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	var user *console.User
	if verified != nil {
		satelliteAddress := a.ExternalAddress
		if !strings.HasSuffix(satelliteAddress, "/") {
			satelliteAddress += "/"
		}
		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: verified.Email}},
			&console.AccountAlreadyExistsEmail{
				Origin:            satelliteAddress,
				SatelliteName:     a.SatelliteName,
				SignInLink:        satelliteAddress + "login",
				ResetPasswordLink: satelliteAddress + "forgot-password",
				CreateAccountLink: satelliteAddress + "signup",
			},
		)

		a.SendResponse(w, r, "You are already registered!", fmt.Sprint(socialmedia.GetConfig().ClientOrigin, loginPageURL))
		return
	} else {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			secret, err := console.RegistrationSecretFromBase64("")
			if err != nil {
				a.SendResponse(w, r, "Error creating secret", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}

			ip, err := web.GetRequestIP(r)
			if err != nil {
				a.SendResponse(w, r, "Error getting IP", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
				return
			}

			user, err = a.service.CreateUser(ctx,
				console.CreateUser{
					FullName:  LinkedinUserDetails.Name,
					ShortName: LinkedinUserDetails.GivenName,
					Email:     LinkedinUserDetails.Email,
					Status:    1,
					IP:        ip,
					Source:    "Linkedin",
					WalletId:  walletId,
				},
				secret, true,
			)

			if err != nil {
				a.SendResponse(w, r, "Error creating user "+err.Error(), fmt.Sprint(cnf.ClientOrigin, signupPageURL))
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
				// trackCreateUserFields.StorageNeeds = registerData.StorageNeeds
				trackCreateUserFields.JobTitle = user.Position
				trackCreateUserFields.HaveSalesContact = user.HaveSalesContact
			}
			a.analytics.TrackCreateUser(trackCreateUserFields)
		}
	}

	// a.TokenGoogleWrapper(ctx, LinkedinUserDetails.Email, w, r)

	// Set up a test project and bucket

	authed := console.WithUser(ctx, user)

	project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
		Name: "My Project",
	})

	if err != nil {
		a.log.Error("Error in Default Project:")
		a.log.Error(err.Error())
		a.SendResponse(w, r, "Error creating default project", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}

	a.log.Info("Default Project Name: " + project.Name)

	// login
	a.TokenGoogleWrapper(ctx, LinkedinUserDetails.Email, w, r)
	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, signupSuccessURL))
}

func (a *Auth) HandleLinkedInLogin(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var code = r.FormValue("code")

	var OAuth2Config = socialmedia.GetLinkedinOAuthConfig_Login()
	token, err := OAuth2Config.Exchange(context.TODO(), code)

	if err != nil || token == nil {
		a.SendResponse(w, r, "Error getting token from LinkedIn", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	client := OAuth2Config.Client(context.TODO(), token)
	req, err := http.NewRequest("GET", "https://api.linkedin.com/v2/userinfo", nil)

	if err != nil {
		a.SendResponse(w, r, "Error creating request to LinkedIn", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	req.Header.Set("Bearer", token.AccessToken)
	response, err := client.Do(req)

	if err != nil {
		a.SendResponse(w, r, "Error getting user details from LinkedIn", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	defer response.Body.Close()
	str, err := io.ReadAll(response.Body)
	if err != nil {
		a.SendResponse(w, r, "Error reading LinkedIn response body", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	var LinkedinUserDetails socialmedia.LinkedinUserDetails
	err = json.Unmarshal(str, &LinkedinUserDetails)
	if err != nil {
		a.SendResponse(w, r, "Error unmarshalling LinkedIn response", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	if LinkedinUserDetails.Email == "" {
		a.SendResponse(w, r, "Email not found in LinkedIn response", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, LinkedinUserDetails.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	fmt.Println(verified, unverified)

	if verified == nil {
		a.SendResponse(w, r, "Your email id is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	a.TokenGoogleWrapper(ctx, LinkedinUserDetails.Email, w, r)

	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
}

func (a *Auth) HandleLinkedInLoginWithAuthToken(w http.ResponseWriter, r *http.Request) {
	cnf := socialmedia.GetConfig()

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var authToken = r.URL.Query().Get("auth_token")
	if authToken == "" {
		a.SendResponse(w, r, "Invalid auth token", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	var OAuth2Config = socialmedia.GetLinkedinOAuthConfig_Login()

	client := OAuth2Config.Client(context.TODO(), &oauth2.Token{
		AccessToken: authToken,
		TokenType:   "bearer",
	})
	req, err := http.NewRequest("GET", "https://api.linkedin.com/v2/userinfo", nil)

	if err != nil {
		a.SendResponse(w, r, "Error creating request to LinkedIn", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	req.Header.Set("Bearer", authToken)
	response, err := client.Do(req)

	if err != nil {
		a.SendResponse(w, r, "Error getting user details from LinkedIn", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	defer response.Body.Close()
	str, err := io.ReadAll(response.Body)
	if err != nil {
		a.SendResponse(w, r, "Error reading LinkedIn response body", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	var LinkedinUserDetails socialmedia.LinkedinUserDetails
	err = json.Unmarshal(str, &LinkedinUserDetails)
	if err != nil {
		a.SendResponse(w, r, "Error unmarshalling LinkedIn response", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	if LinkedinUserDetails.Email == "" {
		a.SendResponse(w, r, "Email not found in LinkedIn response "+string(str), fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified_google(ctx, LinkedinUserDetails.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.SendResponse(w, r, "Error getting user details from system", fmt.Sprint(cnf.ClientOrigin, loginPageURL))
		return
	}
	fmt.Println(verified, unverified)

	if verified == nil {
		a.SendResponse(w, r, "Your email id ("+LinkedinUserDetails.Email+") is not registered", fmt.Sprint(cnf.ClientOrigin, signupPageURL))
		return
	}
	a.TokenGoogleWrapper(ctx, LinkedinUserDetails.Email, w, r)

	a.SendResponse(w, r, "", fmt.Sprint(cnf.ClientOrigin, mainPageURL))
}

// ActivateAccount verifies a signup activation code.
func (a *Auth) ActivateAccount(w http.ResponseWriter, r *http.Request) {
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

	verified, unverified, err := a.service.GetUserByEmailWithUnverified(ctx, activateData.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.serveJSONError(ctx, w, err)
		return
	}

	if verified != nil {
		satelliteAddress := a.ExternalAddress
		if !strings.HasSuffix(satelliteAddress, "/") {
			satelliteAddress += "/"
		}
		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: verified.Email}},
			&console.AccountAlreadyExistsEmail{
				Origin:            satelliteAddress,
				SatelliteName:     a.SatelliteName,
				SignInLink:        satelliteAddress + "login",
				ResetPasswordLink: satelliteAddress + "forgot-password",
				CreateAccountLink: satelliteAddress + "signup",
			},
		)
		// return error since verified user already exists.
		a.serveJSONError(ctx, w, console.ErrUnauthorized.New("user already verified"))
		return
	}

	var user *console.User
	if len(unverified) == 0 {
		a.serveJSONError(ctx, w, console.ErrEmailNotFound.New("no unverified user found"))
		return
	}
	user = &unverified[0]

	now := time.Now()

	if user.LoginLockoutExpiration.After(now) {
		a.serveJSONError(ctx, w, console.ErrActivationCode.New("invalid activation code or account locked"))
		return
	}

	if user.ActivationCode != activateData.Code || user.SignupId != activateData.SignupId {
		lockoutDuration, err := a.service.UpdateUsersFailedLoginState(ctx, user)
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}
		if lockoutDuration > 0 {
			a.mailService.SendRenderedAsync(
				ctx,
				[]post.Address{{Address: user.Email, Name: user.FullName}},
				&console.ActivationLockAccountEmail{
					LockoutDuration: lockoutDuration,
					SupportURL:      a.GeneralRequestURL,
				},
			)
		}

		mon.Counter("account_activation_failed").Inc(1)                                          //mon:locked
		mon.IntVal("account_activation_user_failed_count").Observe(int64(user.FailedLoginCount)) //mon:locked
		penaltyThreshold := a.service.GetLoginAttemptsWithoutPenalty()

		if user.FailedLoginCount == penaltyThreshold {
			mon.Counter("account_activation_lockout_initiated").Inc(1) //mon:locked
		}

		if user.FailedLoginCount > penaltyThreshold {
			mon.Counter("account_activation_lockout_reinitiated").Inc(1) //mon:locked
		}

		a.serveJSONError(ctx, w, console.ErrActivationCode.New("invalid activation code or account locked"))
		return
	}

	if user.FailedLoginCount != 0 {
		if err := a.service.ResetAccountLock(ctx, user); err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}
	}

	err = a.service.SetAccountActive(ctx, user)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	tokenInfo, err := a.service.GenerateSessionToken(ctx, user.ID, user.Email, ip, r.UserAgent(), nil)
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

// loadSession looks for a cookie for the session id.
// this cookie is set from the reverse proxy if the user opts into cookies from Storj.
func loadSession(req *http.Request) string {
	sessionCookie, err := req.Cookie("webtraf-sid")
	if err != nil {
		return ""
	}
	return sessionCookie.Value
}

// GetFreezeStatus checks to see if an account is frozen or warned.
func (a *Auth) GetFreezeStatus(w http.ResponseWriter, r *http.Request) {
	type FrozenResult struct {
		Frozen             bool `json:"frozen"`
		Warned             bool `json:"warned"`
		ViolationFrozen    bool `json:"violationFrozen"`
		TrialExpiredFrozen bool `json:"trialExpiredFrozen"`
	}

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	userID, err := a.service.GetUserID(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	freezes, err := a.accountFreezeService.GetAll(ctx, userID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(FrozenResult{
		Frozen:             freezes.BillingFreeze != nil,
		Warned:             freezes.BillingWarning != nil,
		ViolationFrozen:    freezes.ViolationFreeze != nil,
		TrialExpiredFrozen: freezes.TrialExpirationFreeze != nil,
	})
	if err != nil {
		a.log.Error("could not encode account status", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// UpdateAccount updates user's full name and short name.
func (a *Auth) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var updatedInfo struct {
		FullName  string `json:"fullName"`
		ShortName string `json:"shortName"`
	}

	err = json.NewDecoder(r.Body).Decode(&updatedInfo)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.UpdateAccount(ctx, updatedInfo.FullName, updatedInfo.ShortName); err != nil {
		a.serveJSONError(ctx, w, err)
	}
}

// UpdateAccount updates user's full name and short name.
func (a *Auth) UpdateAccountInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var updatedInfo struct {
		SocialLinkedin *string `json:"socialLinkedin"`
		SocialTwitter  *string `json:"socialTwitter"`
		SocialFacebook *string `json:"socialFacebook"`
		SocialGithub   *string `json:"socialGithub"`

		WalletID *string `json:"walletId"`
	}

	err = json.NewDecoder(r.Body).Decode(&updatedInfo)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.UpdateAccountInfo(ctx, &console.UpdateUserSocialMediaLinks{
		SocialLinkedin: updatedInfo.SocialLinkedin,
		SocialTwitter:  updatedInfo.SocialTwitter,
		SocialFacebook: updatedInfo.SocialFacebook,
		SocialGithub:   updatedInfo.SocialGithub,
		WalletID:       updatedInfo.WalletID,
	}); err != nil {
		a.serveJSONError(ctx, w, err)
	}
}

func (a *Auth) DeleteAccountRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	err = a.service.DeleteAccountRequest(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
	}

	w.WriteHeader(http.StatusAccepted)
}

// SetupAccount updates user's full name and short name.
func (a *Auth) SetupAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var updatedInfo console.SetUpAccountRequest

	err = json.NewDecoder(r.Body).Decode(&updatedInfo)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if err = a.service.SetupAccount(ctx, updatedInfo); err != nil {
		a.serveJSONError(ctx, w, err)
	}
}

// GetAccount gets authorized user and take it's params.
func (a *Auth) GetAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var user struct {
		ID                    uuid.UUID  `json:"id"`
		FullName              string     `json:"fullName"`
		ShortName             string     `json:"shortName"`
		Email                 string     `json:"email"`
		Partner               string     `json:"partner"`
		ProjectLimit          int        `json:"projectLimit"`
		ProjectStorageLimit   int64      `json:"projectStorageLimit"`
		ProjectBandwidthLimit int64      `json:"projectBandwidthLimit"`
		ProjectSegmentLimit   int64      `json:"projectSegmentLimit"`
		IsProfessional        bool       `json:"isProfessional"`
		Position              string     `json:"position"`
		CompanyName           string     `json:"companyName"`
		EmployeeCount         string     `json:"employeeCount"`
		HaveSalesContact      bool       `json:"haveSalesContact"`
		PaidTier              bool       `json:"paidTier"`
		MFAEnabled            bool       `json:"isMFAEnabled"`
		MFARecoveryCodeCount  int        `json:"mfaRecoveryCodeCount"`
		CreatedAt             time.Time  `json:"createdAt"`
		PendingVerification   bool       `json:"pendingVerification"`
		TrialExpiration       *time.Time `json:"trialExpiration"`
		HasVarPartner         bool       `json:"hasVarPartner"`

		LoginToken string `json:"loginToken"`

		SocialLinkedin string `json:"socialLinkedin"`
		SocialTwitter  string `json:"socialTwitter"`
		SocialFacebook string `json:"socialFacebook"`
		SocialGithub   string `json:"socialGithub"`

		WalletId string `json:"walletId"`
	}

	consoleUser, err := console.GetUser(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	user.ShortName = consoleUser.ShortName
	user.FullName = consoleUser.FullName
	user.Email = consoleUser.Email
	user.ID = consoleUser.ID
	if consoleUser.UserAgent != nil {
		user.Partner = string(consoleUser.UserAgent)
	}
	user.ProjectLimit = consoleUser.ProjectLimit
	user.ProjectStorageLimit = consoleUser.ProjectStorageLimit
	user.ProjectBandwidthLimit = consoleUser.ProjectBandwidthLimit
	user.ProjectSegmentLimit = consoleUser.ProjectSegmentLimit
	user.IsProfessional = consoleUser.IsProfessional
	user.CompanyName = consoleUser.CompanyName
	user.Position = consoleUser.Position
	user.EmployeeCount = consoleUser.EmployeeCount
	user.HaveSalesContact = consoleUser.HaveSalesContact
	user.PaidTier = consoleUser.PaidTier
	user.MFAEnabled = consoleUser.MFAEnabled
	user.MFARecoveryCodeCount = len(consoleUser.MFARecoveryCodes)
	user.CreatedAt = consoleUser.CreatedAt
	user.PendingVerification = consoleUser.Status == console.PendingBotVerification
	user.TrialExpiration = consoleUser.TrialExpiration

	user.SocialLinkedin = consoleUser.SocialLinkedin
	user.SocialTwitter = consoleUser.SocialTwitter
	user.SocialFacebook = consoleUser.SocialFacebook
	user.SocialGithub = consoleUser.SocialGithub
	user.WalletId = consoleUser.WalletId

	user.HasVarPartner, err = a.service.GetUserHasVarPartner(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	token, err := r.Cookie("_tokenKey")
	if err == nil {
		user.LoginToken = token.Value
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&user)
	if err != nil {
		a.log.Error("could not encode user info", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// ChangePassword auth user, changes users password for a new one.
func (a *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
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

	err = a.service.ChangePassword(ctx, passwordChange.CurrentPassword, passwordChange.NewPassword)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// ForgotPassword creates password-reset token and sends email to user.
func (a *Auth) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var forgotPassword struct {
		Email           string `json:"email"`
		CaptchaResponse string `json:"captchaResponse"`
	}

	err = json.NewDecoder(r.Body).Decode(&forgotPassword)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	valid, err := a.service.VerifyForgotPasswordCaptcha(ctx, forgotPassword.CaptchaResponse, ip)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
	if !valid {
		a.serveJSONError(ctx, w, console.ErrCaptcha.New("captcha validation unsuccessful"))
		return
	}

	user, _, err := a.service.GetUserByEmailWithUnverified(ctx, forgotPassword.Email)
	if err != nil || user == nil {
		satelliteAddress := a.ExternalAddress

		if !strings.HasSuffix(satelliteAddress, "/") {
			satelliteAddress += "/"
		}
		resetPasswordLink := satelliteAddress + "forgot-password"
		doubleCheckLink := satelliteAddress + "login"
		createAccountLink := satelliteAddress + "signup"

		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: forgotPassword.Email, Name: ""}},
			&console.UnknownResetPasswordEmail{
				Satellite:           a.SatelliteName,
				Email:               forgotPassword.Email,
				DoubleCheckLink:     doubleCheckLink,
				ResetPasswordLink:   resetPasswordLink,
				CreateAnAccountLink: createAccountLink,
				SupportTeamLink:     a.GeneralRequestURL,
			},
		)
		return
	}

	recoveryToken, err := a.service.GeneratePasswordRecoveryToken(ctx, user.ID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	passwordRecoveryLink := a.PasswordRecoveryURL + "?token=" + recoveryToken
	cancelPasswordRecoveryLink := a.CancelPasswordRecoveryURL + "?token=" + recoveryToken
	userName := user.ShortName
	if user.ShortName == "" {
		userName = user.FullName
	}

	contactInfoURL := a.ContactInfoURL
	letUsKnowURL := a.LetUsKnowURL
	termsAndConditionsURL := a.TermsAndConditionsURL

	a.mailService.SendRenderedAsync(
		ctx,
		[]post.Address{{Address: user.Email, Name: userName}},
		&console.ForgotPasswordEmail{
			UserName:                   userName,
			Origin:                     a.ExternalAddress,
			ResetLink:                  passwordRecoveryLink,
			CancelPasswordRecoveryLink: cancelPasswordRecoveryLink,
			LetUsKnowURL:               letUsKnowURL,
			ContactInfoURL:             contactInfoURL,
			TermsAndConditionsURL:      termsAndConditionsURL,
		},
	)
}

// ResendEmail generates activation token by e-mail address and sends email account activation email to user.
// If the account is already activated, a password reset e-mail is sent instead.
func (a *Auth) ResendEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	params := mux.Vars(r)
	email, ok := params["email"]
	if !ok {
		return
	}

	verified, unverified, err := a.service.GetUserByEmailWithUnverified(ctx, email)
	if err != nil {
		return
	}

	if verified != nil {
		recoveryToken, err := a.service.GeneratePasswordRecoveryToken(ctx, verified.ID)
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}

		userName := verified.ShortName
		if verified.ShortName == "" {
			userName = verified.FullName
		}

		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: verified.Email, Name: userName}},
			&console.ForgotPasswordEmail{
				UserName:                   userName,
				Origin:                     a.ExternalAddress,
				ResetLink:                  a.PasswordRecoveryURL + "?token=" + recoveryToken,
				CancelPasswordRecoveryLink: a.CancelPasswordRecoveryURL + "?token=" + recoveryToken,
				LetUsKnowURL:               a.LetUsKnowURL,
				ContactInfoURL:             a.ContactInfoURL,
				TermsAndConditionsURL:      a.TermsAndConditionsURL,
			},
		)
		return
	}

	user := unverified[0]

	if a.ActivationCodeEnabled {
		user, err = a.service.SetActivationCodeAndSignupID(ctx, user)
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}

		a.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: user.Email}},
			&console.AccountActivationCodeEmail{
				ActivationCode: user.ActivationCode,
			},
		)

		return
	}

	token, err := a.service.GenerateActivationToken(ctx, user.ID, user.Email)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	link := a.ActivateAccountURL + "?token=" + token
	contactInfoURL := a.ContactInfoURL
	termsAndConditionsURL := a.TermsAndConditionsURL

	a.mailService.SendRenderedAsync(
		ctx,
		[]post.Address{{Address: user.Email}},
		&console.AccountActivationEmail{
			Username:              user.FullName,
			Origin:                a.ExternalAddress,
			ActivationLink:        link,
			TermsAndConditionsURL: termsAndConditionsURL,
			ContactInfoURL:        contactInfoURL,
		},
	)

	// Create Default Project - Munjal - 1/Oct/2023
	// tokenInfo, err := a.service.GenerateSessionToken(ctx, user.ID, user.Email, "", "", nil)
	// //require.NoError(t, err)
	// a.log.Error("Token Info:")
	// a.log.Error(tokenInfo.Token.String())

	// // Set up a test project and bucket

	// authed := console.WithUser(ctx, &user)

	// project, err := a.service.CreateProject(authed, console.UpsertProjectInfo{
	// 	Name: "My Project",
	// })
	// //require.NoError(t, err)
	// if err != nil {
	// 	a.log.Error("Error in Default Project:")
	// 	a.log.Error(err.Error())
	// 	a.serveJSONError(ctx, w, err)
	// 	return
	// }

	// a.log.Error("Default Project Name: " + project.Name)
	//a.log.Error(project.Name)
	/*
		bucketID, err := uuid.New()
		//require.NoError(t, err)
		if err != nil {
			a.log.Error("Error in uuid:")
			a.log.Error(err.Error())
			a.serveJSONError(ctx, w, err)
			return
		}
		a.log.Error("Default Bucket ID: " + bucketID.String())
		//a.log.Error(bucketID.String())
		b := buckets.Service{}
		bucket, err := b.CreateBucket(authed, buckets.Bucket{
			ID:        bucketID,
			Name:      "default",
			ProjectID: project.ID,
		})
		if err != nil {
			a.log.Error("Bucket Creation Error: " + err.Error())
			a.serveJSONError(ctx, w, err)
			return
		}
		a.log.Error("Default Bucket Creation:" + bucket.Name)
		//a.log.Error(bucket.Name)
	*/
}

func newTestBucket(name string, projectID uuid.UUID) buckets.Bucket {
	return buckets.Bucket{
		ID:                  testrand.UUID(),
		Name:                name,
		ProjectID:           projectID,
		PathCipher:          storj.EncAESGCM,
		DefaultSegmentsSize: 65536,
		DefaultRedundancyScheme: storj.RedundancyScheme{
			Algorithm:      storj.ReedSolomon,
			ShareSize:      9,
			RequiredShares: 10,
			RepairShares:   11,
			OptimalShares:  12,
			TotalShares:    13,
		},
		DefaultEncryptionParameters: storj.EncryptionParameters{
			CipherSuite: storj.EncAESGCM,
			BlockSize:   9 * 10,
		},
		Placement: storj.EU,
	}
}

// EnableUserMFA enables multi-factor authentication for the user.
func (a *Auth) EnableUserMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		Passcode string `json:"passcode"`
	}
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = a.service.EnableUserMFA(ctx, data.Passcode, time.Now())
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	consoleUser, err := console.GetUser(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = a.service.DeleteAllSessionsByUserIDExcept(ctx, consoleUser.ID, sessionID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// DisableUserMFA disables multi-factor authentication for the user.
func (a *Auth) DisableUserMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		Passcode     string `json:"passcode"`
		RecoveryCode string `json:"recoveryCode"`
	}
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = a.service.DisableUserMFA(ctx, data.Passcode, time.Now(), data.RecoveryCode)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	sessionID, err := a.getSessionID(r)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	consoleUser, err := console.GetUser(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = a.service.DeleteAllSessionsByUserIDExcept(ctx, consoleUser.ID, sessionID)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// GenerateMFASecretKey creates a new TOTP secret key for the user.
func (a *Auth) GenerateMFASecretKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	key, err := a.service.ResetMFASecretKey(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(key)
	if err != nil {
		a.log.Error("could not encode MFA secret key", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// GenerateMFARecoveryCodes creates a new set of MFA recovery codes for the user.
func (a *Auth) GenerateMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	codes, err := a.service.ResetMFARecoveryCodes(ctx, false, "", "")
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(codes)
	if err != nil {
		a.log.Error("could not encode MFA recovery codes", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// RegenerateMFARecoveryCodes requires MFA code to create a new set of MFA recovery codes for the user.
func (a *Auth) RegenerateMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		Passcode     string `json:"passcode"`
		RecoveryCode string `json:"recoveryCode"`
	}
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	codes, err := a.service.ResetMFARecoveryCodes(ctx, true, data.Passcode, data.RecoveryCode)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(codes)
	if err != nil {
		a.log.Error("could not encode MFA recovery codes", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// ResetPassword resets user's password using recovery token.
func (a *Auth) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var resetPassword struct {
		RecoveryToken   string `json:"token"`
		NewPassword     string `json:"password"`
		MFAPasscode     string `json:"mfaPasscode"`
		MFARecoveryCode string `json:"mfaRecoveryCode"`
	}

	err = json.NewDecoder(r.Body).Decode(&resetPassword)
	if err != nil {
		a.serveJSONError(ctx, w, err)
	}

	if a.badPasswords != nil {
		_, exists := a.badPasswords[resetPassword.NewPassword]
		if exists {
			a.serveJSONError(ctx, w, console.ErrValidation.Wrap(errs.New("The password you chose is on a list of insecure or breached passwords. Please choose a different one.")))
			return
		}
	}

	err = a.service.ResetPassword(ctx, resetPassword.RecoveryToken, resetPassword.NewPassword, resetPassword.MFAPasscode, resetPassword.MFARecoveryCode, time.Now())

	if console.ErrMFAMissing.Has(err) || console.ErrMFAPasscode.Has(err) || console.ErrMFARecoveryCode.Has(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.getStatusCode(err))

		err = json.NewEncoder(w).Encode(map[string]string{
			"error": a.getUserErrorMessage(err),
			"code":  "mfa_required",
		})

		if err != nil {
			a.log.Error("failed to write json response", zap.Error(ErrUtils.Wrap(err)))
		}

		return
	}

	if console.ErrTokenExpiration.Has(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.getStatusCode(err))

		err = json.NewEncoder(w).Encode(map[string]string{
			"error": a.getUserErrorMessage(err),
			"code":  "token_expired",
		})

		if err != nil {
			a.log.Error("password-reset-token expired: failed to write json response", zap.Error(ErrUtils.Wrap(err)))
		}

		return
	}

	if err != nil {
		a.serveJSONError(ctx, w, err)
	} else {
		a.cookieAuth.RemoveTokenCookie(w)
	}
}

// RefreshSession refreshes the user's session.
func (a *Auth) RefreshSession(w http.ResponseWriter, r *http.Request) {
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

	tokenInfo.ExpiresAt, err = a.service.RefreshSession(ctx, id)
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

// GetUserSettings gets a user's settings.
func (a *Auth) GetUserSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	settings, err := a.service.GetUserSettings(ctx)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = json.NewEncoder(w).Encode(settings)
	if err != nil {
		a.log.Error("could not encode settings", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// SetOnboardingStatus updates a user's onboarding status.
func (a *Auth) SetOnboardingStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var updateInfo struct {
		OnboardingStart *bool   `json:"onboardingStart"`
		OnboardingEnd   *bool   `json:"onboardingEnd"`
		OnboardingStep  *string `json:"onboardingStep"`
	}

	err = json.NewDecoder(r.Body).Decode(&updateInfo)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	_, err = a.service.SetUserSettings(ctx, console.UpsertUserSettingsRequest{
		OnboardingStart: updateInfo.OnboardingStart,
		OnboardingEnd:   updateInfo.OnboardingEnd,
		OnboardingStep:  updateInfo.OnboardingStep,
	})
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}
}

// SetUserSettings updates a user's settings.
func (a *Auth) SetUserSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var updateInfo struct {
		OnboardingStart  *bool                    `json:"onboardingStart"`
		OnboardingEnd    *bool                    `json:"onboardingEnd"`
		PassphrasePrompt *bool                    `json:"passphrasePrompt"`
		OnboardingStep   *string                  `json:"onboardingStep"`
		SessionDuration  *int64                   `json:"sessionDuration"`
		NoticeDismissal  *console.NoticeDismissal `json:"noticeDismissal"`
	}

	err = json.NewDecoder(r.Body).Decode(&updateInfo)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	var newDuration **time.Duration
	if updateInfo.SessionDuration != nil {
		newDuration = new(*time.Duration)
		if *updateInfo.SessionDuration != 0 {
			duration := time.Duration(*updateInfo.SessionDuration)
			*newDuration = &duration
		}
	}

	settings, err := a.service.SetUserSettings(ctx, console.UpsertUserSettingsRequest{
		OnboardingStart:  updateInfo.OnboardingStart,
		OnboardingEnd:    updateInfo.OnboardingEnd,
		OnboardingStep:   updateInfo.OnboardingStep,
		PassphrasePrompt: updateInfo.PassphrasePrompt,
		SessionDuration:  newDuration,
		NoticeDismissal:  updateInfo.NoticeDismissal,
	})
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = json.NewEncoder(w).Encode(settings)
	if err != nil {
		a.log.Error("could not encode settings", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

// RequestLimitIncrease handles requesting increase for project limit.
func (a *Auth) RequestLimitIncrease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		a.serveJSONError(ctx, w, err)
	}

	err = a.service.RequestProjectLimitIncrease(ctx, string(b))
	if err != nil {
		a.serveJSONError(ctx, w, err)
	}
}

// serveJSONError writes JSON error to response output stream.
func (a *Auth) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	status := a.getStatusCode(err)
	web.ServeCustomJSONError(ctx, a.log, w, status, err, a.getUserErrorMessage(err))
}

// getStatusCode returns http.StatusCode depends on console error class.
func (a *Auth) getStatusCode(err error) int {
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

// getUserErrorMessage returns a user-friendly representation of the error.
func (a *Auth) getUserErrorMessage(err error) string {
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

// RegisterPipedriveForApp registers user in storj.io who came from Pipedrive OAuth mobile app.
func (a *Auth) RegisterPipedriveForApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body struct {
		AccessToken string `json:"accessToken"`
		Wallet      string `json:"wallet"`
	}

	if err = json.NewDecoder(r.Body).Decode(&body); err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	if body.AccessToken == "" && body.Wallet == "" {
		a.serveJSONError(ctx, w, errors.New("access token is required"))
		return
	}

	// Get user info using the token
	pipedriveUser, err := socialmedia.GetPipedriveUser(body.AccessToken)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	// Check if user already exists
	user, err := a.service.GetUsers().GetByEmail(ctx, pipedriveUser.Data.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		a.serveJSONError(ctx, w, err)
		return
	}

	if user == nil {
		secret, err := console.RegistrationSecretFromBase64("")
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}

		status := console.Active

		user, err = a.service.CreateUser(ctx, console.CreateUser{
			Email:           pipedriveUser.Data.Email,
			FullName:        pipedriveUser.Data.Name,
			ShortName:       "",
			Password:        "",
			Status:          int(status),
			SignupPromoCode: "",
			IsProfessional:  true,
			Source:          "",
			WalletId:        body.Wallet,
		}, secret, true)
		if err != nil {
			a.serveJSONError(ctx, w, err)
			return
		}

	}

	tokenInfo, err := a.service.GenerateSessionToken(ctx, user.ID, user.Email, "", "", nil)
	if err != nil {
		a.serveJSONError(ctx, w, err)
		return
	}

	err = json.NewEncoder(w).Encode(tokenInfo)
	if err != nil {
		a.log.Error("could not encode token response", zap.Error(ErrAuthAPI.Wrap(err)))
	}
}
