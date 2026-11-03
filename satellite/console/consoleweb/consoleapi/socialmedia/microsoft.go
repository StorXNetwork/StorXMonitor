// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package socialmedia

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	microsoftTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	microsoftGraphMe  = "https://graph.microsoft.com/v1.0/me"
	microsoftJWKSURL  = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

	// MicrosoftAuthActionRegistered is returned when combined Microsoft auth creates a new account.
	MicrosoftAuthActionRegistered = "registered"
	// MicrosoftAuthActionLoggedIn is returned when combined Microsoft auth logs into an existing account.
	MicrosoftAuthActionLoggedIn = "logged_in"
)

var microsoftHTTPClient = &http.Client{Timeout: 15 * time.Second}

// MicrosoftOauthToken holds tokens from Microsoft token exchange or MSAL.
type MicrosoftOauthToken struct {
	Access_token  string
	Id_token      string
	Refresh_token string
	Scope         string
	ExpiresIn     int
	ExpiresAt     time.Time
}

// MicrosoftUserResult is the profile used for login/register.
type MicrosoftUserResult struct {
	Id    string
	Email string
	Name  string
	// TenantID is the Entra `tid` of the signed-in account; empty when it could not be determined.
	TenantID string
}

// MicrosoftAuthSession holds Microsoft profile and tokens after resolution.
type MicrosoftAuthSession struct {
	User   *MicrosoftUserResult
	Tokens *MicrosoftOauthToken
}

type microsoftJWKS struct {
	Keys []microsoftJWK `json:"keys"`
}

type microsoftJWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var (
	microsoftJWKSCache   microsoftJWKS
	microsoftJWKSFetched time.Time
	microsoftJWKSMu      sync.Mutex
)

// ResolveMicrosoftAuth resolves the frontend `code` query value into a Microsoft session.
// Supports Option B (MSAL idToken/accessToken passed as code) and Option A (raw auth code exchange).
func ResolveMicrosoftAuth(code, redirectURI string) (*MicrosoftAuthSession, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, errors.New("authorization code not provided")
	}

	if looksLikeJWT(code) {
		if user, err := GetMicrosoftUserByAccessToken(code); err == nil {
			tokens := &MicrosoftOauthToken{Access_token: code}
			user.TenantID = MicrosoftTenantIDFromTokens(tokens)
			user.Id = MicrosoftAccountIDFromTokens(tokens, user.Id)
			return &MicrosoftAuthSession{User: user, Tokens: tokens}, nil
		} else if claims, idErr := VerifyMicrosoftIDToken(code); idErr == nil {
			return &MicrosoftAuthSession{
				User:   microsoftUserFromIDTokenClaims(claims),
				Tokens: &MicrosoftOauthToken{Id_token: code},
			}, nil
		} else {
			return nil, fmt.Errorf("microsoft token validation failed: graph=%v; id_token=%v", err, idErr)
		}
	}

	tokenRes, err := GetMicrosoftOauthTokenWithRedirect(code, redirectURI)
	if err != nil {
		return nil, err
	}

	user, err := GetMicrosoftUserByAccessToken(tokenRes.Access_token)
	if err != nil {
		claims, idErr := VerifyMicrosoftIDToken(tokenRes.Id_token)
		if idErr != nil {
			return nil, err
		}
		user = microsoftUserFromIDTokenClaims(claims)
	}
	if user.TenantID == "" {
		user.TenantID = MicrosoftTenantIDFromTokens(tokenRes)
	}
	user.Id = MicrosoftAccountIDFromTokens(tokenRes, user.Id)

	return &MicrosoftAuthSession{
		User:   user,
		Tokens: tokenRes,
	}, nil
}

func microsoftUserFromIDTokenClaims(claims *MicrosoftIDTokenClaims) *MicrosoftUserResult {
	return &MicrosoftUserResult{
		Id:       claims.Oid,
		Email:    claims.Email,
		Name:     claims.Name,
		TenantID: claims.Tid,
	}
}

// MicrosoftTenantIDFromTokens returns the Entra `tid` for a Microsoft sign-in.
// The verified id_token is preferred. Otherwise the `tid` claim is read from the access token,
// which Graph has already accepted; personal-account access tokens may be opaque, in which case "" is returned.
func MicrosoftTenantIDFromTokens(tokens *MicrosoftOauthToken) string {
	if tokens == nil {
		return ""
	}
	if strings.TrimSpace(tokens.Id_token) != "" {
		if claims, err := VerifyMicrosoftIDToken(tokens.Id_token); err == nil && claims.Tid != "" {
			return claims.Tid
		}
	}
	return unverifiedJWTClaim(tokens.Access_token, "tid")
}

// MicrosoftAccountIDFromTokens returns the home-tenant object ID (`oid`) of a Microsoft sign-in, which
// identifies the backup credential. The verified id_token is preferred, then the access token claim.
// Graph /me returns a differently formatted id for personal accounts, so fallback is used only when
// neither token carries `oid`.
func MicrosoftAccountIDFromTokens(tokens *MicrosoftOauthToken, fallback string) string {
	if tokens != nil {
		if strings.TrimSpace(tokens.Id_token) != "" {
			if claims, err := VerifyMicrosoftIDToken(tokens.Id_token); err == nil && claims.Oid != "" {
				return strings.ToLower(claims.Oid)
			}
		}
		if oid := unverifiedJWTClaim(tokens.Access_token, "oid"); oid != "" {
			return strings.ToLower(oid)
		}
	}
	return strings.ToLower(strings.TrimSpace(fallback))
}

func unverifiedJWTClaim(token, key string) string {
	token = strings.TrimSpace(token)
	if !looksLikeJWT(token) {
		return ""
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return ""
	}
	return strings.TrimSpace(claimString(claims, key))
}

// GetMicrosoftOauthTokenWithRedirect exchanges an OAuth authorization code for Microsoft tokens.
func GetMicrosoftOauthTokenWithRedirect(code, redirectURI string) (*MicrosoftOauthToken, error) {
	if configVal.OutlookClientID == "" || configVal.OutlookClientSecret == "" {
		return nil, errors.New("invalid outlook client id or secret")
	}

	redirectURL := strings.TrimSpace(redirectURI)
	if redirectURL == "" {
		redirectURL = strings.TrimSpace(configVal.OutlookOAuthRedirectUrl_microsoftbackup)
	}
	if redirectURL == "" {
		return nil, errors.New("OUTLOOK_OAUTH_REDIRECT_URL_MICROSOFT_BACKUP is not configured")
	}
	redirectURL = strings.TrimRight(redirectURL, "/")

	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("client_id", configVal.OutlookClientID)
	values.Set("client_secret", configVal.OutlookClientSecret)
	values.Set("redirect_uri", redirectURL)
	// Do NOT send scope on code exchange. Passing MicrosoftBackupScopes here strips any
	// incremental restore write scopes (e.g. Mail.ReadWrite) the user just consented to,
	// so prepare keeps returning missing_permissions after Grant Access / connect.
	// Omitting scope returns tokens for whatever the authorization code granted.

	req, err := http.NewRequest(http.MethodPost, microsoftTokenURL, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := microsoftHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft token exchange returned status %d: %s", res.StatusCode, string(resBody))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(resBody, &tokenResp); err != nil {
		return nil, err
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("microsoft token response missing access_token")
	}

	tokenBody := &MicrosoftOauthToken{
		Access_token:  tokenResp.AccessToken,
		Id_token:      tokenResp.IDToken,
		Refresh_token: tokenResp.RefreshToken,
		Scope:         tokenResp.Scope,
		ExpiresIn:     tokenResp.ExpiresIn,
	}
	if tokenResp.ExpiresIn > 0 {
		tokenBody.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	return tokenBody, nil
}

// GetMicrosoftUserByAccessToken loads the signed-in user from Microsoft Graph /me.
func GetMicrosoftUserByAccessToken(accessToken string) (*MicrosoftUserResult, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, errors.New("invalid access token")
	}

	req, err := http.NewRequest(http.MethodGet, microsoftGraphMe, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	res, err := microsoftHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft graph /me returned status %d: %s", res.StatusCode, string(body))
	}

	var graphUser struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.Unmarshal(body, &graphUser); err != nil {
		return nil, err
	}

	email := strings.TrimSpace(graphUser.Mail)
	if email == "" {
		email = strings.TrimSpace(graphUser.UserPrincipalName)
	}
	email = strings.ToLower(email)
	if email == "" || !strings.Contains(email, "@") {
		return nil, errors.New("could not retrieve user email from microsoft graph")
	}

	name := strings.TrimSpace(graphUser.DisplayName)
	if name == "" {
		name = email
	}

	return &MicrosoftUserResult{
		Id:    graphUser.ID,
		Email: email,
		Name:  name,
	}, nil
}

// MicrosoftIDTokenClaims are the claims we need from a Microsoft id_token.
type MicrosoftIDTokenClaims struct {
	Oid               string `json:"oid"`
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Tid               string `json:"tid"`
	Aud               string `json:"aud"`
	Iss               string `json:"iss"`
	Exp               int64  `json:"exp"`
}

// VerifyMicrosoftIDToken validates a Microsoft id_token via JWKS and extracts identity claims.
func VerifyMicrosoftIDToken(idToken string) (*MicrosoftIDTokenClaims, error) {
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return nil, errors.New("id token is required")
	}
	if configVal.OutlookClientID == "" {
		return nil, errors.New("invalid outlook client id")
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	token, err := parser.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("microsoft id_token missing kid")
		}
		return getMicrosoftPublicKey(kid)
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("microsoft id_token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("microsoft id_token claims are invalid")
	}

	out := &MicrosoftIDTokenClaims{
		Oid:               claimString(claims, "oid"),
		Sub:               claimString(claims, "sub"),
		Email:             claimString(claims, "email"),
		PreferredUsername: claimString(claims, "preferred_username"),
		Name:              claimString(claims, "name"),
		Tid:               claimString(claims, "tid"),
		Aud:               claimString(claims, "aud"),
		Iss:               claimString(claims, "iss"),
	}
	if exp, ok := claims["exp"].(float64); ok {
		out.Exp = int64(exp)
	}

	if !audienceContains(claims["aud"], configVal.OutlookClientID) {
		return nil, errors.New("microsoft id_token audience mismatch")
	}
	if out.Iss != "" && !strings.Contains(out.Iss, "microsoftonline.com") && !strings.Contains(out.Iss, "sts.windows.net") {
		return nil, errors.New("microsoft id_token issuer mismatch")
	}
	if out.Exp > 0 && time.Now().After(time.Unix(out.Exp, 0)) {
		return nil, errors.New("microsoft id_token has expired")
	}

	email := strings.ToLower(strings.TrimSpace(out.Email))
	if email == "" {
		email = strings.ToLower(strings.TrimSpace(out.PreferredUsername))
	}
	if email == "" || !strings.Contains(email, "@") {
		return nil, errors.New("microsoft id_token missing email")
	}
	out.Email = email

	if out.Name == "" {
		out.Name = email
	}
	if out.Oid == "" {
		out.Oid = out.Sub
	}
	return out, nil
}

// looksLikeJWT requires a base64url JSON header with "alg": Microsoft authorization codes
// (e.g. "1.AcYA...GAA.BQAB...") also contain exactly two dots.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false
	}
	return header.Alg != ""
}

func claimString(claims jwt.MapClaims, key string) string {
	v, ok := claims[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func audienceContains(aud interface{}, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func getMicrosoftPublicKey(kid string) (*rsa.PublicKey, error) {
	jwks, err := fetchMicrosoftJWKS()
	if err != nil {
		return nil, err
	}
	for _, key := range jwks.Keys {
		if key.Kid != kid {
			continue
		}
		return jwkToRSAPublicKey(key)
	}
	// Force refresh once if kid not found (key rotation).
	microsoftJWKSMu.Lock()
	microsoftJWKSFetched = time.Time{}
	microsoftJWKSMu.Unlock()

	jwks, err = fetchMicrosoftJWKS()
	if err != nil {
		return nil, err
	}
	for _, key := range jwks.Keys {
		if key.Kid != kid {
			continue
		}
		return jwkToRSAPublicKey(key)
	}
	return nil, fmt.Errorf("microsoft jwks key not found for kid %s", kid)
}

func fetchMicrosoftJWKS() (microsoftJWKS, error) {
	microsoftJWKSMu.Lock()
	defer microsoftJWKSMu.Unlock()

	if time.Since(microsoftJWKSFetched) < time.Hour && len(microsoftJWKSCache.Keys) > 0 {
		return microsoftJWKSCache, nil
	}

	req, err := http.NewRequest(http.MethodGet, microsoftJWKSURL, nil)
	if err != nil {
		return microsoftJWKS{}, err
	}
	res, err := microsoftHTTPClient.Do(req)
	if err != nil {
		return microsoftJWKS{}, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return microsoftJWKS{}, err
	}
	if res.StatusCode != http.StatusOK {
		return microsoftJWKS{}, fmt.Errorf("microsoft jwks returned status %d: %s", res.StatusCode, string(body))
	}

	var jwks microsoftJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return microsoftJWKS{}, err
	}
	if len(jwks.Keys) == 0 {
		return microsoftJWKS{}, errors.New("microsoft jwks response empty")
	}

	microsoftJWKSCache = jwks
	microsoftJWKSFetched = time.Now()
	return microsoftJWKSCache, nil
}

func jwkToRSAPublicKey(key microsoftJWK) (*rsa.PublicKey, error) {
	if key.Kty != "" && key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported microsoft jwk kty %s", key.Kty)
	}
	nb, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	var eInt int
	for _, b := range eb {
		eInt = eInt<<8 | int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: eInt,
	}, nil
}

const microsoftAuthorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

// MicrosoftBackupScopes are the delegated scopes for Microsoft Backup login/connect (self-backup).
// Only scopes a normal user can approve are listed. Organization backup does not use delegated
// scopes: it uses Graph application permissions granted through tenant admin consent and an
// app-only token in Backup-Tools.
// Restore write scopes are NOT included — UI must use MicrosoftRestoreScopes + POST /microsoft-backup/microsoft-auth.
// Keep aligned with Backup-Tools apps/outlook defaultScopes.
var MicrosoftBackupScopes = []string{
	"openid",
	"profile",
	"email",
	"offline_access", // required for opaque refresh_token (not a JWT)
	"User.Read",
	"Mail.Read",
	"Calendars.Read",
	"Contacts.Read",
	"Files.Read",
}

// MicrosoftRestoreScopes are write permissions for select-and-restore only.
// UI builds a separate Microsoft authorize URL with these scopes, then exchanges the Graph
// access token via POST /microsoft-backup/microsoft-auth before calling office365/satellite-to-*.
var MicrosoftRestoreScopes = []string{
	"openid",
	"profile",
	"email",
	"offline_access",
	"User.Read",
	"Mail.ReadWrite",
	"Calendars.ReadWrite",
	"Contacts.ReadWrite",
	"Files.ReadWrite.All",
	"ChannelMessage.Send",
	"Group.ReadWrite.All",
}

// MicrosoftBackupScopesString returns the space-separated scope list for MSAL / authorize URL.
func MicrosoftBackupScopesString() string {
	return strings.Join(MicrosoftBackupScopes, " ")
}

// MicrosoftRestoreScopesString returns space-separated restore scopes for the restore OAuth consent screen.
func MicrosoftRestoreScopesString() string {
	return strings.Join(MicrosoftRestoreScopes, " ")
}

// BuildMicrosoftBackupOAuthURL builds the Microsoft authorize URL for microsoft-backup.
// Used by tests and UI reference only — no Satellite HTTP route (same as Google backup OAuth URL).
func BuildMicrosoftBackupOAuthURL(state, redirectURI string) (string, error) {
	if configVal.OutlookClientID == "" {
		return "", errors.New("invalid outlook client id")
	}
	redirectURL := strings.TrimSpace(redirectURI)
	if redirectURL == "" {
		redirectURL = strings.TrimSpace(configVal.OutlookOAuthRedirectUrl_microsoftbackup)
	}
	if redirectURL == "" {
		return "", errors.New("OUTLOOK_OAUTH_REDIRECT_URL_MICROSOFT_BACKUP is not configured")
	}
	redirectURL = strings.TrimRight(redirectURL, "/")

	params := url.Values{}
	params.Set("client_id", configVal.OutlookClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("response_mode", "query")
	params.Set("scope", MicrosoftBackupScopesString())
	params.Set("prompt", "consent") // force refresh_token issuance
	if state != "" {
		params.Set("state", state)
	}
	return microsoftAuthorizeURL + "?" + params.Encode(), nil
}

// ParseMicrosoftScopeString splits Microsoft's space-separated scope string.
func ParseMicrosoftScopeString(scope string) []string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}
	parts := strings.Fields(scope)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Normalize Graph full URI → short name for comparison.
		p = strings.TrimPrefix(p, "https://graph.microsoft.com/")
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
