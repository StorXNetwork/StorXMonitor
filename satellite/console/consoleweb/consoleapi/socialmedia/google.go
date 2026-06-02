package socialmedia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const googleTokenURL = "https://oauth2.googleapis.com/token"

var googleHTTPClient = &http.Client{Timeout: 10 * time.Second}

type GoogleOauthToken struct {
	Access_token  string
	Id_token      string
	Refresh_token string
	ExpiresIn     int
	ExpiresAt     time.Time
}

// GoogleRefreshTokenResult is returned after refreshing a Google access token.
type GoogleRefreshTokenResult struct {
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
}

type GoogleUserResult struct {
	Id             string
	Email          string
	Verified_email bool
	Name           string
	Given_name     string
	Family_name    string
	Picture        string
	Locale         string
}

func GetGoogleOauthToken(code string, mode string, zohoInsert bool) (*GoogleOauthToken, error) {
	// signup = register-google redirect; signin = login-google redirect; connect = login redirect for logged-in backup connect.
	if mode != "signup" && mode != "signin" && mode != "connect" {
		return nil, errors.New("invalid mode")
	}

	if configVal.GoogleClientID == "" || configVal.GoogleClientSecret == "" {
		return nil, errors.New("invalid google client id or secret")
	}

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("client_id", configVal.GoogleClientID)
	values.Add("client_secret", configVal.GoogleClientSecret)
	redirectURL := configVal.GoogleOAuthRedirectUrl_login
	if mode == "signup" {
		redirectURL = configVal.GoogleOAuthRedirectUrl_register
	}

	if zohoInsert {
		redirectURL += "?zoho-insert"
	}

	values.Add("redirect_uri", redirectURL)

	query := values.Encode()

	fmt.Println("GOOGLE Query: "+query, "mode: "+mode)

	req, err := http.NewRequest(http.MethodPost, googleTokenURL, bytes.NewBufferString(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := googleHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google token exchange returned status %d: %s", res.StatusCode, string(resBody))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(resBody, &tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.AccessToken == "" || tokenResp.IDToken == "" {
		return nil, errors.New("google token response missing access_token or id_token")
	}

	tokenBody := &GoogleOauthToken{
		Access_token:  tokenResp.AccessToken,
		Id_token:      tokenResp.IDToken,
		Refresh_token: tokenResp.RefreshToken,
		ExpiresIn:     tokenResp.ExpiresIn,
	}
	if tokenResp.ExpiresIn > 0 {
		tokenBody.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return tokenBody, nil
}

func GetGoogleUser(access_token string, id_token string) (*GoogleUserResult, error) {
	if access_token == "" || id_token == "" {
		return nil, errors.New("invalid token")
	}

	rootUrl := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", access_token)

	req, err := http.NewRequest("GET", rootUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", id_token))

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve user")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes GoogleUserResult

	if err := json.Unmarshal(resBody, &GoogleUserRes); err != nil {
		return nil, err
	}

	if GoogleUserRes.Email == "" {
		return nil, errors.New("could not retrieve user details from google")
	}

	return &GoogleUserRes, nil
}

func GetGoogleUserByAccessToken(access_token string) (*GoogleUserResult, error) {
	if access_token == "" {
		return nil, errors.New("invalid access token")
	}

	rootUrl := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", access_token)

	req, err := http.NewRequest("GET", rootUrl, nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve user")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes GoogleUserResult

	if err := json.Unmarshal(resBody, &GoogleUserRes); err != nil {
		return nil, err
	}

	return &GoogleUserRes, nil
}

// GoogleRegisterBackupScopes are required for registration backup, restore, and domain-users classification.
var GoogleRegisterBackupScopes = []string{
	"openid",
	"email",
	"profile",
	// Gmail — personal mailbox read + restore insert
	"https://www.googleapis.com/auth/gmail.readonly",
	"https://www.googleapis.com/auth/gmail.insert",
	// Workspace admin — corporate domain-users and directory listing
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	// Google Drive
	"https://www.googleapis.com/auth/drive.readonly",
	// Google Photos
	"https://www.googleapis.com/auth/photoslibrary.readonly",
	// Google Calendar
	"https://www.googleapis.com/auth/calendar.readonly",
	// Google Contacts (People API)
	"https://www.googleapis.com/auth/contacts.readonly",
}

// BuildGoogleRegisterOAuthURL builds the Google OAuth URL for register-google with offline refresh token.
func BuildGoogleRegisterOAuthURL(state string) (string, error) {
	if configVal.GoogleClientID == "" {
		return "", errors.New("invalid google client id")
	}

	redirectURL := configVal.GoogleOAuthRedirectUrl_register
	params := url.Values{}
	params.Set("client_id", configVal.GoogleClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(GoogleRegisterBackupScopes, " "))
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")
	if state != "" {
		params.Set("state", state)
	}

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode(), nil
}

// RefreshAccessToken exchanges a refresh token for a new Google access token.
func RefreshAccessToken(ctx context.Context, refreshToken string) (*GoogleRefreshTokenResult, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is required")
	}
	if configVal.GoogleClientID == "" || configVal.GoogleClientSecret == "" {
		return nil, errors.New("invalid google client id or secret")
	}

	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("refresh_token", refreshToken)
	values.Set("client_id", configVal.GoogleClientID)
	values.Set("client_secret", configVal.GoogleClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := googleHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google refresh token returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.AccessToken == "" {
		return nil, errors.New("google refresh token response missing access_token")
	}

	return &GoogleRefreshTokenResult{
		AccessToken:  tokenResp.AccessToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}

// ResolveAccessToken returns a valid access token, refreshing when expired.
// Updated tokens are returned in-memory only; callers persist them separately when DB support exists.
func ResolveAccessToken(ctx context.Context, accessToken, refreshToken string, expiry time.Time) (string, time.Time, error) {
	if accessToken != "" && !expiry.IsZero() && time.Now().Before(expiry) {
		return accessToken, expiry, nil
	}

	if refreshToken == "" {
		return "", time.Time{}, errors.New("access token expired and no refresh token available")
	}

	refreshed, err := RefreshAccessToken(ctx, refreshToken)
	if err != nil {
		return "", time.Time{}, err
	}

	newExpiry := time.Time{}
	if refreshed.ExpiresIn > 0 {
		newExpiry = time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second)
	}

	return refreshed.AccessToken, newExpiry, nil
}
