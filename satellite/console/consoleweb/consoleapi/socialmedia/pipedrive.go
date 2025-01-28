package socialmedia

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// PipedriveOauthToken represents the OAuth token response from Pipedrive
type PipedriveOauthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// PipedriveUserResult represents user information from Pipedrive
type PipedriveUserResult struct {
	Success bool `json:"success"`
	Data    struct {
		ID          int    `json:"id"`
		Email       string `json:"email"`
		Name        string `json:"name"`
		CompanyID   int    `json:"company_id"`
		CompanyName string `json:"company_name"`
		Active      bool   `json:"active"`
		Role        string `json:"role"`
	} `json:"data"`
}

// GetPipedriveOauthToken exchanges the authorization code for an access token
func GetPipedriveOauthToken(code string) (*PipedriveOauthToken, error) {
	if configVal.PipeDriveClientID == "" || configVal.PipeDriveClientSecret == "" {
		return nil, errors.New("invalid pipedrive client id or secret")
	}

	const tokenURL = "https://oauth.pipedrive.com/oauth/token"

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("client_id", configVal.PipeDriveClientID)
	values.Add("client_secret", configVal.PipeDriveClientSecret)
	values.Add("redirect_uri", configVal.PipeDriveRedirectUrl)

	query := values.Encode()

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to retrieve token: %s", string(body))
	}

	var token PipedriveOauthToken
	if err := json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %v", err)
	}

	return &token, nil
}

// GetPipedriveUser retrieves user information using the access token
func GetPipedriveUser(accessToken string) (*PipedriveUserResult, error) {
	if accessToken == "" {
		return nil, errors.New("invalid access token")
	}

	const userURL = "https://api.pipedrive.com/v1/users/me"

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to retrieve user info: %s", string(body))
	}

	var userResult PipedriveUserResult
	if err := json.NewDecoder(res.Body).Decode(&userResult); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %v", err)
	}

	if !userResult.Success || userResult.Data.Email == "" {
		return nil, errors.New("could not retrieve user details from Pipedrive")
	}

	return &userResult, nil
}

// RefreshPipedriveToken refreshes an expired access token
func RefreshPipedriveToken(refreshToken string) (*PipedriveOauthToken, error) {
	if configVal.PipeDriveClientID == "" || configVal.PipeDriveClientSecret == "" {
		return nil, errors.New("invalid pipedrive client id or secret")
	}

	const tokenURL = "https://oauth.pipedrive.com/oauth/token"

	values := url.Values{}
	values.Add("grant_type", "refresh_token")
	values.Add("refresh_token", refreshToken)
	values.Add("client_id", configVal.PipeDriveClientID)
	values.Add("client_secret", configVal.PipeDriveClientSecret)

	query := values.Encode()

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to refresh token: %s", string(body))
	}

	var token PipedriveOauthToken
	if err := json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %v", err)
	}

	return &token, nil
}
