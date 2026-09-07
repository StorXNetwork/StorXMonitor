// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package socialmedia

import (
	"encoding/json"
	"errors"
	"net/http"
)

const (
	// GoogleAuthActionRegistered is returned when combined Google auth creates a new account.
	GoogleAuthActionRegistered = "registered"
	// GoogleAuthActionLoggedIn is returned when combined Google auth logs into an existing account.
	GoogleAuthActionLoggedIn = "logged_in"
)

// GoogleAuthSession holds Google user profile and OAuth tokens after a successful code exchange.
type GoogleAuthSession struct {
	User   *GoogleUserResult
	Tokens *GoogleOauthToken
}

// ExchangeGoogleAuthCode exchanges an OAuth authorization code for tokens and loads the Google user profile.
func ExchangeGoogleAuthCode(code, mode string, zohoInsert bool) (*GoogleAuthSession, error) {
	return ExchangeGoogleAuthCodeWithRedirect(code, mode, zohoInsert, "")
}

// ExchangeGoogleAuthCodeWithRedirect is like ExchangeGoogleAuthCode but allows overriding redirect_uri
// (used by google-backup where redirect_uri equals the frontend origin).
func ExchangeGoogleAuthCodeWithRedirect(code, mode string, zohoInsert bool, redirectURI string) (*GoogleAuthSession, error) {
	if code == "" {
		return nil, errors.New("authorization code not provided")
	}

	tokenRes, err := GetGoogleOauthTokenWithRedirect(code, mode, zohoInsert, redirectURI)
	if err != nil {
		return nil, err
	}

	googleUser, err := GetGoogleUserByAccessToken(tokenRes.Access_token)
	if err != nil {
		return nil, err
	}

	return &GoogleAuthSession{
		User:   googleUser,
		Tokens: tokenRes,
	}, nil
}

// WriteCombinedGoogleAuthSuccess writes the standard combined Google auth JSON success response.
func WriteCombinedGoogleAuthSuccess(w http.ResponseWriter, action string, extra map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	payload := map[string]interface{}{
		"success": true,
		"action":  action,
	}
	for k, v := range extra {
		if v != nil {
			payload[k] = v
		}
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteCombinedGoogleAuthError writes the standard combined Google auth JSON error response.
func WriteCombinedGoogleAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
