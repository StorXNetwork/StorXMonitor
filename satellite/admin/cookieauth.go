// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"net/http"
	"time"
)

// CookieSettings defines cookie settings for admin authentication.
type CookieSettings struct {
	Name string
	Path string
}

// CookieAuth handles cookie authorization for admin.
type CookieAuth struct {
	settings CookieSettings
	domain   string
}

// AdminTokenInfo contains token information for admin authentication.
type AdminTokenInfo struct {
	Token     string
	ExpiresAt time.Time
}

// NewCookieAuth create new cookie authorization with provided settings.
func NewCookieAuth(settings CookieSettings, domain string) *CookieAuth {
	return &CookieAuth{
		settings: settings,
		domain:   domain,
	}
}

// GetToken retrieves token from request.
func (auth *CookieAuth) GetToken(r *http.Request) (AdminTokenInfo, error) {
	cookie, err := r.Cookie(auth.settings.Name)
	if err != nil {
		return AdminTokenInfo{}, err
	}

	return AdminTokenInfo{
		Token:     cookie.Value,
		ExpiresAt: cookie.Expires,
	}, nil
}

// SetTokenCookie sets parametrized token cookie that is not accessible from js.
func (auth *CookieAuth) SetTokenCookie(w http.ResponseWriter, tokenInfo AdminTokenInfo) {
	http.SetCookie(w, &http.Cookie{
		Domain:   auth.domain,
		Name:     auth.settings.Name,
		Value:    tokenInfo.Token,
		Path:     auth.settings.Path,
		Expires:  tokenInfo.ExpiresAt,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

// RemoveTokenCookie removes auth cookie that is not accessible from js.
func (auth *CookieAuth) RemoveTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Domain:   auth.domain,
		Name:     auth.settings.Name,
		Value:    "",
		Path:     auth.settings.Path,
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

// GetTokenCookieName returns the name of the cookie storing the token.
func (auth *CookieAuth) GetTokenCookieName() string {
	return auth.settings.Name
}
