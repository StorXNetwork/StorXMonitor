// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package socialmedia

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveRequestOrigin(t *testing.T) {
	SetGoogleBackupOAuthRedirectURL("http://localhost:3000")
	SetClientOrigin("http://localhost:3000")

	t.Run("Host with port", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://localhost:3000/api/v0/auth/google-backup", nil)
		r.Host = "localhost:3000"
		require.Equal(t, "http://localhost:3000", ResolveRequestOrigin(r))
	})

	t.Run("X-Forwarded-Host and Proto", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://backend/api/v0/auth/google-backup", nil)
		r.Header.Set("X-Forwarded-Host", "cyberls.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		require.Equal(t, "https://cyberls.com", ResolveRequestOrigin(r))
	})

	t.Run("reseller custom domain", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://backend/api/v0/google-backup/connect", nil)
		r.Header.Set("X-Forwarded-Host", "portal.acme.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		require.Equal(t, "https://portal.acme.com", ResolveRequestOrigin(r))
	})

	t.Run("loopback API host uses config fallback", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://localhost:10002/api/v0/google-backup/connect", nil)
		r.Host = "localhost:10002"
		require.Equal(t, "http://localhost:3000", ResolveRequestOrigin(r))
	})

	t.Run("ignores Origin header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://backend/api/v0/auth/google-backup", nil)
		r.Header.Set("Origin", "https://other.example.com")
		r.Header.Set("X-Forwarded-Host", "cyberls.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		require.Equal(t, "https://cyberls.com", ResolveRequestOrigin(r))
	})
}
