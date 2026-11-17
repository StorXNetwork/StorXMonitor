// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserForAuditFromLookup(t *testing.T) {
	verified := &User{Email: "verified@example.com", Status: Active}
	unverifiedActive := User{Email: "pending@example.com", Status: PendingBotVerification}
	unverifiedOther := User{Email: "other@example.com", Status: Inactive}

	tests := []struct {
		name       string
		verified   *User
		unverified []User
		wantEmail  string
	}{
		{
			name:      "prefers verified user",
			verified:  verified,
			wantEmail: "verified@example.com",
		},
		{
			name:       "uses pending bot verification account",
			unverified: []User{unverifiedOther, unverifiedActive},
			wantEmail:  "pending@example.com",
		},
		{
			name:       "falls back to first unverified user",
			unverified: []User{unverifiedOther},
			wantEmail:  "other@example.com",
		},
		{
			name: "returns nil when no users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := userForAuditFromLookup(tt.verified, tt.unverified)
			if tt.wantEmail == "" {
				require.Nil(t, user)
				return
			}
			require.NotNil(t, user)
			require.Equal(t, tt.wantEmail, user.Email)
		})
	}
}

func TestUserAuditOutcome(t *testing.T) {
	tests := []struct {
		name            string
		successMessage  string
		err             error
		wantMessage     string
		wantStatusLabel string
	}{
		{
			name:            "success",
			successMessage:  "User logged in",
			wantMessage:     "User logged in",
			wantStatusLabel: "success",
		},
		{
			name:            "failed login",
			successMessage:  "User logged in",
			err:             ErrLoginCredentials.New("incorrect credentials"),
			wantMessage:     "login credentials: incorrect credentials",
			wantStatusLabel: "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, status := userAuditOutcome(tt.successMessage, tt.err)
			require.Equal(t, tt.wantMessage, message)
			require.Equal(t, tt.wantStatusLabel, string(status))
		})
	}
}

func TestNormalizeAuditIP(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "ipv4 with port", raw: "203.0.113.10:57217", want: "203.0.113.10"},
		{name: "ipv4 bare", raw: "203.0.113.10", want: "203.0.113.10"},
		{name: "ipv6 loopback with port", raw: "[::1]:58807", want: "::1"},
		{name: "ipv6 loopback brackets", raw: "[::1]", want: "::1"},
		{name: "ipv6 full with port", raw: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "whitespace", raw: "  127.0.0.1:8080  ", want: "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, normalizeAuditIP(tt.raw))
		})
	}
}

func TestPreferRoutableAuditIP(t *testing.T) {
	lan := primaryLANIPv4()
	require.NotEmpty(t, lan)

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty uses lan", raw: "", want: lan},
		{name: "ipv6 loopback uses lan", raw: "[::1]:58807", want: lan},
		{name: "ipv4 loopback uses lan", raw: "127.0.0.1:9", want: lan},
		{name: "keeps public", raw: "203.0.113.10:443", want: "203.0.113.10"},
		{name: "keeps lan peer", raw: "192.168.1.50", want: "192.168.1.50"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, preferRoutableAuditIP(tt.raw))
		})
	}
}
