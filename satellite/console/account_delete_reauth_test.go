// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestVerifyAccountDeleteReauth(t *testing.T) {
	s := &Service{log: zap.NewNop()}

	tests := []struct {
		name    string
		user    *User
		req     AccountDeleteRequest
		wantErr string
	}{
		{
			name: "no mfa no factors session enough",
			user: &User{Email: "a@example.com", MFAEnabled: false},
			req:  AccountDeleteRequest{},
		},
		{
			name:    "mfa enabled requires factor",
			user:    &User{Email: "a@example.com", MFAEnabled: true},
			req:     AccountDeleteRequest{},
			wantErr: "mfa or google re-authentication required",
		},
		{
			name: "google reauth alone ok when mfa enabled",
			user: &User{Email: "a@example.com", MFAEnabled: true},
			req:  AccountDeleteRequest{GoogleReauthEmail: "a@example.com"},
		},
		{
			name: "google reauth alone ok when mfa disabled",
			user: &User{Email: "a@example.com", MFAEnabled: false},
			req:  AccountDeleteRequest{GoogleReauthEmail: "a@example.com"},
		},
		{
			name: "google reauth case insensitive",
			user: &User{Email: "A@Example.com", MFAEnabled: true},
			req:  AccountDeleteRequest{GoogleReauthEmail: "a@example.com"},
		},
		{
			name:    "google reauth email mismatch",
			user:    &User{Email: "a@example.com", MFAEnabled: true},
			req:     AccountDeleteRequest{GoogleReauthEmail: "other@example.com"},
			wantErr: "google account does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.verifyAccountDeleteReauth(t.Context(), tt.user, tt.req)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
