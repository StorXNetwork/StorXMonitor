// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
)

func TestMicrosoftAdminConsentState(t *testing.T) {
	newService := func(secret string) *Service {
		return &Service{tokens: consoleauth.NewService(consoleauth.Config{}, &consoleauth.Hmac{Secret: []byte(secret)})}
	}
	s := newService("secret")
	now := time.Now()

	state := microsoftAdminConsentState{
		Purpose:      microsoftAdminConsentStatePurpose,
		UserID:       "user-1",
		CredentialID: "credential-1",
		TenantID:     "tenant-1",
		ClientID:     "client-1",
		ExpiresAt:    now.Add(microsoftAdminConsentStateTTL).Unix(),
		Nonce:        "nonce",
	}

	t.Run("round trip", func(t *testing.T) {
		raw, err := s.signMicrosoftAdminConsentState(state)
		require.NoError(t, err)

		got, err := s.verifyMicrosoftAdminConsentState(raw, now)
		require.NoError(t, err)
		require.Equal(t, state, got)
	})

	t.Run("signed with another secret", func(t *testing.T) {
		raw, err := newService("other").signMicrosoftAdminConsentState(state)
		require.NoError(t, err)

		_, err = s.verifyMicrosoftAdminConsentState(raw, now)
		require.True(t, ErrValidation.Has(err))
	})

	t.Run("expired", func(t *testing.T) {
		raw, err := s.signMicrosoftAdminConsentState(state)
		require.NoError(t, err)

		_, err = s.verifyMicrosoftAdminConsentState(raw, now.Add(microsoftAdminConsentStateTTL+time.Minute))
		require.True(t, ErrValidation.Has(err))
	})

	t.Run("wrong purpose", func(t *testing.T) {
		other := state
		other.Purpose = "something_else"
		raw, err := s.signMicrosoftAdminConsentState(other)
		require.NoError(t, err)

		_, err = s.verifyMicrosoftAdminConsentState(raw, now)
		require.True(t, ErrValidation.Has(err))
	})

	t.Run("garbage", func(t *testing.T) {
		_, err := s.verifyMicrosoftAdminConsentState("not-a-token", now)
		require.True(t, ErrValidation.Has(err))

		_, err = s.verifyMicrosoftAdminConsentState("", now)
		require.True(t, ErrValidation.Has(err))
	})
}
