// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireConfiguredSMTP(t *testing.T) {
	err := requireConfiguredSMTP(nil)
	require.True(t, ErrMailNotConfigured.Has(err))

	err = requireConfiguredSMTP(&ResellerMailSettings{
		From: "Acme <noreply@acme.com>",
	})
	require.True(t, ErrMailNotConfigured.Has(err))

	err = requireConfiguredSMTP(&ResellerMailSettings{
		From:              "Acme <noreply@acme.com>",
		SMTPServerAddress: "smtp.gmail.com:587",
		AuthType:          "login",
		Login:             "noreply@acme.com",
		Password:          "secret",
	})
	require.NoError(t, err)
}

func TestResellerMailSettingsToMailConfig(t *testing.T) {
	_, ok := (*ResellerMailSettings)(nil).ToMailConfig()
	require.False(t, ok)

	_, ok = (&ResellerMailSettings{}).ToMailConfig()
	require.False(t, ok)

	cfg, ok := (&ResellerMailSettings{
		From:              "Acme <noreply@acme.com>",
		SMTPServerAddress: "smtp.gmail.com:587",
		AuthType:          "login",
		Login:             "noreply@acme.com",
		Password:          "secret",
	}).ToMailConfig()
	require.True(t, ok)
	require.Equal(t, "smtp.gmail.com:587", cfg.SMTPServerAddress)
	require.Equal(t, "login", cfg.AuthType)
}

func TestValidateResellerMailSettingsKeepsPassword(t *testing.T) {
	existing := &ResellerMailSettings{
		From:              "Acme <noreply@acme.com>",
		SMTPServerAddress: "smtp.zoho.com:587",
		AuthType:          "login",
		Login:             "noreply@acme.com",
		Password:          "old-secret",
	}

	updated, err := validateResellerMailSettings(UpdateResellerMailSettingsRequest{
		From:              "Acme <noreply@acme.com>",
		SMTPServerAddress: "smtp.zoho.com:587",
		AuthType:          "login",
		Login:             "noreply@acme.com",
		Password:          "",
	}, existing)
	require.NoError(t, err)
	require.Equal(t, "old-secret", updated.Password)
	require.True(t, updated.toView().PasswordSet)
	require.True(t, updated.toView().Configured)
}

func TestValidateResellerMailSettings(t *testing.T) {
	mail, err := validateResellerMailSettings(UpdateResellerMailSettingsRequest{
		From:              "Acme <noreply@gmail.com>",
		SMTPServerAddress: "smtp.gmail.com:587",
		AuthType:          "login",
		Login:             "noreply@gmail.com",
		Password:          "google-app-password",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "smtp.gmail.com:587", mail.SMTPServerAddress)

	_, err = validateResellerMailSettings(UpdateResellerMailSettingsRequest{
		From:              "not-an-email",
		SMTPServerAddress: "smtp.gmail.com:587",
		AuthType:          "login",
		Login:             "noreply@gmail.com",
		Password:          "x",
	}, nil)
	require.True(t, ErrValidation.Has(err))

	_, err = validateResellerMailSettings(UpdateResellerMailSettingsRequest{
		From:              "Acme <noreply@acme.com>",
		SMTPServerAddress: "smtp.gmail.com", // missing port
		AuthType:          "login",
		Login:             "noreply@acme.com",
		Password:          "x",
	}, nil)
	require.True(t, ErrValidation.Has(err))

	_, err = validateResellerMailSettings(UpdateResellerMailSettingsRequest{
		From:              "Acme <noreply@gmail.com>",
		SMTPServerAddress: "smtp.gmail.com:587",
		AuthType:          "oauth2",
		Login:             "noreply@gmail.com",
		Password:          "x",
	}, nil)
	require.True(t, ErrValidation.Has(err))

	_, err = validateResellerMailSettings(UpdateResellerMailSettingsRequest{
		From:              "Acme <noreply@acme.com>",
		SMTPServerAddress: "mail.example.com:587",
		AuthType:          "plain",
		Login:             "noreply@acme.com",
		Password:          "x",
	}, nil)
	require.True(t, ErrValidation.Has(err))
}
