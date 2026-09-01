// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package mailservice_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
)

func TestVerifySMTPConfigRejectsBadHost(t *testing.T) {
	err := mailservice.VerifySMTPConfig(context.Background(), mailservice.Config{
		SMTPServerAddress: "127.0.0.1:1",
		From:              "Test <test@example.com>",
		AuthType:          "login",
		Login:             "test@example.com",
		Password:          "secret",
	})
	require.Error(t, err)
}

func TestSendTestEmailRequiresRecipient(t *testing.T) {
	err := mailservice.SendTestEmail(context.Background(), mailservice.Config{
		SMTPServerAddress: "smtp.gmail.com:587",
		From:              "Test <test@example.com>",
		AuthType:          "login",
		Login:             "test@example.com",
		Password:          "secret",
	}, "  ")
	require.Error(t, err)
}
