// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package razorpay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/payments/gateway"
)

func TestAmountToMinorUnits(t *testing.T) {
	amount, err := AmountToMinorUnits(99.99)
	require.NoError(t, err)
	require.Equal(t, int64(9999), amount)

	_, err = AmountToMinorUnits(-1)
	require.Error(t, err)
}

func TestVerifyWebhookSignature(t *testing.T) {
	client := NewClient(Config{
		Enabled:       true,
		KeyID:         "key",
		KeySecret:     "secret",
		WebhookSecret: "whsec",
	})
	body := []byte(`{"event":"payment.captured"}`)
	mac := hmac.New(sha256.New, []byte("whsec"))
	_, _ = mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	require.NoError(t, client.VerifyWebhookSignature(body, sig))
	require.Error(t, client.VerifyWebhookSignature(body, "bad"))
}

func TestParseWebhookPaymentCaptured(t *testing.T) {
	p := NewProvider(Config{Enabled: true, KeyID: "k", KeySecret: "s", WebhookSecret: "w"})
	body := []byte(`{
		"event":"payment.captured",
		"payload":{
			"payment":{
				"entity":{
					"id":"pay_123",
					"order_id":"order_456",
					"amount":50000,
					"currency":"INR",
					"status":"captured",
					"notes":{"attempt_id":"aid","plan_id":"1"}
				}
			}
		}
	}`)
	ev, err := p.ParseWebhook(body)
	require.NoError(t, err)
	require.Equal(t, gateway.WebhookPaymentCaptured, ev.Type)
	require.Equal(t, "order_456", ev.ProviderRef)
	require.Equal(t, "pay_123", ev.PaymentRef)
	require.Equal(t, int64(50000), ev.AmountMinor)
	require.Equal(t, "payment.captured:pay_123", ev.ProviderEventID)
}

func TestParseWebhookUnknown(t *testing.T) {
	p := NewProvider(Config{Enabled: true, KeyID: "k", KeySecret: "s"})
	ev, err := p.ParseWebhook([]byte(`{"event":"something.else","payload":{}}`))
	require.NoError(t, err)
	require.Equal(t, gateway.WebhookUnknown, ev.Type)
}
