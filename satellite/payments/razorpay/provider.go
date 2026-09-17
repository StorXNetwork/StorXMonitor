// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package razorpay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/StorXNetwork/StorXMonitor/satellite/payments/gateway"
)

// Provider implements gateway.Provider for Razorpay.
type Provider struct {
	client *Client
}

var _ gateway.Provider = (*Provider)(nil)

// NewProvider constructs a Razorpay gateway provider.
func NewProvider(config Config) *Provider {
	return &Provider{client: NewClient(config)}
}

// NewProviderFromClient wraps an existing client.
func NewProviderFromClient(client *Client) *Provider {
	return &Provider{client: client}
}

// Name returns the provider name.
func (p *Provider) Name() string { return "razorpay" }

// Client returns the underlying API client.
func (p *Provider) Client() *Client { return p.client }

// CreateCheckout creates a Razorpay order for Checkout.js.
func (p *Provider) CreateCheckout(ctx context.Context, req gateway.CheckoutRequest) (gateway.CheckoutSession, error) {
	if p.client == nil || !p.client.Enabled() {
		return gateway.CheckoutSession{}, Error.New("razorpay is not enabled")
	}
	orderID, err := p.client.CreateOrder(ctx, req.AmountMinor, req.Currency, req.ReceiptID, req.Notes)
	if err != nil {
		return gateway.CheckoutSession{}, err
	}
	cfg := p.client.Config()
	return gateway.CheckoutSession{
		ProviderRef: orderID,
		KeyID:       cfg.KeyID,
		OrderID:     orderID,
		AmountMinor: req.AmountMinor,
		Currency:    req.Currency,
		Description: req.Description,
	}, nil
}

// EnsureCustomer creates a Razorpay customer.
func (p *Provider) EnsureCustomer(ctx context.Context, user gateway.UserRef) (string, error) {
	return p.client.CreateCustomer(ctx, user.Name, user.Email)
}

// SaveCard fetches token details for a Checkout-created token.
func (p *Provider) SaveCard(ctx context.Context, req gateway.SaveCardRequest) (gateway.PaymentMethod, error) {
	methodID, brand, last4, expMonth, expYear, err := p.client.CreateToken(ctx, req.CustomerID, req.TokenID)
	if err != nil {
		return gateway.PaymentMethod{}, err
	}
	return gateway.PaymentMethod{
		Provider:         p.Name(),
		ProviderMethodID: methodID,
		Brand:            brand,
		Last4:            last4,
		ExpMonth:         expMonth,
		ExpYear:          expYear,
	}, nil
}

// ListCards returns nil; local DB is source of truth for saved methods.
func (p *Provider) ListCards(ctx context.Context, customerID string) ([]gateway.PaymentMethod, error) {
	return nil, nil
}

// SetDefaultCard is a no-op at provider level (local DB tracks default).
func (p *Provider) SetDefaultCard(ctx context.Context, customerID, methodID string) error {
	return nil
}

// DeleteCard deletes a customer token.
func (p *Provider) DeleteCard(ctx context.Context, customerID, methodID string) error {
	return p.client.DeleteToken(ctx, customerID, methodID)
}

// EnsureRemotePlan creates a Razorpay plan when ProviderPlanID is empty.
func (p *Provider) EnsureRemotePlan(ctx context.Context, plan gateway.LocalPlan) (string, error) {
	if plan.ProviderPlanID != "" {
		return plan.ProviderPlanID, nil
	}
	if plan.Currency == "" {
		plan.Currency = p.client.Config().Currency
		if plan.Currency == "" {
			plan.Currency = "INR"
		}
	}
	return p.client.CreatePlan(ctx, plan)
}

// CreateSubscription creates a Razorpay subscription.
func (p *Provider) CreateSubscription(ctx context.Context, req gateway.SubRequest) (gateway.Subscription, error) {
	return p.client.CreateSubscription(ctx, req)
}

// CancelSubscription cancels a Razorpay subscription.
func (p *Provider) CancelSubscription(ctx context.Context, remoteSubID string, atPeriodEnd bool) error {
	return p.client.CancelSubscription(ctx, remoteSubID, atPeriodEnd)
}

// VerifyWebhook verifies the Razorpay webhook signature.
func (p *Provider) VerifyWebhook(headers http.Header, body []byte) error {
	return p.client.VerifyWebhookSignature(body, headers.Get("X-Razorpay-Signature"))
}

// ParseWebhook normalizes Razorpay webhook events.
func (p *Provider) ParseWebhook(body []byte) (gateway.WebhookEvent, error) {
	var envelope struct {
		Event   string          `json:"event"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return gateway.WebhookEvent{}, Error.Wrap(err)
	}

	sum := sha256.Sum256(body)
	eventID := envelope.Event + ":" + hex.EncodeToString(sum[:8])
	ev := gateway.WebhookEvent{
		ProviderEventID: eventID,
		RawPayload:      body,
		Notes:           map[string]string{},
	}

	switch envelope.Event {
	case "payment.captured":
		ev.Type = gateway.WebhookPaymentCaptured
		var payload struct {
			Payment struct {
				Entity struct {
					ID       string            `json:"id"`
					OrderID  string            `json:"order_id"`
					Amount   int64             `json:"amount"`
					Currency string            `json:"currency"`
					Status   string            `json:"status"`
					Notes    map[string]string `json:"notes"`
				} `json:"entity"`
			} `json:"payment"`
		}
		_ = json.Unmarshal(envelope.Payload, &payload)
		ev.ProviderRef = payload.Payment.Entity.OrderID
		ev.PaymentRef = payload.Payment.Entity.ID
		ev.AmountMinor = payload.Payment.Entity.Amount
		ev.Currency = payload.Payment.Entity.Currency
		ev.Status = payload.Payment.Entity.Status
		ev.Notes = payload.Payment.Entity.Notes
		if payload.Payment.Entity.ID != "" {
			ev.ProviderEventID = envelope.Event + ":" + payload.Payment.Entity.ID
		}
	case "order.paid":
		ev.Type = gateway.WebhookOrderPaid
		var payload struct {
			Order struct {
				Entity struct {
					ID       string            `json:"id"`
					Amount   int64             `json:"amount"`
					Currency string            `json:"currency"`
					Notes    map[string]string `json:"notes"`
				} `json:"entity"`
			} `json:"order"`
		}
		_ = json.Unmarshal(envelope.Payload, &payload)
		ev.ProviderRef = payload.Order.Entity.ID
		ev.AmountMinor = payload.Order.Entity.Amount
		ev.Currency = payload.Order.Entity.Currency
		ev.Notes = payload.Order.Entity.Notes
		if payload.Order.Entity.ID != "" {
			ev.ProviderEventID = envelope.Event + ":" + payload.Order.Entity.ID
		}
	case "payment.failed":
		ev.Type = gateway.WebhookPaymentFailed
		var payload struct {
			Payment struct {
				Entity struct {
					ID      string `json:"id"`
					OrderID string `json:"order_id"`
				} `json:"entity"`
			} `json:"payment"`
		}
		_ = json.Unmarshal(envelope.Payload, &payload)
		ev.ProviderRef = payload.Payment.Entity.OrderID
		ev.PaymentRef = payload.Payment.Entity.ID
		if payload.Payment.Entity.ID != "" {
			ev.ProviderEventID = envelope.Event + ":" + payload.Payment.Entity.ID
		}
	case "subscription.activated":
		ev.Type = gateway.WebhookSubscriptionActivated
		fillSubscriptionEvent(&ev, envelope.Event, envelope.Payload)
	case "subscription.charged":
		ev.Type = gateway.WebhookSubscriptionCharged
		fillSubscriptionEvent(&ev, envelope.Event, envelope.Payload)
	case "subscription.cancelled":
		ev.Type = gateway.WebhookSubscriptionCancelled
		fillSubscriptionEvent(&ev, envelope.Event, envelope.Payload)
	case "subscription.completed":
		ev.Type = gateway.WebhookSubscriptionCompleted
		fillSubscriptionEvent(&ev, envelope.Event, envelope.Payload)
	default:
		ev.Type = gateway.WebhookUnknown
	}
	if ev.Notes == nil {
		ev.Notes = map[string]string{}
	}
	return ev, nil
}

func fillSubscriptionEvent(ev *gateway.WebhookEvent, eventName string, payload json.RawMessage) {
	var body struct {
		Subscription struct {
			Entity struct {
				ID     string            `json:"id"`
				Status string            `json:"status"`
				Notes  map[string]string `json:"notes"`
			} `json:"entity"`
		} `json:"subscription"`
		Payment struct {
			Entity struct {
				ID     string `json:"id"`
				Amount int64  `json:"amount"`
			} `json:"entity"`
		} `json:"payment"`
	}
	_ = json.Unmarshal(payload, &body)
	ev.ProviderRef = body.Subscription.Entity.ID
	ev.Status = body.Subscription.Entity.Status
	ev.Notes = body.Subscription.Entity.Notes
	ev.PaymentRef = body.Payment.Entity.ID
	ev.AmountMinor = body.Payment.Entity.Amount
	ev.ProviderEventID = eventName + ":" + body.Subscription.Entity.ID
	if body.Payment.Entity.ID != "" {
		ev.ProviderEventID = eventName + ":" + body.Payment.Entity.ID
	}
}
