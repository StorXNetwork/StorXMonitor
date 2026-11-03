// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/StorXNetwork/common/uuid"
)

// Provider is implemented by payment gateways (Razorpay, future adapters).
type Provider interface {
	Name() string

	CreateCheckout(ctx context.Context, req CheckoutRequest) (CheckoutSession, error)

	EnsureCustomer(ctx context.Context, user UserRef) (customerID string, err error)
	SaveCard(ctx context.Context, req SaveCardRequest) (PaymentMethod, error)
	ListCards(ctx context.Context, customerID string) ([]PaymentMethod, error)
	SetDefaultCard(ctx context.Context, customerID, methodID string) error
	DeleteCard(ctx context.Context, customerID, methodID string) error

	EnsureRemotePlan(ctx context.Context, plan LocalPlan) (remotePlanID string, err error)
	CreateSubscription(ctx context.Context, req SubRequest) (Subscription, error)
	CancelSubscription(ctx context.Context, remoteSubID string, atPeriodEnd bool) error

	VerifyWebhook(headers http.Header, body []byte) error
	ParseWebhook(body []byte) (WebhookEvent, error)
}

// UserRef identifies a satellite user for provider customer mapping.
type UserRef struct {
	ID    uuid.UUID
	Email string
	Name  string
}

// CheckoutRequest is a one-time plan payment request to a provider.
type CheckoutRequest struct {
	AmountMinor int64
	Currency    string
	Description string
	ReceiptID   string
	CustomerID  string
	Notes       map[string]string
}

// CheckoutSession is returned to the frontend for Razorpay Checkout.js.
type CheckoutSession struct {
	ProviderRef string
	KeyID       string
	OrderID     string
	AmountMinor int64
	Currency    string
	Name        string
	Description string
	Prefill     CheckoutPrefill
}

// CheckoutPrefill is customer prefill for Checkout.js.
type CheckoutPrefill struct {
	Name  string
	Email string
}

// SaveCardRequest saves a tokenized card on a provider customer.
type SaveCardRequest struct {
	CustomerID string
	TokenID    string
}

// PaymentMethod is a saved card (local + provider view).
type PaymentMethod struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	Provider         string
	ProviderMethodID string
	Brand            string
	Last4            string
	ExpMonth         int
	ExpYear          int
	IsDefault        bool
	CreatedAt        time.Time
}

// LocalPlan is the catalog plan fields needed to sync a remote subscription plan.
type LocalPlan struct {
	ID             int64
	Name           string
	Price          float64
	Currency       string
	Validity       int64
	ValidityUnit   string
	ProviderPlanID string
}

// SubRequest creates a provider subscription.
type SubRequest struct {
	RemotePlanID   string
	CustomerID     string
	PaymentMethod  string
	TotalCount     int
	Notes          map[string]string
}

// Subscription is a provider subscription snapshot.
type Subscription struct {
	ProviderSubID  string
	ProviderPlanID string
	Status         string
	PeriodEnd      time.Time
}

// WebhookEventType classifies parsed webhook events.
type WebhookEventType string

const (
	WebhookPaymentCaptured      WebhookEventType = "payment_captured"
	WebhookOrderPaid            WebhookEventType = "order_paid"
	WebhookPaymentFailed        WebhookEventType = "payment_failed"
	WebhookSubscriptionActivated WebhookEventType = "subscription_activated"
	WebhookSubscriptionCharged  WebhookEventType = "subscription_charged"
	WebhookSubscriptionCancelled WebhookEventType = "subscription_cancelled"
	WebhookSubscriptionCompleted WebhookEventType = "subscription_completed"
	WebhookUnknown              WebhookEventType = "unknown"
)

// WebhookEvent is a normalized provider webhook.
type WebhookEvent struct {
	Type            WebhookEventType
	ProviderEventID string
	ProviderRef     string // order id, payment link id, or subscription id
	PaymentRef      string
	AmountMinor     int64
	Currency        string
	Status          string
	Notes           map[string]string
	RawPayload      []byte
}
