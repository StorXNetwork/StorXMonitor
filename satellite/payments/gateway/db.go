// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

import (
	"context"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

// Error is the gateway package error class.
var Error = errs.Class("payment gateway")

var (
	// ErrNotFound is returned when a gateway record is missing.
	ErrNotFound = Error.New("not found")
	// ErrConflict is returned for duplicate or illegal state transitions.
	ErrConflict = Error.New("conflict")
	// ErrProviderDisabled is returned when the selected provider is not enabled.
	ErrProviderDisabled = Error.New("provider disabled")
	// ErrActiveSubscription is returned when the user already has an active subscription.
	ErrActiveSubscription = Error.New("active subscription exists")
	// ErrDefaultCardRequired is returned when autopay needs a default card.
	ErrDefaultCardRequired = Error.New("default card required")
	// ErrCannotDeleteDefault is returned when deleting the default card would break an active sub.
	ErrCannotDeleteDefault = Error.New("cannot delete default card with active subscription")
)

// AttemptStatus is the status of a one-time payment attempt.
type AttemptStatus string

const (
	AttemptPending AttemptStatus = "pending"
	AttemptPaid    AttemptStatus = "paid"
	AttemptFailed  AttemptStatus = "failed"
	AttemptExpired AttemptStatus = "expired"
)

// SubscriptionStatus is the local subscription status.
type SubscriptionStatus string

const (
	SubCreated   SubscriptionStatus = "created"
	SubActive    SubscriptionStatus = "active"
	SubPastDue   SubscriptionStatus = "past_due"
	SubCancelled SubscriptionStatus = "cancelled"
	SubExpired   SubscriptionStatus = "expired"
)

// Customer maps a user to a provider customer id.
type Customer struct {
	UserID             uuid.UUID
	Provider           string
	ProviderCustomerID string
	CreatedAt          time.Time
}

// Attempt is a one-time checkout attempt.
type Attempt struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	PlanID      int64
	Provider    string
	ProviderRef string
	AmountMinor int64
	Currency    string
	Status      AttemptStatus
	CouponCode  *string
	Metadata    []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// LocalSubscription is a stored autopay subscription.
type LocalSubscription struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	PlanID            int64
	Provider          string
	ProviderSubID     string
	ProviderPlanID    string
	Status            SubscriptionStatus
	CurrentPeriodEnd  *time.Time
	CancelAtPeriodEnd bool
	DefaultMethodID   *uuid.UUID
	CouponCode        *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Event is a stored webhook event for idempotency.
type Event struct {
	ID              uuid.UUID
	Provider        string
	ProviderEventID string
	EventType       string
	Payload         []byte
	AttemptID       *uuid.UUID
	SubscriptionID  *uuid.UUID
	ReceivedAt      time.Time
}

// DB is the payment gateway database facade.
//
// architecture: Database
type DB interface {
	Customers() CustomersDB
	Methods() MethodsDB
	Attempts() AttemptsDB
	Subscriptions() SubscriptionsDB
	Events() EventsDB
}

// CustomersDB stores provider customer mappings.
type CustomersDB interface {
	Upsert(ctx context.Context, customer Customer) error
	GetByUserID(ctx context.Context, userID uuid.UUID, provider string) (*Customer, error)
	GetByProviderCustomerID(ctx context.Context, provider, providerCustomerID string) (*Customer, error)
}

// MethodsDB stores saved payment methods.
type MethodsDB interface {
	Insert(ctx context.Context, method PaymentMethod) (*PaymentMethod, error)
	ListByUserID(ctx context.Context, userID uuid.UUID, provider string) ([]PaymentMethod, error)
	GetByID(ctx context.Context, id uuid.UUID) (*PaymentMethod, error)
	GetByProviderMethodID(ctx context.Context, provider, providerMethodID string) (*PaymentMethod, error)
	SetDefault(ctx context.Context, userID uuid.UUID, provider string, methodID uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetDefault(ctx context.Context, userID uuid.UUID, provider string) (*PaymentMethod, error)
}

// AttemptsDB stores one-time checkout attempts.
type AttemptsDB interface {
	Insert(ctx context.Context, attempt Attempt) (*Attempt, error)
	UpdateProviderRef(ctx context.Context, id uuid.UUID, providerRef string) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status AttemptStatus) error
	GetByID(ctx context.Context, id uuid.UUID) (*Attempt, error)
	GetByProviderRef(ctx context.Context, provider, providerRef string) (*Attempt, error)
}

// SubscriptionsDB stores autopay subscriptions.
type SubscriptionsDB interface {
	Insert(ctx context.Context, sub LocalSubscription) (*LocalSubscription, error)
	Update(ctx context.Context, sub LocalSubscription) error
	GetByID(ctx context.Context, id uuid.UUID) (*LocalSubscription, error)
	GetByProviderSubID(ctx context.Context, provider, providerSubID string) (*LocalSubscription, error)
	GetActiveByUserID(ctx context.Context, userID uuid.UUID, provider string) (*LocalSubscription, error)
}

// EventsDB stores webhook events for idempotency.
type EventsDB interface {
	// Insert returns ErrConflict if (provider, provider_event_id) already exists.
	Insert(ctx context.Context, event Event) error
	Exists(ctx context.Context, provider, providerEventID string) (bool, error)
}
