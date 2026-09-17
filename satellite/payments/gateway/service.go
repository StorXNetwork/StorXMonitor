// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/billing"
	"github.com/StorXNetwork/common/uuid"
)

var mon = monkit.Package()

// ServiceDependencies consolidates dependencies for the gateway service.
type ServiceDependencies struct {
	DB       DB
	Billing  billing.TransactionsDB
	Users    console.Users
	Projects console.Projects
	Mail     *mailservice.Service
}

// Service orchestrates provider-agnostic payment flows.
type Service struct {
	log             *zap.Logger
	config          Config
	deps            ServiceDependencies
	providers       map[string]Provider
	defaultProvider string
	currency        string
}

// NewService constructs a gateway service.
func NewService(log *zap.Logger, config Config, deps ServiceDependencies, currency string, providers ...Provider) *Service {
	m := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if p != nil {
			m[p.Name()] = p
		}
	}
	def := config.DefaultProvider
	if def == "" {
		def = "razorpay"
	}
	if currency == "" {
		currency = "INR"
	}
	return &Service{
		log:             log,
		config:          config,
		deps:            deps,
		providers:       m,
		defaultProvider: def,
		currency:        currency,
	}
}

func (s *Service) provider(name string) (Provider, error) {
	if name == "" {
		name = s.defaultProvider
	}
	p, ok := s.providers[name]
	if !ok || p == nil {
		return nil, ErrProviderDisabled
	}
	enabled := false
	for _, n := range strings.Split(s.config.EnabledProviders, ",") {
		if strings.TrimSpace(n) == name {
			enabled = true
			break
		}
	}
	if strings.TrimSpace(s.config.EnabledProviders) == "" {
		enabled = name == s.defaultProvider
	}
	if !enabled {
		return nil, ErrProviderDisabled
	}
	return p, nil
}

// CreateCheckoutRequest is the API input for one-time checkout.
type CreateCheckoutRequest struct {
	UserID     uuid.UUID
	UserEmail  string
	UserName   string
	PlanID     int64
	CouponCode string
	Provider   string
}

// CreateCheckout creates a pending attempt and provider checkout session.
func (s *Service) CreateCheckout(ctx context.Context, req CreateCheckoutRequest) (session CheckoutSession, attemptID uuid.UUID, paid bool, err error) {
	defer mon.Task()(&ctx)(&err)

	prov, err := s.provider(req.Provider)
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, err
	}

	plan, err := s.deps.Billing.GetPaymentPlansByID(ctx, req.PlanID)
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
	}

	price := plan.Price
	var couponCode *string
	if req.CouponCode != "" {
		coupon, err := s.deps.Billing.GetCouponByCode(ctx, req.CouponCode)
		if err != nil {
			return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
		}
		price, err = ApplyCoupon(price, coupon.Discount, coupon.MaxDiscount, coupon.MinOrderAmount, coupon.DiscountType, coupon.ValidFrom, coupon.ValidTo, time.Now().UTC())
		if err != nil {
			return CheckoutSession{}, uuid.UUID{}, false, err
		}
		couponCode = &req.CouponCode
	}

	amountMinor, err := AmountToMinorUnits(price)
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, err
	}

	attemptID, err = uuid.New()
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
	}

	// Zero after coupon: complete immediately.
	if amountMinor == 0 {
		attempt, err := s.deps.DB.Attempts().Insert(ctx, Attempt{
			ID:          attemptID,
			UserID:      req.UserID,
			PlanID:      plan.ID,
			Provider:    prov.Name(),
			ProviderRef: "coupon-" + attemptID.String(),
			AmountMinor: 0,
			Currency:    s.currency,
			Status:      AttemptPaid,
			CouponCode:  couponCode,
		})
		if err != nil {
			return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
		}
		if err := s.CompletePayment(ctx, attempt, "coupon", "Plan upgrade (coupon covered)"); err != nil {
			return CheckoutSession{}, uuid.UUID{}, false, err
		}
		return CheckoutSession{OrderID: attempt.ProviderRef, AmountMinor: 0, Currency: s.currency}, attemptID, true, nil
	}

	customerID, err := s.ensureLocalCustomer(ctx, prov, UserRef{ID: req.UserID, Email: req.UserEmail, Name: req.UserName})
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, err
	}

	tempRef := "pending-" + attemptID.String()
	attempt, err := s.deps.DB.Attempts().Insert(ctx, Attempt{
		ID:          attemptID,
		UserID:      req.UserID,
		PlanID:      plan.ID,
		Provider:    prov.Name(),
		ProviderRef: tempRef,
		AmountMinor: amountMinor,
		Currency:    s.currency,
		Status:      AttemptPending,
		CouponCode:  couponCode,
	})
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
	}

	session, err = prov.CreateCheckout(ctx, CheckoutRequest{
		AmountMinor: amountMinor,
		Currency:    s.currency,
		Description: "StorX plan: " + plan.Name,
		ReceiptID:   attemptID.String(),
		CustomerID:  customerID,
		Notes: map[string]string{
			"user_id":    req.UserID.String(),
			"plan_id":    strconv.FormatInt(plan.ID, 10),
			"attempt_id": attemptID.String(),
		},
	})
	if err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
	}
	session.Prefill = CheckoutPrefill{Name: req.UserName, Email: req.UserEmail}
	session.Name = plan.Name

	if err := s.deps.DB.Attempts().UpdateProviderRef(ctx, attempt.ID, session.ProviderRef); err != nil {
		return CheckoutSession{}, uuid.UUID{}, false, Error.Wrap(err)
	}
	return session, attemptID, false, nil
}

func (s *Service) ensureLocalCustomer(ctx context.Context, prov Provider, user UserRef) (string, error) {
	existing, err := s.deps.DB.Customers().GetByUserID(ctx, user.ID, prov.Name())
	if err == nil {
		return existing.ProviderCustomerID, nil
	}
	if err != ErrNotFound {
		return "", Error.Wrap(err)
	}
	customerID, err := prov.EnsureCustomer(ctx, user)
	if err != nil {
		return "", Error.Wrap(err)
	}
	if err := s.deps.DB.Customers().Upsert(ctx, Customer{
		UserID:             user.ID,
		Provider:           prov.Name(),
		ProviderCustomerID: customerID,
	}); err != nil {
		return "", Error.Wrap(err)
	}
	return customerID, nil
}

// ListMethods lists saved cards for a user.
func (s *Service) ListMethods(ctx context.Context, userID uuid.UUID, providerName string) ([]PaymentMethod, error) {
	prov, err := s.provider(providerName)
	if err != nil {
		return nil, err
	}
	return s.deps.DB.Methods().ListByUserID(ctx, userID, prov.Name())
}

// SaveMethodRequest saves a tokenized card.
type SaveMethodRequest struct {
	UserID     uuid.UUID
	UserEmail  string
	UserName   string
	Provider   string
	TokenID    string
	Brand      string
	Last4      string
	ExpMonth   int
	ExpYear    int
	MakeDefault bool
}

// SaveMethod persists a saved card locally and on the provider.
func (s *Service) SaveMethod(ctx context.Context, req SaveMethodRequest) (*PaymentMethod, error) {
	prov, err := s.provider(req.Provider)
	if err != nil {
		return nil, err
	}
	customerID, err := s.ensureLocalCustomer(ctx, prov, UserRef{ID: req.UserID, Email: req.UserEmail, Name: req.UserName})
	if err != nil {
		return nil, err
	}
	saved, err := prov.SaveCard(ctx, SaveCardRequest{CustomerID: customerID, TokenID: req.TokenID})
	if err != nil {
		return nil, Error.Wrap(err)
	}
	existing, _ := s.deps.DB.Methods().ListByUserID(ctx, req.UserID, prov.Name())
	isDefault := req.MakeDefault || len(existing) == 0
	method, err := s.deps.DB.Methods().Insert(ctx, PaymentMethod{
		UserID:           req.UserID,
		Provider:         prov.Name(),
		ProviderMethodID: saved.ProviderMethodID,
		Brand:            firstNonEmpty(req.Brand, saved.Brand),
		Last4:            firstNonEmpty(req.Last4, saved.Last4),
		ExpMonth:         pickInt(req.ExpMonth, saved.ExpMonth),
		ExpYear:          pickInt(req.ExpYear, saved.ExpYear),
		IsDefault:        isDefault,
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if isDefault {
		_ = s.deps.DB.Methods().SetDefault(ctx, req.UserID, prov.Name(), method.ID)
		method.IsDefault = true
	}
	return method, nil
}

// SetDefaultMethod marks a card as default.
func (s *Service) SetDefaultMethod(ctx context.Context, userID, methodID uuid.UUID, providerName string) error {
	prov, err := s.provider(providerName)
	if err != nil {
		return err
	}
	method, err := s.deps.DB.Methods().GetByID(ctx, methodID)
	if err != nil {
		return err
	}
	if method.UserID != userID || method.Provider != prov.Name() {
		return ErrNotFound
	}
	customer, err := s.deps.DB.Customers().GetByUserID(ctx, userID, prov.Name())
	if err != nil {
		return err
	}
	if err := prov.SetDefaultCard(ctx, customer.ProviderCustomerID, method.ProviderMethodID); err != nil {
		return Error.Wrap(err)
	}
	return s.deps.DB.Methods().SetDefault(ctx, userID, prov.Name(), methodID)
}

// DeleteMethod deletes a saved card.
func (s *Service) DeleteMethod(ctx context.Context, userID, methodID uuid.UUID, providerName string) error {
	prov, err := s.provider(providerName)
	if err != nil {
		return err
	}
	method, err := s.deps.DB.Methods().GetByID(ctx, methodID)
	if err != nil {
		return err
	}
	if method.UserID != userID || method.Provider != prov.Name() {
		return ErrNotFound
	}
	if method.IsDefault {
		if _, err := s.deps.DB.Subscriptions().GetActiveByUserID(ctx, userID, prov.Name()); err == nil {
			return ErrCannotDeleteDefault
		}
	}
	customer, err := s.deps.DB.Customers().GetByUserID(ctx, userID, prov.Name())
	if err != nil {
		return err
	}
	if err := prov.DeleteCard(ctx, customer.ProviderCustomerID, method.ProviderMethodID); err != nil {
		s.log.Warn("provider delete card failed", zap.Error(err))
	}
	return s.deps.DB.Methods().Delete(ctx, methodID)
}

// CreateSubscriptionRequest starts autopay.
type CreateSubscriptionRequest struct {
	UserID     uuid.UUID
	UserEmail  string
	UserName   string
	PlanID     int64
	CouponCode string
	Provider   string
}

// CreateSubscription starts an autopay subscription for the user.
func (s *Service) CreateSubscription(ctx context.Context, req CreateSubscriptionRequest) (*LocalSubscription, error) {
	prov, err := s.provider(req.Provider)
	if err != nil {
		return nil, err
	}
	if _, err := s.deps.DB.Subscriptions().GetActiveByUserID(ctx, req.UserID, prov.Name()); err == nil {
		return nil, ErrActiveSubscription
	} else if err != ErrNotFound {
		return nil, err
	}

	plan, err := s.deps.Billing.GetPaymentPlansByID(ctx, req.PlanID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	defaultMethod, err := s.deps.DB.Methods().GetDefault(ctx, req.UserID, prov.Name())
	if err != nil {
		return nil, ErrDefaultCardRequired
	}

	customerID, err := s.ensureLocalCustomer(ctx, prov, UserRef{ID: req.UserID, Email: req.UserEmail, Name: req.UserName})
	if err != nil {
		return nil, err
	}

	remotePlanID := ""
	if plan.ProviderPlanIDs != nil {
		remotePlanID = plan.ProviderPlanIDs[prov.Name()]
	}
	localPlan := LocalPlan{
		ID: plan.ID, Name: plan.Name, Price: plan.Price, Currency: s.currency,
		Validity: plan.Validity, ValidityUnit: plan.ValidityUnit, ProviderPlanID: remotePlanID,
	}
	if remotePlanID == "" {
		remotePlanID, err = prov.EnsureRemotePlan(ctx, localPlan)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		_ = s.persistProviderPlanID(ctx, plan, prov.Name(), remotePlanID)
	}

	var couponCode *string
	if req.CouponCode != "" {
		couponCode = &req.CouponCode
	}

	remoteSub, err := prov.CreateSubscription(ctx, SubRequest{
		RemotePlanID:  remotePlanID,
		CustomerID:    customerID,
		PaymentMethod: defaultMethod.ProviderMethodID,
		TotalCount:    0,
		Notes: map[string]string{
			"user_id": req.UserID.String(),
			"plan_id": strconv.FormatInt(plan.ID, 10),
		},
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	status := SubCreated
	if remoteSub.Status == "active" {
		status = SubActive
	}
	var periodEnd *time.Time
	if !remoteSub.PeriodEnd.IsZero() {
		periodEnd = &remoteSub.PeriodEnd
	}
	return s.deps.DB.Subscriptions().Insert(ctx, LocalSubscription{
		UserID:            req.UserID,
		PlanID:            plan.ID,
		Provider:          prov.Name(),
		ProviderSubID:     remoteSub.ProviderSubID,
		ProviderPlanID:    remotePlanID,
		Status:            status,
		CurrentPeriodEnd:  periodEnd,
		CancelAtPeriodEnd: false,
		DefaultMethodID:   &defaultMethod.ID,
		CouponCode:        couponCode,
	})
}

func (s *Service) persistProviderPlanID(ctx context.Context, plan *billing.PaymentPlans, provider, remotePlanID string) error {
	// Best-effort: update in-memory map; DB update via raw is optional in phase 1.
	if plan.ProviderPlanIDs == nil {
		plan.ProviderPlanIDs = map[string]string{}
	}
	plan.ProviderPlanIDs[provider] = remotePlanID
	_, _ = json.Marshal(plan.ProviderPlanIDs)
	return nil
}

// GetCurrentSubscription returns the user's active subscription if any.
func (s *Service) GetCurrentSubscription(ctx context.Context, userID uuid.UUID, providerName string) (*LocalSubscription, error) {
	prov, err := s.provider(providerName)
	if err != nil {
		return nil, err
	}
	return s.deps.DB.Subscriptions().GetActiveByUserID(ctx, userID, prov.Name())
}

// CancelSubscription cancels autopay at period end.
func (s *Service) CancelSubscription(ctx context.Context, userID uuid.UUID, providerName string) (*LocalSubscription, error) {
	prov, err := s.provider(providerName)
	if err != nil {
		return nil, err
	}
	sub, err := s.deps.DB.Subscriptions().GetActiveByUserID(ctx, userID, prov.Name())
	if err != nil {
		return nil, err
	}
	if err := prov.CancelSubscription(ctx, sub.ProviderSubID, true); err != nil {
		return nil, Error.Wrap(err)
	}
	sub.CancelAtPeriodEnd = true
	if err := s.deps.DB.Subscriptions().Update(ctx, *sub); err != nil {
		return nil, Error.Wrap(err)
	}
	return sub, nil
}

// HandleWebhook verifies and processes a provider webhook.
func (s *Service) HandleWebhook(ctx context.Context, providerName string, headers http.Header, body []byte) error {
	prov, err := s.provider(providerName)
	if err != nil {
		return err
	}
	if err := prov.VerifyWebhook(headers, body); err != nil {
		return Error.Wrap(err)
	}
	event, err := prov.ParseWebhook(body)
	if err != nil {
		return Error.Wrap(err)
	}
	if event.Type == WebhookUnknown {
		return nil
	}
	exists, err := s.deps.DB.Events().Exists(ctx, prov.Name(), event.ProviderEventID)
	if err != nil {
		return Error.Wrap(err)
	}
	if exists {
		return nil
	}

	var attemptID *uuid.UUID
	var subID *uuid.UUID

	switch event.Type {
	case WebhookPaymentCaptured, WebhookOrderPaid:
		attempt, err := s.deps.DB.Attempts().GetByProviderRef(ctx, prov.Name(), event.ProviderRef)
		if err != nil {
			if aid := event.Notes["attempt_id"]; aid != "" {
				id, parseErr := uuid.FromString(aid)
				if parseErr == nil {
					attempt, err = s.deps.DB.Attempts().GetByID(ctx, id)
				}
			}
		}
		if err != nil {
			return Error.Wrap(err)
		}
		attemptID = &attempt.ID
		if attempt.Status != AttemptPaid {
			if err := s.deps.DB.Attempts().UpdateStatus(ctx, attempt.ID, AttemptPaid); err != nil {
				return Error.Wrap(err)
			}
			attempt.Status = AttemptPaid
			if err := s.CompletePayment(ctx, attempt, event.PaymentRef, "Paid via "+prov.Name()); err != nil {
				return err
			}
		}
	case WebhookPaymentFailed:
		attempt, err := s.deps.DB.Attempts().GetByProviderRef(ctx, prov.Name(), event.ProviderRef)
		if err == nil && attempt.Status == AttemptPending {
			_ = s.deps.DB.Attempts().UpdateStatus(ctx, attempt.ID, AttemptFailed)
			attemptID = &attempt.ID
		}
		sub, err := s.deps.DB.Subscriptions().GetByProviderSubID(ctx, prov.Name(), event.ProviderRef)
		if err == nil {
			sub.Status = SubPastDue
			_ = s.deps.DB.Subscriptions().Update(ctx, *sub)
			subID = &sub.ID
		}
	case WebhookSubscriptionActivated, WebhookSubscriptionCharged:
		sub, err := s.deps.DB.Subscriptions().GetByProviderSubID(ctx, prov.Name(), event.ProviderRef)
		if err != nil {
			return Error.Wrap(err)
		}
		subID = &sub.ID
		sub.Status = SubActive
		now := time.Now().UTC()
		periodEnd := now.AddDate(0, 1, 0)
		sub.CurrentPeriodEnd = &periodEnd
		if err := s.deps.DB.Subscriptions().Update(ctx, *sub); err != nil {
			return Error.Wrap(err)
		}
		if err := s.ApplyRenewal(ctx, sub, event.PaymentRef, event.AmountMinor); err != nil {
			return err
		}
	case WebhookSubscriptionCancelled, WebhookSubscriptionCompleted:
		sub, err := s.deps.DB.Subscriptions().GetByProviderSubID(ctx, prov.Name(), event.ProviderRef)
		if err != nil {
			return Error.Wrap(err)
		}
		subID = &sub.ID
		sub.Status = SubCancelled
		sub.CancelAtPeriodEnd = true
		if err := s.deps.DB.Subscriptions().Update(ctx, *sub); err != nil {
			return Error.Wrap(err)
		}
		if err := s.HandleCancel(ctx, sub); err != nil {
			return err
		}
	}

	err = s.deps.DB.Events().Insert(ctx, Event{
		Provider:        prov.Name(),
		ProviderEventID: event.ProviderEventID,
		EventType:       string(event.Type),
		Payload:         body,
		AttemptID:       attemptID,
		SubscriptionID:  subID,
	})
	if err != nil && !errors.Is(err, ErrConflict) {
		return Error.Wrap(err)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func pickInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}
