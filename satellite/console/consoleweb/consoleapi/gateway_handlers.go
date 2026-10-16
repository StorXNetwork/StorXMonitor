// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/payments/gateway"
	"github.com/StorXNetwork/common/uuid"
)

type checkoutRequestBody struct {
	PlanID     int64  `json:"planId"`
	CouponCode string `json:"couponCode"`
	Provider   string `json:"provider"`
}

type saveMethodRequestBody struct {
	TokenID     string `json:"tokenId"`
	Brand       string `json:"brand"`
	Last4       string `json:"last4"`
	ExpMonth    int    `json:"expMonth"`
	ExpYear     int    `json:"expYear"`
	MakeDefault bool   `json:"makeDefault"`
	Provider    string `json:"provider"`
}

type subscriptionRequestBody struct {
	PlanID     int64  `json:"planId"`
	CouponCode string `json:"couponCode"`
	Provider   string `json:"provider"`
}

// CreateCheckout starts a Razorpay Checkout.js one-time payment for a plan.
func (p *Payments) CreateCheckout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}

	user, err := p.service.GetUserAndAuditLog(ctx, "create payment checkout")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	var body checkoutRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.PlanID == 0 {
		http.Error(w, "planId is required", http.StatusBadRequest)
		return
	}

	session, attemptID, paid, err := p.gateway.CreateCheckout(ctx, gateway.CreateCheckoutRequest{
		UserID:     user.ID,
		UserEmail:  user.Email,
		UserName:   user.FullName,
		PlanID:     body.PlanID,
		CouponCode: body.CouponCode,
		Provider:   body.Provider,
	})
	if err != nil {
		p.log.Error("create checkout failed", zap.Error(err))
		status := http.StatusInternalServerError
		if errors.Is(err, gateway.ErrProviderDisabled) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"attemptId":   attemptID.String(),
		"paid":        paid,
		"keyId":       session.KeyID,
		"orderId":     session.OrderID,
		"amount":      session.AmountMinor,
		"currency":    session.Currency,
		"name":        session.Name,
		"description": session.Description,
		"prefill": map[string]string{
			"name":  session.Prefill.Name,
			"email": session.Prefill.Email,
		},
		"provider": "razorpay",
	})
}

// ListPaymentMethods lists saved cards.
func (p *Payments) ListPaymentMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "list payment methods")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	methods, err := p.gateway.ListMethods(ctx, user.ID, r.URL.Query().Get("provider"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(methods)
}

// SavePaymentMethod saves a tokenized card.
func (p *Payments) SavePaymentMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "save payment method")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	var body saveMethodRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TokenID == "" {
		http.Error(w, "tokenId is required", http.StatusBadRequest)
		return
	}
	method, err := p.gateway.SaveMethod(ctx, gateway.SaveMethodRequest{
		UserID:      user.ID,
		UserEmail:   user.Email,
		UserName:    user.FullName,
		Provider:    body.Provider,
		TokenID:     body.TokenID,
		Brand:       body.Brand,
		Last4:       body.Last4,
		ExpMonth:    body.ExpMonth,
		ExpYear:     body.ExpYear,
		MakeDefault: body.MakeDefault,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(method)
}

// SetDefaultPaymentMethod sets the default card.
func (p *Payments) SetDefaultPaymentMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "set default payment method")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "invalid method id", http.StatusBadRequest)
		return
	}
	if err := p.gateway.SetDefaultMethod(ctx, user.ID, id, r.URL.Query().Get("provider")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gateway.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// DeletePaymentMethod deletes a saved card.
func (p *Payments) DeletePaymentMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "delete payment method")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "invalid method id", http.StatusBadRequest)
		return
	}
	if err := p.gateway.DeleteMethod(ctx, user.ID, id, r.URL.Query().Get("provider")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gateway.ErrCannotDeleteDefault) {
			status = http.StatusConflict
		} else if errors.Is(err, gateway.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// CreateSubscription starts autopay for a plan.
func (p *Payments) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "create subscription")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	var body subscriptionRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PlanID == 0 {
		http.Error(w, "planId is required", http.StatusBadRequest)
		return
	}
	sub, err := p.gateway.CreateSubscription(ctx, gateway.CreateSubscriptionRequest{
		UserID:     user.ID,
		UserEmail:  user.Email,
		UserName:   user.FullName,
		PlanID:     body.PlanID,
		CouponCode: body.CouponCode,
		Provider:   body.Provider,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gateway.ErrActiveSubscription) {
			status = http.StatusConflict
		} else if errors.Is(err, gateway.ErrDefaultCardRequired) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sub)
}

// GetCurrentSubscription returns the current subscription.
func (p *Payments) GetCurrentSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "get current subscription")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	sub, err := p.gateway.GetCurrentSubscription(ctx, user.ID, r.URL.Query().Get("provider"))
	if err != nil {
		if errors.Is(err, gateway.ErrNotFound) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"subscription": nil})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sub)
}

// CancelSubscription cancels autopay at period end.
func (p *Payments) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	user, err := p.service.GetUserAndAuditLog(ctx, "cancel subscription")
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	sub, err := p.gateway.CancelSubscription(ctx, user.ID, body.Provider)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gateway.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sub)
}

// HandleRazorpayWebhook processes Razorpay webhooks (no session auth).
func (p *Payments) HandleRazorpayWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if p.gateway == nil {
		http.Error(w, "payment gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if err := p.gateway.HandleWebhook(ctx, "razorpay", r.Header, body); err != nil {
		p.log.Warn("razorpay webhook failed", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
