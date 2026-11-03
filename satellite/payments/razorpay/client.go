// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package razorpay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/payments/gateway"
)

// Error is the razorpay package error class.
var Error = errs.Class("razorpay")

// Client talks to the Razorpay REST API.
type Client struct {
	config     Config
	httpClient *http.Client
}

// NewClient constructs a Razorpay API client.
func NewClient(config Config) *Client {
	base := strings.TrimRight(config.APIBaseURL, "/")
	if base == "" {
		base = "https://api.razorpay.com/v1"
	}
	config.APIBaseURL = base
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Config returns a copy of the client configuration.
func (c *Client) Config() Config {
	return c.config
}

// Enabled reports whether Razorpay checkout is configured and turned on.
func (c *Client) Enabled() bool {
	return c != nil && c.config.Enabled && c.config.KeyID != "" && c.config.KeySecret != ""
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, out any) error {
	if !c.Enabled() {
		return Error.New("razorpay is not enabled")
	}
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return Error.Wrap(err)
		}
		bodyReader = bytes.NewReader(b)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.config.APIBaseURL+path, bodyReader)
	if err != nil {
		return Error.Wrap(err)
	}
	httpReq.SetBasicAuth(c.config.KeyID, c.config.KeySecret)
	if reqBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return Error.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Error.Wrap(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Error.New("%s %s failed: status=%d body=%s", method, path, resp.StatusCode, string(respBody))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return Error.Wrap(err)
	}
	return nil
}

// VerifyWebhookSignature validates the X-Razorpay-Signature header.
func (c *Client) VerifyWebhookSignature(body []byte, signature string) error {
	if c == nil || c.config.WebhookSecret == "" {
		return Error.New("razorpay webhook secret is not configured")
	}
	if signature == "" {
		return Error.New("missing razorpay signature")
	}
	mac := hmac.New(sha256.New, []byte(c.config.WebhookSecret))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return Error.New("invalid razorpay signature")
	}
	return nil
}

// CreateOrder creates a Razorpay order for Checkout.js.
func (c *Client) CreateOrder(ctx context.Context, amountMinor int64, currency, receipt string, notes map[string]string) (orderID string, err error) {
	var out struct {
		ID string `json:"id"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/orders", map[string]any{
		"amount":   amountMinor,
		"currency": currency,
		"receipt":  truncate(receipt, 40),
		"notes":    notes,
	}, &out)
	if err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", Error.New("create order returned empty id")
	}
	return out.ID, nil
}

// CreateCustomer creates a Razorpay customer.
func (c *Client) CreateCustomer(ctx context.Context, name, email string) (customerID string, err error) {
	var out struct {
		ID string `json:"id"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/customers", map[string]any{
		"name":  name,
		"email": email,
	}, &out)
	if err != nil {
		return "", err
	}
	return out.ID, nil
}

// CreateToken saves a card token against a customer (token id from Checkout).
func (c *Client) CreateToken(ctx context.Context, customerID, tokenID string) (methodID string, brand, last4 string, expMonth, expYear int, err error) {
	// Token is already created by Checkout; fetch details.
	var out struct {
		ID   string `json:"id"`
		Card struct {
			Network string `json:"network"`
			Last4   string `json:"last4"`
			ExpiryMonth int `json:"expiry_month"`
			ExpiryYear  int `json:"expiry_year"`
		} `json:"card"`
	}
	err = c.doJSON(ctx, http.MethodGet, "/tokens/"+tokenID, nil, &out)
	if err != nil {
		// Fallback: treat tokenID as the method id.
		return tokenID, "", "", 0, 0, nil
	}
	if out.ID == "" {
		out.ID = tokenID
	}
	return out.ID, out.Card.Network, out.Card.Last4, out.Card.ExpiryMonth, out.Card.ExpiryYear, nil
}

// DeleteToken deletes a saved token.
func (c *Client) DeleteToken(ctx context.Context, customerID, tokenID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/customers/"+customerID+"/tokens/"+tokenID, nil, nil)
}

// CreatePlan creates a Razorpay subscription plan.
func (c *Client) CreatePlan(ctx context.Context, plan gateway.LocalPlan) (planID string, err error) {
	period, interval := mapValidity(plan.Validity, plan.ValidityUnit)
	amount, err := gateway.AmountToMinorUnits(plan.Price)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/plans", map[string]any{
		"period":   period,
		"interval": interval,
		"item": map[string]any{
			"name":     plan.Name,
			"amount":   amount,
			"currency": plan.Currency,
		},
	}, &out)
	if err != nil {
		return "", err
	}
	return out.ID, nil
}

// CreateSubscription creates a Razorpay subscription.
func (c *Client) CreateSubscription(ctx context.Context, req gateway.SubRequest) (sub gateway.Subscription, err error) {
	body := map[string]any{
		"plan_id":         req.RemotePlanID,
		"customer_id":     req.CustomerID,
		"total_count":     120,
		"customer_notify": 1,
		"notes":           req.Notes,
	}
	if req.PaymentMethod != "" {
		body["addon"] = []any{}
	}
	if req.TotalCount > 0 {
		body["total_count"] = req.TotalCount
	}
	var out struct {
		ID                 string `json:"id"`
		Status             string `json:"status"`
		PlanID             string `json:"plan_id"`
		CurrentEnd         int64  `json:"current_end"`
		CurrentStart       int64  `json:"current_start"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/subscriptions", body, &out)
	if err != nil {
		return gateway.Subscription{}, err
	}
	sub = gateway.Subscription{
		ProviderSubID:  out.ID,
		ProviderPlanID: out.PlanID,
		Status:         out.Status,
	}
	if out.CurrentEnd > 0 {
		sub.PeriodEnd = time.Unix(out.CurrentEnd, 0).UTC()
	}
	return sub, nil
}

// CancelSubscription cancels a Razorpay subscription.
func (c *Client) CancelSubscription(ctx context.Context, subID string, atPeriodEnd bool) error {
	path := "/subscriptions/" + subID + "/cancel"
	body := map[string]any{"cancel_at_cycle_end": atPeriodEnd}
	return c.doJSON(ctx, http.MethodPost, path, body, nil)
}

func mapValidity(validity int64, unit string) (period string, interval int) {
	interval = int(validity)
	if interval <= 0 {
		interval = 1
	}
	switch strings.ToLower(unit) {
	case "day", "days":
		return "daily", interval
	case "week", "weeks":
		return "weekly", interval
	case "year", "years":
		return "yearly", interval
	default:
		return "monthly", interval
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// AmountToMinorUnits is exported for tests; delegates to gateway helper.
func AmountToMinorUnits(price float64) (int64, error) {
	return gateway.AmountToMinorUnits(price)
}

// FormatAmountMajor formats minor units.
func FormatAmountMajor(amountMinor int64) string {
	return gateway.FormatAmountMajor(amountMinor)
}

// NoteString reads a note value.
func NoteString(notes map[string]string, key string) string {
	if notes == nil {
		return ""
	}
	return notes[key]
}
