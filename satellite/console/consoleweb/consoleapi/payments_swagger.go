// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// GeneratePaymentLinkSwaggerRequest is the body for POST /api/v0/payments/generate-payment-link.
type GeneratePaymentLinkSwaggerRequest struct {
	CryptoMode string `json:"cryptoMode" binding:"required" example:"USDT" enums:"SRX,XDC,USDT"`
	PlanID     int64  `json:"planId" binding:"required" example:"1"`
	CouponCode string `json:"couponCode,omitempty" example:"SAVE10"`
}

// GeneratePaymentLinkSwaggerResponse is returned on successful payment link creation.
type GeneratePaymentLinkSwaggerResponse struct {
	RedirectURL string `json:"redirectURL" example:"https://pay.example.com/checkout/abc123"`
}

// PaymentCouponSwaggerItem is one active billing coupon.
type PaymentCouponSwaggerItem struct {
	Code           string    `json:"code" example:"SAVE10"`
	Discount       float64   `json:"discount" example:"10"`
	DiscountType   string    `json:"discount_type" example:"percentage" enums:"percentage,fixed"`
	MaxDiscount    float64   `json:"max_discount" example:"50"`
	MinOrderAmount float64   `json:"min_order_amount" example:"9.99"`
	ValidFrom      time.Time `json:"valid_from" example:"2026-01-01T00:00:00Z"`
	ValidTo        time.Time `json:"valid_to" example:"2026-12-31T23:59:59Z"`
	CreatedAt      time.Time `json:"created_at" example:"2026-01-01T00:00:00Z"`
}

// PaymentInvoiceHistoryItemSwagger is one billing transaction in GET /api/v0/payments/invoice-history.
type PaymentInvoiceHistoryItemSwagger struct {
	ID          int64     `json:"ID" example:"42"`
	UserID      string    `json:"UserID" example:"00000000-0000-0000-0000-000000000000"`
	Amount      float64   `json:"Amount" example:"9.99"`
	Description string    `json:"Description" example:"Plan purchase"`
	Source      string    `json:"Source" example:"token_payment"`
	Status      string    `json:"Status" example:"complete" enums:"pending,complete,failed"`
	Type        string    `json:"Type" example:"debit" enums:"credit,debit,unknown"`
	Metadata    string    `json:"Metadata" example:""`
	Timestamp   time.Time `json:"Timestamp" example:"2026-06-01T12:00:00Z"`
	CreatedAt   time.Time `json:"CreatedAt" example:"2026-06-01T12:00:00Z"`
	PlanID      *int64    `json:"PlanID,omitempty" example:"1"`
}
