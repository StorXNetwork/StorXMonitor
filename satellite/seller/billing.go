// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
)

// Billing period values.
const (
	BillingPeriodMonth = "month"
	BillingPeriodYear  = "year"
)

// Assignment status values.
const (
	AssignmentStatusActive    = "active"
	AssignmentStatusScheduled = "scheduled"
	AssignmentStatusEnded     = "ended"
)

// Invoice status values.
const (
	InvoiceStatusDraft            = "draft"
	InvoiceStatusPending          = "pending"
	InvoiceStatusPaymentReceived  = "payment_received"
	InvoiceStatusOverdue          = "overdue"
	InvoiceStatusCancelled        = "cancelled"
)

// Billing notification types.
const (
	NotificationTypePlanEnding   = "plan_ending"
	NotificationTypePlanSwitched = "plan_switched"
	NotificationTypeInvoice      = "invoice"
	NotificationTypePayment      = "payment"
)

// SellerPlan is an admin-created shared user plan.
type SellerPlan struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	TierKey         string    `json:"tierKey"`
	BillingPeriod   string    `json:"billingPeriod"`
	StorageBytes    int64     `json:"storageBytes"`
	BandwidthBytes  int64     `json:"bandwidthBytes"`
	RetailAmount    int64     `json:"retailAmount"`
	WholesaleAmount int64     `json:"wholesaleAmount"`
	Currency        string    `json:"currency"`
	Description     string    `json:"description"`
	Features        []string  `json:"features"`
	Recommended     bool      `json:"recommended"`
	PaymentPlanID   *int64    `json:"paymentPlanId,omitempty"`
	Active          bool      `json:"active"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// CreateSellerPlanRequest holds fields for creating a plan.
type CreateSellerPlanRequest struct {
	Name            string   `json:"name"`
	TierKey         string   `json:"tierKey"`
	BillingPeriod   string   `json:"billingPeriod"`
	StorageBytes    int64    `json:"storageBytes"`
	BandwidthBytes  int64    `json:"bandwidthBytes"`
	RetailAmount    int64    `json:"retailAmount"`
	WholesaleAmount int64    `json:"wholesaleAmount"`
	Currency        string   `json:"currency"`
	Description     string   `json:"description"`
	Features        []string `json:"features"`
	Recommended     bool     `json:"recommended"`
}

// UpdateSellerPlanRequest holds updatable plan fields.
type UpdateSellerPlanRequest struct {
	Name            *string
	TierKey         *string
	BillingPeriod   *string
	StorageBytes    *int64
	BandwidthBytes  *int64
	RetailAmount    *int64
	WholesaleAmount *int64
	Currency        *string
	Description     *string
	Features        *[]string
	Recommended     *bool
	Active          *bool
	PaymentPlanID   *int64
	UpdatedAt       time.Time
}

// UserPlanAssignment is a plan assignment for a reseller's user.
type UserPlanAssignment struct {
	ID                  uuid.UUID  `json:"id"`
	ResellerID          uuid.UUID  `json:"resellerId"`
	UserID              uuid.UUID  `json:"userId"`
	PlanID              uuid.UUID  `json:"planId"`
	Status              string     `json:"status"`
	RetailAmount        int64      `json:"retailAmount"`
	WholesaleAmount     int64      `json:"wholesaleAmount"`
	BillingPeriod       string     `json:"billingPeriod"`
	DurationMonths      *int       `json:"durationMonths,omitempty"`
	PlanStartsAt        time.Time  `json:"planStartsAt"`
	PlanEndsAt          *time.Time `json:"planEndsAt,omitempty"`
	FuturePlanID        *uuid.UUID `json:"futurePlanId,omitempty"`
	AutoSwitchOnEnd     bool       `json:"autoSwitchOnEnd"`
	NotifyBeforeEnd     bool       `json:"notifyBeforeEnd"`
	NotifiedEndingAt    *time.Time `json:"notifiedEndingAt,omitempty"`
	UserPaidAt          *time.Time `json:"userPaidAt,omitempty"`
	Notes               *string    `json:"notes,omitempty"`
	AssignedAt          time.Time  `json:"assignedAt"`
	EndedAt             *time.Time `json:"endedAt,omitempty"`
	AssignedByReseller  bool       `json:"assignedByReseller"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`

	// Optional hydrated fields for API responses.
	UserEmail string `json:"userEmail,omitempty"`
	PlanName  string `json:"planName,omitempty"`
}

// AssignPlanRequest is the seller assign-plan payload.
type AssignPlanRequest struct {
	PlanID           uuid.UUID  `json:"planId"`
	DurationMonths   int        `json:"durationMonths"`
	FuturePlanID     *uuid.UUID `json:"futurePlanId,omitempty"`
	AutoSwitchOnEnd  bool       `json:"autoSwitchOnEnd"`
	NotifyBeforeEnd  bool       `json:"notifyBeforeEnd"`
	UserPaid         bool       `json:"userPaid"`
	Notes            string     `json:"notes"`
}

// UpdateFuturePlanRequest updates or cancels a scheduled future plan.
type UpdateFuturePlanRequest struct {
	FuturePlanID    *uuid.UUID `json:"futurePlanId"`
	AutoSwitchOnEnd *bool      `json:"autoSwitchOnEnd"`
	NotifyBeforeEnd *bool      `json:"notifyBeforeEnd"`
	Cancel          bool       `json:"cancel"`
}

// SellerInvoice is a wholesale invoice for a reseller.
type SellerInvoice struct {
	ID          uuid.UUID  `json:"id"`
	ResellerID  uuid.UUID  `json:"resellerId"`
	PeriodStart time.Time  `json:"periodStart"`
	PeriodEnd   time.Time  `json:"periodEnd"`
	TotalAmount int64      `json:"totalAmount"`
	Currency    string     `json:"currency"`
	Status      string     `json:"status"`
	IssuedAt    *time.Time `json:"issuedAt,omitempty"`
	PaidAt      *time.Time `json:"paidAt,omitempty"`
	AdminNote   *string    `json:"adminNote,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	Lines       []SellerInvoiceLine `json:"lines,omitempty"`
}

// SellerInvoiceLine is a wholesale line on an invoice.
type SellerInvoiceLine struct {
	ID            uuid.UUID `json:"id"`
	InvoiceID     uuid.UUID `json:"invoiceId"`
	AssignmentID  uuid.UUID `json:"assignmentId"`
	UserID        uuid.UUID `json:"userId"`
	PlanID        uuid.UUID `json:"planId"`
	Description   string    `json:"description"`
	Amount        int64     `json:"amount"`
	RetailAmount  int64     `json:"retailAmount"`
	AssignedAt    time.Time `json:"assignedAt"`
	CreatedAt     time.Time `json:"createdAt"`
	UserEmail     string    `json:"userEmail,omitempty"`
	PlanName      string    `json:"planName,omitempty"`
}

// GenerateInvoiceRequest is the admin invoice generation payload.
type GenerateInvoiceRequest struct {
	PeriodStart time.Time `json:"periodStart"`
	PeriodEnd   time.Time `json:"periodEnd"`
	AdminNote   string    `json:"adminNote"`
}

// UpdateInvoiceStatusRequest updates invoice status.
type UpdateInvoiceStatusRequest struct {
	Status    string `json:"status"`
	AdminNote string `json:"adminNote"`
}

// BillingNotification is a seller billing event notification.
type BillingNotification struct {
	ID         uuid.UUID  `json:"id"`
	ResellerID uuid.UUID  `json:"resellerId"`
	UserID     *uuid.UUID `json:"userId,omitempty"`
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Body       string     `json:"body"`
	Read       bool       `json:"read"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// ResellerSummary is used by admin seller list.
type ResellerSummary struct {
	Reseller         Reseller `json:"reseller"`
	UserCount         int64    `json:"userCount"`
	AssignmentCount   int64    `json:"assignmentCount"`
}

// TenantUserWithPlan is a tenant user plus current/scheduled assignment info.
type TenantUserWithPlan struct {
	ID             uuid.UUID          `json:"id"`
	Email          string             `json:"email"`
	FullName       string             `json:"fullName"`
	Status         int                `json:"status"`
	Kind           int                `json:"kind"`
	CreatedAt      time.Time          `json:"createdAt"`
	ActivePlan     *UserPlanAssignment `json:"activePlan,omitempty"`
	ScheduledPlan  *UserPlanAssignment `json:"scheduledPlan,omitempty"`
}

// SellerPlans exposes methods to manage seller_plans.
type SellerPlans interface {
	Insert(ctx context.Context, plan *SellerPlan) (*SellerPlan, error)
	Get(ctx context.Context, id uuid.UUID) (*SellerPlan, error)
	List(ctx context.Context) ([]SellerPlan, error)
	ListActive(ctx context.Context) ([]SellerPlan, error)
	Update(ctx context.Context, id uuid.UUID, update UpdateSellerPlanRequest) (*SellerPlan, error)
	Deactivate(ctx context.Context, id uuid.UUID) error
	// ClearRecommendedExcept sets recommended=false on every plan except exceptID.
	ClearRecommendedExcept(ctx context.Context, exceptID uuid.UUID) error
}

// UserPlanAssignments exposes methods to manage assignments.
type UserPlanAssignments interface {
	Insert(ctx context.Context, a *UserPlanAssignment) (*UserPlanAssignment, error)
	Get(ctx context.Context, id uuid.UUID) (*UserPlanAssignment, error)
	GetByUserAndStatus(ctx context.Context, userID uuid.UUID, status string) (*UserPlanAssignment, error)
	ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]UserPlanAssignment, error)
	ListByResellerIDAndStatus(ctx context.Context, resellerID uuid.UUID, status string) ([]UserPlanAssignment, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]UserPlanAssignment, error)
	ListDueScheduled(ctx context.Context, now time.Time) ([]UserPlanAssignment, error)
	ListDueAutoSwitch(ctx context.Context, now time.Time) ([]UserPlanAssignment, error)
	ListNeedingEndNotification(ctx context.Context, notifyBefore time.Time) ([]UserPlanAssignment, error)
	CountByResellerID(ctx context.Context, resellerID uuid.UUID) (int64, error)
	Update(ctx context.Context, id uuid.UUID, a *UserPlanAssignment) (*UserPlanAssignment, error)
}

// SellerInvoices exposes methods to manage invoices.
type SellerInvoices interface {
	Insert(ctx context.Context, inv *SellerInvoice) (*SellerInvoice, error)
	Get(ctx context.Context, id uuid.UUID) (*SellerInvoice, error)
	ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]SellerInvoice, error)
	Update(ctx context.Context, inv *SellerInvoice) (*SellerInvoice, error)
	InsertLine(ctx context.Context, line *SellerInvoiceLine) (*SellerInvoiceLine, error)
	ListLines(ctx context.Context, invoiceID uuid.UUID) ([]SellerInvoiceLine, error)
}

// BillingNotifications exposes methods to manage billing notifications.
type BillingNotifications interface {
	Insert(ctx context.Context, n *BillingNotification) (*BillingNotification, error)
	ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]BillingNotification, error)
	MarkRead(ctx context.Context, id uuid.UUID) error
}
