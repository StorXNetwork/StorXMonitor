// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package billing

import (
	"context"
	"fmt"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/currency"
	"storj.io/common/uuid"
)

// TransactionStatus indicates transaction status.
type TransactionStatus string

// ErrInsufficientFunds represents err when a user balance is too low for some transaction.
var ErrInsufficientFunds = errs.New("Insufficient funds for this transaction")

// ErrNoWallet represents err when there is no wallet in the DB.
var ErrNoWallet = errs.New("wallet does not exists")

// ErrNoTransactions represents err when there is no billing transactions in the DB.
var ErrNoTransactions = errs.New("no transactions in the database")

const (
	// TransactionStatusPending indicates that status of this transaction is pending.
	TransactionStatusPending = "pending"
	// TransactionStatusCompleted indicates that status of this transaction is complete.
	TransactionStatusCompleted = "complete"
	// TransactionStatusFailed indicates that status of this transaction is failed.
	TransactionStatusFailed = "failed"
)

// TransactionType indicates transaction type.
type TransactionType string

const (
	// TransactionTypeCredit indicates that type of this transaction is credit.
	TransactionTypeCredit = "credit"
	// TransactionTypeDebit indicates that type of this transaction is debit.
	TransactionTypeDebit = "debit"
	// TransactionTypeUnknown indicates that type of this transaction is unknown.
	TransactionTypeUnknown = "unknown"
)

// TransactionsDB is an interface which defines functionality
// of DB which stores billing transactions.
//
// architecture: Database
type TransactionsDB interface {
	// Insert inserts the provided primary transaction along with zero or more
	// supplemental transactions that. This is NOT intended for bulk insertion,
	// but rather to provide an atomic commit of one or more _related_
	// transactions.
	Insert(ctx context.Context, primaryTx Transaction, supplementalTx ...Transaction) (txIDs []int64, err error)
	// boris
	Inserts(ctx context.Context, primaryTx Transactions) (err error)
	// FailPendingInvoiceTokenPayments marks all specified pending invoice token payments as failed, and refunds the pending charges.
	FailPendingInvoiceTokenPayments(ctx context.Context, txIDs ...int64) error
	// CompletePendingInvoiceTokenPayments updates the status of the pending invoice token payment to complete.
	CompletePendingInvoiceTokenPayments(ctx context.Context, txIDs ...int64) error
	// UpdateMetadata updates the metadata of the transaction.
	UpdateMetadata(ctx context.Context, txID int64, metadata []byte) error
	// LastTransaction returns the timestamp and metadata of the last known transaction for given source and type.
	LastTransaction(ctx context.Context, txSource string, txType TransactionType) (time.Time, []byte, error)
	// List returns all transactions for the specified user.
	List(ctx context.Context, userID uuid.UUID) ([]Transaction, error)
	// boris
	Lists(ctx context.Context, userID uuid.UUID) ([]Transactions, error)
	// ListSource returns all transactions for the specified user and source.
	ListSource(ctx context.Context, userID uuid.UUID, txSource string) ([]Transaction, error)
	// GetBalance returns the current usable balance for the specified user.
	GetBalance(ctx context.Context, userID uuid.UUID) (currency.Amount, error)

	GetPaymentPlans(ctx context.Context) ([]PaymentPlans, error)

	GetPaymentPlansByID(ctx context.Context, id int64) (*PaymentPlans, error)

	GetActiveCoupons(ctx context.Context) ([]Coupons, error)

	GetCouponByCode(ctx context.Context, code string) (*Coupons, error)

	GetCoupons(ctx context.Context) ([]Coupons, error)

	// GetCouponsWithFilters returns coupons with filters and pagination applied at database level
	GetCouponsWithFilters(ctx context.Context, filters CouponFilters) (coupons []Coupons, total int64, err error)

	// GetCouponStats returns statistics about coupons (total, active, expired, upcoming)
	GetCouponStats(ctx context.Context) (stats CouponStats, err error)

	// CreateCoupon creates a new coupon in the database
	CreateCoupon(ctx context.Context, coupon Coupons) (*Coupons, error)

	// UpdateCoupon updates an existing coupon
	UpdateCoupon(ctx context.Context, code string, coupon Coupons) (*Coupons, error)

	// DeleteCoupon deletes a coupon by code
	DeleteCoupon(ctx context.Context, code string) error
}

// PaymentType is an interface which defines functionality required for all billing payment types. Payment types can
// include but are not limited to Bitcoin, Ether, credit or debit card, ACH transfer, or even physical transfer of live
// goats. In each case, a source, type, and method to get new transactions must be defined by the service, though
// metadata specific to each payment type is also supported (i.e. goat hair type).
type PaymentType interface {
	// Sources the supported sources of the payment type
	Sources() []string
	// Type the type of the payment
	Type() TransactionType
	// GetNewTransactions returns new transactions for a given source that occurred after the provided last transaction received.
	GetNewTransactions(ctx context.Context, source string, lastTransactionTime time.Time, metadata []byte) ([]Transaction, error)
}

// Well-known PaymentType sources.
const (
	StripeSource            = "stripe"
	StorjScanEthereumSource = "ethereum"
	StorjScanZkSyncSource   = "zkSync"
	StorjScanBonusSource    = "storjscanbonus"
)

// SourceChainIDs are some well known chain IDs for the above sources.
var SourceChainIDs = map[string][]int64{
	StorjScanEthereumSource: {1, 4, 5, 1337, 11155111},
	StorjScanZkSyncSource:   {300, 324},
}

// Transaction defines billing related transaction info that is stored in the DB.
type Transaction struct {
	ID          int64
	UserID      uuid.UUID
	Amount      currency.Amount
	Description string
	Source      string
	Status      TransactionStatus
	Type        TransactionType
	Metadata    []byte
	Timestamp   time.Time
	CreatedAt   time.Time
}

// boris
type Transactions struct {
	ID          int64
	UserID      uuid.UUID
	Amount      float64
	Description string
	Source      string
	Status      TransactionStatus
	Type        TransactionType
	Metadata    []byte
	Timestamp   time.Time
	CreatedAt   time.Time
}

type PaymentPlans struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Storage      int64     `json:"storage"`
	Price        float64   `json:"price"`
	Bandwidth    int64     `json:"bandwidth"`
	Benefit      []string  `json:"benefit"`
	Validity     int64     `json:"validity"`
	ValidityUnit string    `json:"validity_unit"`
	Group        string    `json:"group"`
	CreatedAt    time.Time `json:"created_at"`
}

type Coupons struct {
	Code           string    `json:"code"`
	Discount       float64   `json:"discount"`
	DiscountType   string    `json:"discount_type"`
	MaxDiscount    float64   `json:"max_discount"`
	MinOrderAmount float64   `json:"min_order_amount"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidTo        time.Time `json:"valid_to"`
	CreatedAt      time.Time `json:"created_at"`
}

// CouponFilters defines filters and pagination for coupon queries
type CouponFilters struct {
	// Status filters coupons by status: 1=active, 2=expired, 3=upcoming
	Status *int `json:"status,omitempty"`

	// DiscountType filters by discount type ("percentage" or "fixed")
	DiscountType *string `json:"discount_type,omitempty"`

	// This finds coupons valid/active during the specified period
	ValidDuringStart *time.Time `json:"valid_during_start,omitempty"`
	ValidDuringEnd   *time.Time `json:"valid_during_end,omitempty"`

	// Code filters by coupon code (partial match)
	Code *string `json:"code,omitempty"`

	// Pagination
	Limit  int `json:"limit"`  // Number of records to return (default: 100, max: 1000)
	Offset int `json:"offset"` // Number of records to skip (default: 0)

	// OrderBy field name for sorting (default: "created_at")
	OrderBy string `json:"order_by,omitempty"`

	// OrderDirection "ASC" or "DESC" (default: "DESC")
	OrderDirection string `json:"order_direction,omitempty"`
}

// CouponStats contains statistics about coupons
type CouponStats struct {
	Total    int64 `json:"total"`    // Total number of coupons
	Active   int64 `json:"active"`   // Coupons currently valid (valid_from <= now <= valid_to)
	Expired  int64 `json:"expired"`  // Coupons that have expired (valid_to < now)
	Upcoming int64 `json:"upcoming"` // Coupons not yet active (valid_from > now)
}

// CalculateBonusAmount calculates bonus for given currency amount and bonus rate.
func CalculateBonusAmount(amount currency.Amount, bonusRate int64) currency.Amount {
	bonusUnits := amount.BaseUnits() * bonusRate / 100
	return currency.AmountFromBaseUnits(bonusUnits, amount.Currency())
}

func prepareBonusTransaction(bonusRate int64, source string, transaction Transaction) (Transaction, bool) {
	// Bonus transactions only apply when enabled (i.e. positive rate) and
	// for StorjScan transactions.
	switch {
	case bonusRate <= 0:
		return Transaction{}, false
	case source != StorjScanEthereumSource && source != StorjScanZkSyncSource:
		return Transaction{}, false
	case transaction.Type != TransactionTypeCredit:
		// This is defensive. Storjscan shouldn't provide "debit" transactions.
		return Transaction{}, false
	}

	return Transaction{
		UserID:      transaction.UserID,
		Amount:      CalculateBonusAmount(transaction.Amount, bonusRate),
		Description: fmt.Sprintf("STORJ Token Bonus (%d%%)", bonusRate),
		Source:      StorjScanBonusSource,
		Status:      TransactionStatusCompleted,
		Type:        TransactionTypeCredit,
		Timestamp:   transaction.Timestamp,
		Metadata:    append([]byte(nil), transaction.Metadata...),
	}, true
}
