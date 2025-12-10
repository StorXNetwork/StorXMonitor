// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/currency"
	"storj.io/common/dbutil/pgutil/pgerrcode"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/payments/billing"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that *billingDB implements billing.TransactionsDB.
var _ billing.TransactionsDB = (*billingDB)(nil)

// billingDB is billing DB.
//
// architecture: Database
type billingDB struct {
	db *satelliteDB
}

func updateBalance(ctx context.Context, tx *dbx.Tx, userID uuid.UUID, oldBalance, newBalance currency.Amount) error {
	updatedRow, err := tx.Update_BillingBalance_By_UserId_And_Balance(ctx,
		dbx.BillingBalance_UserId(userID[:]),
		dbx.BillingBalance_Balance(oldBalance.BaseUnits()),
		dbx.BillingBalance_Update_Fields{
			Balance: dbx.BillingBalance_Balance(newBalance.BaseUnits()),
		})
	if err != nil {
		return Error.Wrap(err)
	}
	if updatedRow == nil {
		// Try an insert here, in case the user never had a record in the table.
		// If the user already had a record, and the oldBalance was not as expected,
		// the insert will fail anyways.
		err = tx.CreateNoReturn_BillingBalance(ctx,
			dbx.BillingBalance_UserId(userID[:]),
			dbx.BillingBalance_Balance(newBalance.BaseUnits()))
		if err != nil {
			return Error.Wrap(err)
		}
	}
	return nil
}

func (db billingDB) Insert(ctx context.Context, primaryTx billing.Transaction, supplementalTxs ...billing.Transaction) (_ []int64, err error) {
	defer mon.Task()(&ctx)(&err)

	// NOTE: if this is changed for bulk insertion we'll need to ensure that
	// either limits are imposed on the number of inserts, or that the work
	// is broken up into distinct batches.
	// If the latter happens, care must be taken to provide an interface where
	// even if the bulk inserts are broken up, that transactions that
	// absolutely need to be committed together can continue to do so (e.g.
	// a storjscan sourced transaction and its related bonus transaction).

	// This limit is somewhat arbitrary and can be revisited. This method is
	// NOT intended for bulk insertion but rather to provided a way for
	// related transactions to be committed together.
	const supplementalTxLimit = 5
	if len(supplementalTxs) > supplementalTxLimit {
		return nil, Error.New("Cannot insert more than %d supplemental txs (tried %d)", supplementalTxLimit, len(supplementalTxs))
	}

	return nil, Error.New("Unable to insert new billing transaction after several retries: %v", err)
}

// boris
func (db billingDB) Inserts(ctx context.Context, primaryTx billing.Transactions) (err error) {
	defer mon.Task()(&ctx)(&err)

	for retryCount := 0; retryCount < 5; retryCount++ {
		err := db.tryInserts(ctx, primaryTx)
		switch {
		case err == nil:
			return nil
		case pgerrcode.IsConstraintViolation(err):
		default:
			return err
		}
	}
	return Error.New("Unable to insert new billing transaction after several retries: %v", err)
}

// boris
func (db billingDB) tryInserts(ctx context.Context, primaryTx billing.Transactions) (err error) {
	defer mon.Task()(&ctx)(&err)

	createTransaction := func(ctx context.Context, tx *dbx.Tx, billingTX *billing.Transactions) error {
		amount := billingTX.Amount
		createFields := dbx.BillingTransaction_Create_Fields{}
		if billingTX.PlanID != nil {
			createFields.PlanId = dbx.BillingTransaction_PlanId(*billingTX.PlanID)
		}
		_, err := tx.Create_BillingTransaction(ctx,
			dbx.BillingTransaction_UserId(billingTX.UserID[:]),
			dbx.BillingTransaction_Amount(int64(amount)),
			dbx.BillingTransaction_Currency("USD"),
			dbx.BillingTransaction_Description(billingTX.Description),
			dbx.BillingTransaction_Source(billingTX.Source),
			dbx.BillingTransaction_Status(string(billingTX.Status)),
			dbx.BillingTransaction_Type(string(billingTX.Type)),
			dbx.BillingTransaction_Metadata(handleMetaDataZeroValue(billingTX.Metadata)),
			dbx.BillingTransaction_Timestamp(billingTX.Timestamp),
			createFields)
		if err != nil {
			return Error.Wrap(err)
		}
		return nil
	}

	// var txIDs []int64
	err = db.db.WithTx(ctx, func(ctx context.Context, tx *dbx.Tx) error {

		err := createTransaction(ctx, tx, &primaryTx)
		if err != nil {
			return err
		}
		// txIDs = append(txIDs, txID)

		// for _, supplementalTx := range supplementalTxs {
		// 	txID, err := createTransaction(ctx, tx, &supplementalTx)
		// 	if err != nil {
		// 		return err
		// 	}
		// 	txIDs = append(txIDs, txID)
		// }
		return nil
	})
	return err
}

func (db billingDB) GetPaymentPlans(ctx context.Context) (plans []billing.PaymentPlans, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxPlans, err := db.db.All_PaymentPlans(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	plans, err = convertSlice(dbxPlans, fromDBXPaymentPlans)
	return plans, Error.Wrap(err)
}

func (db billingDB) GetPaymentPlansByID(ctx context.Context, id int64) (plans *billing.PaymentPlans, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxPlan, err := db.db.Get_PaymentPlans_By_Id(ctx, dbx.PaymentPlans_Id(id))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	plan, err := fromDBXPaymentPlans(dbxPlan)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &plan, nil
}

func (db billingDB) GetCoupons(ctx context.Context) (coupons []billing.Coupons, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxCoupons, err := db.db.All_Coupon(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	coupons, err = convertSlice(dbxCoupons, fromDBXCoupon)
	return coupons, Error.Wrap(err)
}

func (db billingDB) GetCouponsWithFilters(ctx context.Context, f billing.CouponFilters) ([]billing.Coupons, int64, error) {
	defer mon.Task()(&ctx)(nil)

	var (
		where []string
		args  []interface{}
	)

	// Helper to add WHERE conditions cleanly
	add := func(cond string, val interface{}) {
		where = append(where, fmt.Sprintf("%s $%d", cond, len(args)+1))
		args = append(args, val)
	}

	// Filters
	if f.DiscountType != nil && *f.DiscountType != "" {
		add("discount_type =", *f.DiscountType)
	}

	// Status filter: 1=active, 2=expired, 3=upcoming
	if f.Status != nil {
		now := time.Now().UTC()
		switch *f.Status {
		case 1: // Active: valid_from <= now <= valid_to
			where = append(where, fmt.Sprintf("valid_from <= $%d AND valid_to >= $%d", len(args)+1, len(args)+2))
			args = append(args, now, now)
		case 2: // Expired: valid_to < now
			where = append(where, fmt.Sprintf("valid_to < $%d", len(args)+1))
			args = append(args, now)
		case 3: // Upcoming: valid_from > now
			where = append(where, fmt.Sprintf("valid_from > $%d", len(args)+1))
			args = append(args, now)
		}
	}

	// Overlap filter: find coupons valid during a date range
	// Coupon overlaps with range if: coupon.valid_from <= range_end AND coupon.valid_to >= range_start
	if f.ValidDuringStart != nil && f.ValidDuringEnd != nil {
		where = append(where, fmt.Sprintf("valid_from <= $%d AND valid_to >= $%d", len(args)+1, len(args)+2))
		args = append(args, *f.ValidDuringEnd, *f.ValidDuringStart)
	}

	if f.Code != nil && *f.Code != "" {
		add("LOWER(code) LIKE LOWER", "%"+*f.Code+"%")
	}

	// WHERE clause
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// OrderBy validation
	allowedOrder := map[string]bool{
		"code":             true,
		"discount":         true,
		"discount_type":    true,
		"max_discount":     true,
		"min_order_amount": true,
		"valid_from":       true,
		"valid_to":         true,
		"created_at":       true,
	}

	orderBy := f.OrderBy
	if orderBy == "" || !allowedOrder[orderBy] {
		orderBy = "created_at"
	}

	orderDir := strings.ToUpper(f.OrderDirection)
	if orderDir != "ASC" && orderDir != "DESC" {
		orderDir = "DESC"
	}

	// Pagination
	limit := f.Limit
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	// Count Query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM coupons %s", whereSQL)
	var total int64
	if err := db.db.DB.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, Error.Wrap(err)
	}

	// Main Query - conditionally add LIMIT/OFFSET only when pagination is needed
	baseQuery := fmt.Sprintf(`
		SELECT code, discount, discount_type, max_discount, min_order_amount,
		       valid_from, valid_to, created_at
		FROM coupons
		%s
		ORDER BY %s %s
	`, whereSQL, orderBy, orderDir)

	var query string
	var queryArgs []interface{}

	if limit > 0 {
		// Add pagination
		query = baseQuery + fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
		queryArgs = append(args, limit, offset)
	} else {
		// No pagination - return all records
		query = baseQuery
		queryArgs = args
	}

	rows, err := db.db.DB.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	defer rows.Close()

	var coupons []billing.Coupons
	for rows.Next() {
		var c billing.Coupons
		if err := rows.Scan(
			&c.Code, &c.Discount, &c.DiscountType,
			&c.MaxDiscount, &c.MinOrderAmount,
			&c.ValidFrom, &c.ValidTo, &c.CreatedAt,
		); err != nil {
			return nil, 0, Error.Wrap(err)
		}
		coupons = append(coupons, c)
	}

	return coupons, total, rows.Err()
}

func (db billingDB) GetCouponStats(ctx context.Context) (stats billing.CouponStats, err error) {
	defer mon.Task()(&ctx)(&err)

	now := time.Now().UTC()

	// Single query to get all counts efficiently
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE valid_from <= $1 AND valid_to >= $1) as active,
			COUNT(*) FILTER (WHERE valid_to < $1) as expired,
			COUNT(*) FILTER (WHERE valid_from > $1) as upcoming
		FROM coupons
	`

	err = db.db.DB.QueryRowContext(ctx, query, now).Scan(
		&stats.Total,
		&stats.Active,
		&stats.Expired,
		&stats.Upcoming,
	)
	if err != nil {
		return billing.CouponStats{}, Error.Wrap(err)
	}

	return stats, nil
}

func (db billingDB) GetActiveCoupons(ctx context.Context) (coupons []billing.Coupons, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxCoupons, err := db.db.All_Coupon_By_ValidFrom_LessOrEqual_And_ValidTo_GreaterOrEqual(ctx,
		dbx.Coupon_ValidFrom(time.Now().UTC()), dbx.Coupon_ValidTo(time.Now().UTC()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	coupons, err = convertSlice(dbxCoupons, fromDBXCoupon)
	return coupons, Error.Wrap(err)
}

func (db billingDB) GetCouponByCode(ctx context.Context, code string) (coupon *billing.Coupons, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxCoupon, err := db.db.Get_Coupon_By_Code(ctx, dbx.Coupon_Code(code))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	c, err := fromDBXCoupon(dbxCoupon)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &c, nil
}

func (db billingDB) CreateCoupon(ctx context.Context, coupon billing.Coupons) (createdCoupon *billing.Coupons, err error) {
	defer mon.Task()(&ctx)(&err)

	// Check if coupon already exists
	existing, err := db.db.Get_Coupon_By_Code(ctx, dbx.Coupon_Code(coupon.Code))
	if err == nil && existing != nil {
		return nil, Error.New("coupon with code %s already exists", coupon.Code)
	}

	// Create new coupon
	dbxCoupon, err := db.db.Create_Coupon(ctx,
		dbx.Coupon_Code(coupon.Code),
		dbx.Coupon_Discount(coupon.Discount),
		dbx.Coupon_DiscountType(coupon.DiscountType),
		dbx.Coupon_MaxDiscount(coupon.MaxDiscount),
		dbx.Coupon_MinOrderAmount(coupon.MinOrderAmount),
		dbx.Coupon_ValidFrom(coupon.ValidFrom),
		dbx.Coupon_ValidTo(coupon.ValidTo),
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	c, err := fromDBXCoupon(dbxCoupon)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &c, nil
}

func (db billingDB) UpdateCoupon(ctx context.Context, code string, coupon billing.Coupons) (updatedCoupon *billing.Coupons, err error) {
	defer mon.Task()(&ctx)(&err)

	// Check if coupon exists
	_, err = db.db.Get_Coupon_By_Code(ctx, dbx.Coupon_Code(code))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Update coupon
	updateFields := dbx.Coupon_Update_Fields{
		Discount:       dbx.Coupon_Discount(coupon.Discount),
		DiscountType:   dbx.Coupon_DiscountType(coupon.DiscountType),
		MaxDiscount:    dbx.Coupon_MaxDiscount(coupon.MaxDiscount),
		MinOrderAmount: dbx.Coupon_MinOrderAmount(coupon.MinOrderAmount),
		ValidFrom:      dbx.Coupon_ValidFrom(coupon.ValidFrom),
		ValidTo:        dbx.Coupon_ValidTo(coupon.ValidTo),
	}

	dbxCoupon, err := db.db.Update_Coupon_By_Code(ctx,
		dbx.Coupon_Code(code),
		updateFields,
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	c, err := fromDBXCoupon(dbxCoupon)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &c, nil
}

func (db billingDB) DeleteCoupon(ctx context.Context, code string) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Check if coupon exists
	_, err = db.db.Get_Coupon_By_Code(ctx, dbx.Coupon_Code(code))
	if err != nil {
		return Error.Wrap(err)
	}

	// Delete coupon using raw SQL (dbx doesn't have Delete_Coupon method)
	_, err = db.db.DB.ExecContext(ctx, "DELETE FROM coupons WHERE code = $1", code)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

func (db billingDB) FailPendingInvoiceTokenPayments(ctx context.Context, txIDs ...int64) (err error) {
	defer mon.Task()(&ctx)(&err)

	for _, txID := range txIDs {
		dbxTX, err := db.db.Get_BillingTransaction_By_Id(ctx, dbx.BillingTransaction_Id(txID))
		if err != nil {
			return Error.Wrap(err)
		}

		userID, err := uuid.FromBytes(dbxTX.UserId)
		if err != nil {
			return Error.New("Unable to get user ID for transaction: %v %v", txID, err)
		}
		oldBalance, err := db.GetBalance(ctx, userID)
		if err != nil {
			return Error.New("Unable to get user balance for ID: %v %v", userID, err)
		}
		err = db.db.WithTx(ctx, func(ctx context.Context, tx *dbx.Tx) error {
			err = db.db.UpdateNoReturn_BillingTransaction_By_Id_And_Status(ctx, dbx.BillingTransaction_Id(txID),
				dbx.BillingTransaction_Status(billing.TransactionStatusPending),
				dbx.BillingTransaction_Update_Fields{
					Status: dbx.BillingTransaction_Status(billing.TransactionStatusFailed),
				})
			if err != nil {
				return Error.Wrap(err)
			}
			// refund the pending charge. dbx amount is negative.
			return updateBalance(ctx, tx, userID, oldBalance, currency.AmountFromBaseUnits(oldBalance.BaseUnits()-dbxTX.Amount, currency.USDollarsMicro))
		})
		if err != nil {
			return Error.New("Unable to transition token invoice payment to failed state for transaction: %v %v", txID, err)
		}
	}
	return nil
}

func (db billingDB) CompletePendingInvoiceTokenPayments(ctx context.Context, txIDs ...int64) (err error) {
	defer mon.Task()(&ctx)(&err)

	for _, txID := range txIDs {
		err = db.db.UpdateNoReturn_BillingTransaction_By_Id_And_Status(ctx, dbx.BillingTransaction_Id(txID),
			dbx.BillingTransaction_Status(billing.TransactionStatusPending),
			dbx.BillingTransaction_Update_Fields{
				Status: dbx.BillingTransaction_Status(billing.TransactionStatusCompleted),
			})
		if err != nil {
			return Error.Wrap(err)
		}
	}
	return nil
}

func (db billingDB) UpdateMetadata(ctx context.Context, txID int64, newMetadata []byte) (err error) {

	dbxTX, err := db.db.Get_BillingTransaction_Metadata_By_Id(ctx, dbx.BillingTransaction_Id(txID))
	if err != nil {
		return Error.Wrap(err)
	}

	updatedMetadata, err := updateMetadata(dbxTX.Metadata, newMetadata)
	if err != nil {
		return Error.Wrap(err)
	}

	return db.db.UpdateNoReturn_BillingTransaction_By_Id_And_Status(ctx, dbx.BillingTransaction_Id(txID),
		dbx.BillingTransaction_Status(billing.TransactionStatusPending),
		dbx.BillingTransaction_Update_Fields{
			Metadata: dbx.BillingTransaction_Metadata(updatedMetadata),
		})
}

func (db billingDB) LastTransaction(ctx context.Context, txSource string, txType billing.TransactionType) (_ time.Time, metadata []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	lastTransaction, err := db.db.First_BillingTransaction_By_Source_And_Type_OrderBy_Desc_CreatedAt(
		ctx,
		dbx.BillingTransaction_Source(txSource),
		dbx.BillingTransaction_Type(string(txType)))

	if err != nil {
		return time.Time{}, nil, Error.Wrap(err)
	}

	if lastTransaction == nil {
		return time.Time{}, nil, billing.ErrNoTransactions
	}

	return lastTransaction.Timestamp, lastTransaction.Metadata, nil
}

func (db billingDB) List(ctx context.Context, userID uuid.UUID) (txs []billing.Transaction, err error) {
	defer mon.Task()(&ctx)(&err)
	dbxTXs, err := db.db.All_BillingTransaction_By_UserId_OrderBy_Desc_Timestamp(ctx,
		dbx.BillingTransaction_UserId(userID[:]))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	txs, err = convertSlice(dbxTXs, fromDBXBillingTransaction)
	return txs, Error.Wrap(err)
}

// boris
func (db billingDB) Lists(ctx context.Context, userID uuid.UUID) (txs []billing.Transactions, err error) {
	defer mon.Task()(&ctx)(&err)
	dbxTXs, err := db.db.All_BillingTransaction_By_UserId_OrderBy_Desc_Timestamp(ctx,
		dbx.BillingTransaction_UserId(userID[:]))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	txs, err = convertSlice(dbxTXs, fromDBXBillingTransactions)
	return txs, Error.Wrap(err)
}

func (db billingDB) ListSource(ctx context.Context, userID uuid.UUID, txSource string) (txs []billing.Transaction, err error) {
	defer mon.Task()(&ctx)(&err)
	dbxTXs, err := db.db.All_BillingTransaction_By_UserId_And_Source_OrderBy_Desc_Timestamp(ctx,
		dbx.BillingTransaction_UserId(userID[:]),
		dbx.BillingTransaction_Source(txSource))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	txs, err = convertSlice(dbxTXs, fromDBXBillingTransaction)
	return txs, Error.Wrap(err)
}

func (db billingDB) GetBalance(ctx context.Context, userID uuid.UUID) (_ currency.Amount, err error) {
	defer mon.Task()(&ctx)(&err)
	dbxBilling, err := db.db.Get_BillingBalance_Balance_By_UserId(ctx,
		dbx.BillingBalance_UserId(userID[:]))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return currency.USDollarsMicro.Zero(), nil
		}
		return currency.USDollarsMicro.Zero(), Error.Wrap(err)
	}

	return currency.AmountFromBaseUnits(dbxBilling.Balance, currency.USDollarsMicro), nil
}

// boris
func fromDBXBillingTransactions(dbxTX *dbx.BillingTransaction) (billing.Transactions, error) {
	userID, err := uuid.FromBytes(dbxTX.UserId)
	if err != nil {
		return billing.Transactions{}, errs.Wrap(err)
	}
	return billing.Transactions{
		ID:          dbxTX.Id,
		UserID:      userID,
		Amount:      float64(dbxTX.Amount),
		Description: dbxTX.Description,
		Source:      dbxTX.Source,
		Status:      billing.TransactionStatus(dbxTX.Status),
		Type:        billing.TransactionType(dbxTX.Type),
		Metadata:    dbxTX.Metadata,
		Timestamp:   dbxTX.Timestamp,
		CreatedAt:   dbxTX.CreatedAt,
		PlanID:      dbxTX.PlanId,
	}, nil
}

// fromDBXPaymentPlans converts *dbx.PaymentPlans to *billing.PaymentPlans.
func fromDBXPaymentPlans(dbxPlan *dbx.PaymentPlans) (billing.PaymentPlans, error) {
	var benefit []string
	err := json.Unmarshal(dbxPlan.Benefit, &benefit)
	if err != nil {
		return billing.PaymentPlans{}, err
	}

	return billing.PaymentPlans{
		ID:           dbxPlan.Id,
		Name:         dbxPlan.Name,
		Storage:      dbxPlan.Storage,
		Bandwidth:    dbxPlan.Bandwidth,
		Price:        dbxPlan.Price,
		Validity:     dbxPlan.Validity,
		ValidityUnit: dbxPlan.ValidityUnit,
		Benefit:      benefit,
		Group:        dbxPlan.Group,
	}, nil
}

func fromDBXCoupon(dbxCoupon *dbx.Coupon) (billing.Coupons, error) {
	return billing.Coupons{
		Code:           dbxCoupon.Code,
		Discount:       dbxCoupon.Discount,
		DiscountType:   dbxCoupon.DiscountType,
		MaxDiscount:    dbxCoupon.MaxDiscount,
		MinOrderAmount: dbxCoupon.MinOrderAmount,
		ValidFrom:      dbxCoupon.ValidFrom,
		ValidTo:        dbxCoupon.ValidTo,
		CreatedAt:      dbxCoupon.CreatedAt,
	}, nil
}

// fromDBXBillingTransaction converts *dbx.BillingTransaction to *billing.Transaction.
func fromDBXBillingTransaction(dbxTX *dbx.BillingTransaction) (billing.Transaction, error) {
	userID, err := uuid.FromBytes(dbxTX.UserId)
	if err != nil {
		return billing.Transaction{}, errs.Wrap(err)
	}
	return billing.Transaction{
		ID:          dbxTX.Id,
		UserID:      userID,
		Amount:      currency.AmountFromBaseUnits(dbxTX.Amount, currency.USDollarsMicro),
		Description: dbxTX.Description,
		Source:      dbxTX.Source,
		Status:      billing.TransactionStatus(dbxTX.Status),
		Type:        billing.TransactionType(dbxTX.Type),
		Metadata:    dbxTX.Metadata,
		Timestamp:   dbxTX.Timestamp,
		CreatedAt:   dbxTX.CreatedAt,
	}, nil
}

func updateMetadata(oldMetaData []byte, newMetaData []byte) ([]byte, error) {
	var updatedMetadata map[string]interface{}

	err := json.Unmarshal(oldMetaData, &updatedMetadata)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(handleMetaDataZeroValue(newMetaData), &updatedMetadata)
	if err != nil {
		return nil, err
	}

	return json.Marshal(updatedMetadata)
}

func handleMetaDataZeroValue(metaData []byte) []byte {
	if metaData != nil {
		return metaData
	}
	return []byte(`{}`)
}
