// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
		_, err := tx.Create_BillingTransaction(ctx,
			dbx.BillingTransaction_UserId(billingTX.UserID[:]),
			dbx.BillingTransaction_Amount(int64(amount)),
			dbx.BillingTransaction_Currency("USD"),
			dbx.BillingTransaction_Description(billingTX.Description),
			dbx.BillingTransaction_Source(billingTX.Source),
			dbx.BillingTransaction_Status(string(billingTX.Status)),
			dbx.BillingTransaction_Type(string(billingTX.Type)),
			dbx.BillingTransaction_Metadata(handleMetaDataZeroValue(billingTX.Metadata)),
			dbx.BillingTransaction_Timestamp(billingTX.Timestamp))
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
