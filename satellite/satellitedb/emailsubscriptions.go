// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"time"

	"github.com/zeebo/errs"

	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that emailSubscriptions implements console.EmailSubscriptions.
var _ console.EmailSubscriptions = (*emailSubscriptions)(nil)

// emailSubscriptions is an implementation of EmailSubscriptions interface repository using spacemonkeygo/dbx orm.
type emailSubscriptions struct {
	db *satelliteDB
}

// GetByEmail is a method for querying email subscription by email.
func (es *emailSubscriptions) GetByEmail(ctx context.Context, email string) (_ *console.EmailSubscription, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxSubscription, err := es.db.Get_EmailSubscription_By_Email(ctx, dbx.EmailSubscription_Email(email))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, Error.Wrap(err)
	}

	return emailSubscriptionFromDBX(dbxSubscription)
}

// Subscribe creates or updates an email subscription to subscribed status.
func (es *emailSubscriptions) Subscribe(ctx context.Context, email string) (_ *console.EmailSubscription, err error) {
	defer mon.Task()(&ctx)(&err)

	now := time.Now()

	// Check if subscription exists
	existing, err := es.GetByEmail(ctx, email)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if existing != nil {
		// Update existing subscription: set status to 1 and clear unsubscribed_at
		status := 1
		dbxSubscription, err := es.db.Update_EmailSubscription_By_Email(ctx,
			dbx.EmailSubscription_Email(email),
			dbx.EmailSubscription_Update_Fields{
				Status:         dbx.EmailSubscription_Status(status),
				UnsubscribedAt: dbx.EmailSubscription_UnsubscribedAt_Null(),
				UpdatedAt:      dbx.EmailSubscription_UpdatedAt(now),
			},
		)
		if err != nil {
			return nil, Error.Wrap(err)
		}

		return emailSubscriptionFromDBX(dbxSubscription)
	}

	// Create new subscription
	dbxSubscription, err := es.db.Create_EmailSubscription(ctx,
		dbx.EmailSubscription_Email(email),
		dbx.EmailSubscription_UpdatedAt(now),
		dbx.EmailSubscription_Create_Fields{
			Status: dbx.EmailSubscription_Status(1),
		},
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return emailSubscriptionFromDBX(dbxSubscription)
}

// Unsubscribe updates an email subscription to unsubscribed status.
func (es *emailSubscriptions) Unsubscribe(ctx context.Context, email string) (err error) {
	defer mon.Task()(&ctx)(&err)

	now := time.Now()
	status := 0

	_, err = es.db.Update_EmailSubscription_By_Email(ctx,
		dbx.EmailSubscription_Email(email),
		dbx.EmailSubscription_Update_Fields{
			Status:         dbx.EmailSubscription_Status(status),
			UnsubscribedAt: dbx.EmailSubscription_UnsubscribedAt(now),
			UpdatedAt:      dbx.EmailSubscription_UpdatedAt(now),
		},
	)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// emailSubscriptionFromDBX converts dbx.EmailSubscription to console.EmailSubscription.
func emailSubscriptionFromDBX(dbxSubscription *dbx.EmailSubscription) (*console.EmailSubscription, error) {
	subscription := &console.EmailSubscription{
		Email:     dbxSubscription.Email,
		Status:    dbxSubscription.Status,
		CreatedAt: dbxSubscription.CreatedAt,
		UpdatedAt: dbxSubscription.UpdatedAt,
	}

	if dbxSubscription.UnsubscribedAt != nil {
		subscription.UnsubscribedAt = dbxSubscription.UnsubscribedAt
	}

	return subscription, nil
}
