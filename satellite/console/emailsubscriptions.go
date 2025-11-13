// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"time"
)

// EmailSubscription represents a newsletter email subscription.
type EmailSubscription struct {
	Email          string
	Status         int
	UnsubscribedAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EmailSubscriptions exposes methods to manage EmailSubscription table in database.
//
// architecture: Database
type EmailSubscriptions interface {
	// GetByEmail is a method for querying email subscription by email.
	GetByEmail(ctx context.Context, email string) (*EmailSubscription, error)
	// Subscribe creates or updates an email subscription to subscribed status.
	Subscribe(ctx context.Context, email string) (*EmailSubscription, error)
	// Unsubscribe updates an email subscription to unsubscribed status.
	Unsubscribe(ctx context.Context, email string) error
}
