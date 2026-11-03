// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package satellitedb

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/gateway"
)

var _ gateway.DB = (*paymentGatewayDB)(nil)

type paymentGatewayDB struct {
	db *satelliteDB
}

func (db *paymentGatewayDB) Customers() gateway.CustomersDB {
	return &paymentCustomers{db: db.db}
}

func (db *paymentGatewayDB) Methods() gateway.MethodsDB {
	return &paymentMethods{db: db.db}
}

func (db *paymentGatewayDB) Attempts() gateway.AttemptsDB {
	return &paymentAttempts{db: db.db}
}

func (db *paymentGatewayDB) Subscriptions() gateway.SubscriptionsDB {
	return &paymentSubscriptions{db: db.db}
}

func (db *paymentGatewayDB) Events() gateway.EventsDB {
	return &paymentEvents{db: db.db}
}
