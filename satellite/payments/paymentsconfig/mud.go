// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package paymentsconfig

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/stripe"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module definition.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "payments")
	mud.View[Config, stripe.Config](ball, func(c Config) stripe.Config {
		return c.StripeCoinPayments
	})
}
