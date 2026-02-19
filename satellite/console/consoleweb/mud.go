// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "console")
	mud.View[Config, console.Config](ball, func(c Config) console.Config {
		return c.Config
	})
}
