// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package valdi

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/console/valdi/valdiclient"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "valdi")
	mud.Provide[*Service](ball, NewService)
	mud.View[Config, valdiclient.Config](ball, func(c Config) valdiclient.Config {
		return c.Config
	})
	mud.Tag[*Service](ball, mud.Optional{})
	mud.Tag[*Service](ball, mud.Nullable{})
}
