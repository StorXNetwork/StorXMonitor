// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package overlay

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "overlay")
	mud.View[Config, NodeSelectionConfig](ball, func(c Config) NodeSelectionConfig {
		return c.Node
	})
}
