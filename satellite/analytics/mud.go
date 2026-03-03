// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package analytics

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "analytics")
	mud.RegisterInterfaceImplementation[FreezeTracker, *Service](ball)
}
