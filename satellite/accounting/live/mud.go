// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package live

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	mud.Provide[accounting.Cache](ball, OpenCache)
	config.RegisterConfig[Config](ball, "live-accounting")
}
