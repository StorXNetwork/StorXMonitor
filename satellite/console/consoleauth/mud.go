// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleauth

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "console-auth")
	mud.Provide[*Service](ball, NewService)
}
