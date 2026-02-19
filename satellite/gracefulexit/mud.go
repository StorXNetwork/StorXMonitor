// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package gracefulexit

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module definition.
func Module(ball *mud.Ball) {
	mud.Provide[*Endpoint](ball, NewEndpoint)
	config.RegisterConfig[Config](ball, "graceful-exit")
}
