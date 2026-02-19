// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package contact

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module definition.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "contact")
	mud.Provide[*Service](ball, NewService)
	mud.Provide[*Endpoint](ball, NewEndpoint)
}
