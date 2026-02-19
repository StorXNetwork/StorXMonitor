// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package eventkit

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module registers the Eventkit module.
func Module(ball *mud.Ball) {
	mud.Provide[*Eventkit](ball, NewEventkit)
	config.RegisterConfig[Config](ball, "eventkit")
}
