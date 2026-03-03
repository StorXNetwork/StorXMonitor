// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package repaircsv

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/queue"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud Module definition.
func Module(ball *mud.Ball) {
	mud.Provide[*Queue](ball, NewQueue)
	config.RegisterConfig[Config](ball, "csv")
	mud.RegisterInterfaceImplementation[queue.Consumer, *Queue](ball)
}
