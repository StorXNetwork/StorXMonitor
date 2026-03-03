// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package jobq

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud Module definition.
func Module(ball *mud.Ball) {
	mud.Provide[*RepairJobQueue](ball, OpenJobQueue)
	config.RegisterConfig[Config](ball, "jobq")

}
