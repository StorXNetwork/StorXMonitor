// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package tracing

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud Module definition for tracing.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "tracing")
	mud.Provide[*Tracing](ball, NewTracing)
}
