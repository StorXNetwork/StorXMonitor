// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package profiler

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module registers all the possible components for the profiler instance.
func Module(ball *mud.Ball) {
	mud.Provide[*Profiler](ball, NewProfiler)
	config.RegisterConfig[Config](ball, "profiler")
}
