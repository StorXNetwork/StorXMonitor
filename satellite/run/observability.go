// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	"github.com/StorXNetwork/StorXMonitor/shared/debug"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/eventkit"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/profiler"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/tracing"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Observability implements mud.ComponentSelectorProvider. It selects all standard observability modules.
func Observability(ball *mud.Ball) mud.ComponentSelector {
	return mud.Or(
		mud.Select[debug.Wrapper](ball),
		mud.Select[*tracing.Tracing](ball),
		mud.Select[*eventkit.Eventkit](ball),
		mud.Select[*profiler.Profiler](ball),
	)
}
