// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/eventing"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// ChangeStream is a subcommand to start only Repairer (worker) service.
type ChangeStream struct {
}

// GetSelector implements mud.ComponentSelectorProvider.
func (a *ChangeStream) GetSelector(ball *mud.Ball) mud.ComponentSelector {
	return mud.Or(
		Observability(ball),
		mud.Select[*eventing.Service](ball))
}
