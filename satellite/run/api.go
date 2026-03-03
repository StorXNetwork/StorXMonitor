// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/orders"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Api is a subcommand to start only API services.
type Api struct {
}

// GetSelector implements mud.ComponentSelectorProvider.
func (a *Api) GetSelector(ball *mud.Ball) mud.ComponentSelector {
	return mud.Or(
		Observability(ball),
		mud.Select[*satellite.EndpointRegistration](ball),
		mud.Select[*orders.Chore](ball),
	)
}
