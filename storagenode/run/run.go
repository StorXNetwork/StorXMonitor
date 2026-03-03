// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	"github.com/StorXNetwork/StorXMonitor/shared/debug"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/tracing"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/StorXMonitor/storagenode"
	"github.com/StorXNetwork/StorXMonitor/storagenode/bandwidth"
	"github.com/StorXNetwork/StorXMonitor/storagenode/console/consoleserver"
	"github.com/StorXNetwork/StorXMonitor/storagenode/contact"
	"github.com/StorXNetwork/StorXMonitor/storagenode/monitor"
	"github.com/StorXNetwork/StorXMonitor/storagenode/orders"
	"github.com/StorXNetwork/StorXMonitor/storagenode/reputation"
	"github.com/StorXNetwork/StorXMonitor/storagenode/retain"
)

// Run is a subcommand to start the regular storagenode.
type Run struct {
}

// GetSelector implements mud.ComponentSelectorProvider.
func (a *Run) GetSelector(ball *mud.Ball) mud.ComponentSelector {
	return mud.Or(
		mud.Select[debug.Wrapper](ball),
		mud.Select[*tracing.Tracing](ball),
		mud.Select[*storagenode.EndpointRegistration](ball),
		mud.Select[*contact.Endpoint](ball),
		mud.Select[*contact.Chore](ball),
		mud.Select[*bandwidth.Service](ball),
		mud.Select[*retain.Service](ball),
		mud.Select[*monitor.Service](ball),
		mud.Select[*orders.Service](ball),
		mud.Select[*reputation.Chore](ball),
		mud.Select[*consoleserver.Server](ball),
	)
}
