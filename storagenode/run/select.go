// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	"github.com/StorXNetwork/StorXMonitor/shared/debug"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/profiler"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/tracing"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/StorXMonitor/storagenode"
	"github.com/StorXNetwork/StorXMonitor/storagenode/bandwidth"
	"github.com/StorXNetwork/StorXMonitor/storagenode/contact"
	"github.com/StorXNetwork/StorXMonitor/storagenode/monitor"
	"github.com/StorXNetwork/StorXMonitor/storagenode/nodestats"
	"github.com/StorXNetwork/StorXMonitor/storagenode/orders"
	"github.com/StorXNetwork/StorXMonitor/storagenode/piecestore"
	"github.com/StorXNetwork/StorXMonitor/storagenode/reputation"
	"github.com/StorXNetwork/StorXMonitor/storagenode/retain"
)

// Select is a subcommand to start select specific version of storagenode.
type Select struct {
}

// GetSelector implements mud.ComponentSelectorProvider.
func (a *Select) GetSelector(ball *mud.Ball) mud.ComponentSelector {
	mud.ReplaceDependency[piecestore.PieceBackend, *piecestore.HashStoreBackend](ball)
	mud.DisableImplementation[monitor.DiskVerification](ball)
	mud.Tag[*retain.Service, mud.Optional](ball, mud.Optional{})
	mud.Tag[bandwidth.Writer, mud.Optional](ball, mud.Optional{})
	return mud.Or(
		mud.Select[debug.Wrapper](ball),
		mud.Select[*profiler.Profiler](ball),
		mud.Select[*tracing.Tracing](ball),
		mud.Select[*storagenode.EndpointRegistration](ball),
		mud.Select[*contact.Endpoint](ball),
		mud.Select[*contact.Chore](ball),
		mud.Select[*orders.Service](ball),
		mud.Select[*reputation.Service](ball),
		mud.Select[*reputation.Chore](ball),
		mud.Select[*nodestats.Cache](ball),
	)
}
