// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package piecetracker

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/rangedloop"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	mud.Provide[*Observer](ball, NewObserver)
	mud.Implementation[[]rangedloop.Observer, *Observer](ball)
	config.RegisterConfig[Config](ball, "piece-tracker")
}
