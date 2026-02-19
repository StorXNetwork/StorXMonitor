// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package bloomfilter

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/rangedloop"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module provides dependency injection configuration for garbage collection bloom filter components.
func Module(ball *mud.Ball) {

	config.RegisterConfig[Config](ball, "garbage-collection-bf")

	mud.Provide[*SyncObserver](ball, NewSyncObserver)
	mud.Implementation[[]rangedloop.Observer, *SyncObserver](ball)
	mud.Tag[*SyncObserver, mud.Optional](ball, mud.Optional{})

	mud.Provide[*SyncObserverV2](ball, NewSyncObserverV2)
	mud.Implementation[[]rangedloop.Observer, *SyncObserverV2](ball)
	mud.Tag[*SyncObserverV2, mud.Optional](ball, mud.Optional{})

	mud.Provide[*Observer](ball, NewObserver)
	mud.Implementation[[]rangedloop.Observer, *Observer](ball)
	mud.Tag[*Observer, mud.Optional](ball, mud.Optional{})
}
