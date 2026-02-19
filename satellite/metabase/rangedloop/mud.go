// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package rangedloop

import (
	"time"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {

	mud.Provide[RangeSplitter](ball, NewMetabaseRangeSplitter)
	mud.Provide[*Service](ball, NewService)
	mud.Provide[*LiveCountObserver](ball, func(db *metabase.DB, cfg Config) *LiveCountObserver {
		return NewLiveCountObserver(db, cfg.SuspiciousProcessedRatio, cfg.AsOfSystemInterval)
	})
	mud.Provide[*SegmentsCountValidation](ball, func(log *zap.Logger, db *metabase.DB, cfg Config) *SegmentsCountValidation {
		return NewSegmentsCountValidation(log, db, time.Now().Add(-cfg.SpannerStaleInterval))
	})
	mud.Provide[*RunOnce](ball, NewRunOnce)
	config.RegisterConfig[Config](ball, "ranged-loop")
	mud.RegisterImplementation[[]Observer](ball)

	mud.Implementation[[]Observer, *LiveCountObserver](ball)
	mud.Implementation[[]Observer, *SegmentsCountValidation](ball)
	mud.Tag[*SegmentsCountValidation, mud.Optional](ball, mud.Optional{})

}
