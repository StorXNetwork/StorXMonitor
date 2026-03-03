// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package audit

import (
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/rpc"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/orders"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {

	mud.Provide[*Verifier](ball, func(log *zap.Logger, metabase *metabase.DB, dialer rpc.Dialer, overlay *overlay.Service, containment Containment, orders *orders.Service, id *identity.FullIdentity, cfg Config) *Verifier {
		return NewVerifier(log, metabase, dialer, overlay, containment, orders, id, cfg.MinBytesPerSecond, cfg.MinDownloadTimeout)
	})
	mud.Provide[*Worker](ball, NewWorker)
	mud.Provide[*ReverifyWorker](ball, NewReverifyWorker)
	mud.Provide[*Reverifier](ball, NewReverifier)

	mud.Provide[*DBReporter](ball, NewReporter)
	mud.Provide[NoReport](ball, func() NoReport {
		return NoReport{}
	})
	mud.RegisterInterfaceImplementation[Reporter, *DBReporter](ball)

	mud.Provide[*NoContainment](ball, func() *NoContainment {
		return &NoContainment{}
	})
	mud.RegisterInterfaceImplementation[Containment, WrappedContainment](ball)

	mud.Provide[*RunOnce](ball, NewRunOnce)
	config.RegisterConfig[Config](ball, "audit")
	config.RegisterConfig[RunOnceConfig](ball, "audit")

}
