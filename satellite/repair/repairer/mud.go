// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package repairer

import (
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/rpc"
	"github.com/StorXNetwork/common/signing"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/StorXMonitor/satellite/orders"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/checker"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module definition.
func Module(ball *mud.Ball) {
	mud.Provide[*ECRepairer](ball, func(dialer rpc.Dialer, satelliteSignee signing.Signee, cfg Config) *ECRepairer {
		return NewECRepairer(dialer, satelliteSignee, cfg.DialTimeout, cfg.DownloadTimeout, cfg.InMemoryRepair, cfg.InMemoryUpload, cfg.DownloadLongTail)
	})
	mud.Provide[*SegmentRepairer](ball, func(log *zap.Logger, metabase *metabase.DB, orders *orders.Service, overlay *overlay.Service, reporter audit.Reporter, ecRepairer *ECRepairer, placements nodeselection.PlacementDefinitions, config Config, checkerConfig checker.Config) (*SegmentRepairer, error) {
		return NewSegmentRepairer(log, metabase, orders, overlay, reporter, ecRepairer, placements, checkerConfig.RepairThresholdOverrides, checkerConfig.RepairTargetOverrides, config)
	})
	config.RegisterConfig[Config](ball, "repairer")
	mud.Provide[*Service](ball, NewService)

}
