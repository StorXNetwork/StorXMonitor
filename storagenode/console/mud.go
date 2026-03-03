// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"net"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/version"
	"github.com/StorXNetwork/StorXMonitor/private/server"
	"github.com/StorXNetwork/StorXMonitor/private/version/checker"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/StorXMonitor/storagenode/bandwidth"
	"github.com/StorXNetwork/StorXMonitor/storagenode/contact"
	"github.com/StorXNetwork/StorXMonitor/storagenode/monitor"
	"github.com/StorXNetwork/StorXMonitor/storagenode/operator"
	"github.com/StorXNetwork/StorXMonitor/storagenode/payouts/estimatedpayouts"
	"github.com/StorXNetwork/StorXMonitor/storagenode/pricing"
	"github.com/StorXNetwork/StorXMonitor/storagenode/reputation"
	"github.com/StorXNetwork/StorXMonitor/storagenode/satellites"
	"github.com/StorXNetwork/StorXMonitor/storagenode/storageusage"
	"github.com/StorXNetwork/StorXMonitor/storagenode/trust"
)

// Module registers the console service dependency injection components.
func Module(ball *mud.Ball) {
	mud.Provide[*Service](ball, func(log *zap.Logger, bandwidth bandwidth.DB, version *checker.Service,
		versionInfo version.Info, trust *trust.Pool,
		reputationDB reputation.DB, storageUsageDB storageusage.DB, pricingDB pricing.DB, satelliteDB satellites.DB,
		pingStats *contact.PingStats, contact *contact.Service, estimation *estimatedpayouts.Service,
		walletFeatures operator.WalletFeatures, quicStats *contact.QUICStats,
		spaceReport monitor.SpaceReport, server *server.Server, config operator.Config) (*Service, error) {

		_, port, _ := net.SplitHostPort(server.Addr().String())
		return NewService(log, bandwidth, version,
			config.Wallet, versionInfo, trust,
			reputationDB, storageUsageDB, pricingDB, satelliteDB,
			pingStats, contact, estimation,
			config.WalletFeatures, port, quicStats,
			spaceReport)
	})
	mud.View[operator.Config, operator.WalletFeatures](ball, func(config operator.Config) operator.WalletFeatures {
		return config.WalletFeatures
	})
}
