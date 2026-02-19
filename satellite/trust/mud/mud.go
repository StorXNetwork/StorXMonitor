// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package trust_mud

// TODO: this package is separated as we have circular dependencies between due to the usage of metainfo.Config.

import (
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/metainfo"
	"github.com/StorXNetwork/StorXMonitor/satellite/trust"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/common/storxnetwork"
)

// Module is a mud Module definition.
func Module(ball *mud.Ball) {
	mud.Provide[*trust.TrustedPeersList](ball, func(logger *zap.Logger, config metainfo.Config) (*trust.TrustedPeersList, error) {
		var uplinks []storxnetwork.NodeID
		for _, u := range config.SuccessTrackerTrustedUplinks {
			nodeID, err := storxnetwork.NodeIDFromString(u)
			if err != nil {
				return nil, errs.Wrap(err)
			}
			uplinks = append(uplinks, nodeID)
		}
		return trust.NewTrustedPeerList(uplinks), nil
	})

}
