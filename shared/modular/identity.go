// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package modular

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/storxnetwork"
)

// IdentityModule provides identity related components for modular setup.
func IdentityModule(ball *mud.Ball) {
	config.RegisterConfig[identity.Config](ball, "identity")
	mud.Provide[*identity.FullIdentity](ball, func(cfg *identity.Config) (*identity.FullIdentity, error) {
		return cfg.Load()
	})
	mud.View[*identity.FullIdentity, storxnetwork.NodeID](ball, func(fid *identity.FullIdentity) storxnetwork.NodeID {
		return fid.ID
	})
}
