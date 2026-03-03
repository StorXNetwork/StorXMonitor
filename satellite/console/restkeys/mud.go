// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package restkeys

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/oidc"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	config.RegisterConfig[Config](ball, "console-restkeys")
	mud.Provide[*Service](ball, func(db oidc.OAuthTokens, config Config) *Service {
		return NewService(db, config.DefaultExpiration)
	})
}
