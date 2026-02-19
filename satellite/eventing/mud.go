// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package eventing

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module provides the changestream module.
func Module(ball *mud.Ball) {
	mud.Provide[*Service](ball, NewService)
	config.RegisterConfig[Config](ball, "change-stream")

	mud.Provide[*CachedPublicProjectIDs](ball, NewCachedPublicProjectIDs)
	mud.RegisterInterfaceImplementation[PublicProjectIDGetter, *CachedPublicProjectIDs](ball)

	mud.Provide[*ConfigCache](ball, NewConfigCache)
	mud.RegisterInterfaceImplementation[BucketNotificationConfigGetter, *ConfigCache](ball)
}
