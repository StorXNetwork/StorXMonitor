// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package logger

import (
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module that provides a logger.
func Module(ball *mud.Ball) {
	mud.Provide[*zap.Config](ball, NewZapConfig)
	mud.Provide[RootLogger](ball, NewRootLogger)
	mud.Factory[*zap.Logger](ball, NewLogger)
	config.RegisterConfig[Config](ball, "log")
}
