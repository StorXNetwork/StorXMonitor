// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	"github.com/StorXNetwork/StorXMonitor/shared/modular"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/cli"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/logger"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/StorXMonitor/storagenode"
)

// Module registers all the possible components for the storagenode instance.
func Module(ball *mud.Ball) {
	logger.Module(ball)
	modular.IdentityModule(ball)
	storagenode.Module(ball)
	mud.Provide[*Setup](ball, NewSetup)
	cli.RegisterSubcommand[*Setup](ball, "setup", "setup storagenode configuration")

	mud.Provide[*Run](ball, func() *Run {
		return &Run{}
	})
	cli.RegisterSubcommand[*Run](ball, "run", "Run storagenode with all the default components.")

	mud.Provide[*Select](ball, func() *Select {
		return &Select{}
	})
	cli.RegisterSubcommand[*Select](ball, "select", "EXPERIMENTAL! (can be removed later). Run storagenode version optimized for select. (NOT RECOMMENDED for public network. No UI, No piecestore compatibility. Risk of losing data)")
}
