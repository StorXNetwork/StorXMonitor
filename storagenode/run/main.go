// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package root

import (
	_ "github.com/StorXNetwork/StorXMonitor/private/version" // This attaches version information during release builds.
	"github.com/StorXNetwork/StorXMonitor/shared/modular/cli"
)

// Main is the main entrypoint. Can be called from real `main` package after importing optional modules.
func Main() {
	cli.Run(Module)
}
