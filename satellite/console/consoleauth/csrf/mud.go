// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package csrf

import (
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	mud.Provide[*Service](ball, NewService)
}
