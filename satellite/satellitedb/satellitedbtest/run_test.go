// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedbtest_test

import (
	"testing"

	"storj.io/common/testcontext"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
)

func TestDatabase(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
	})
}
