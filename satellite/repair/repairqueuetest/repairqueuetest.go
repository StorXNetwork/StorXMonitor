// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package repairqueuetest

import (
	"testing"

	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/jobq/jobqtest"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/queue"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
)

// Run runs the given test function first with the SQL-based repair queue and
// then with the jobq repair queue.
func Run(t *testing.T, f func(ctx *testcontext.Context, t *testing.T, rq queue.RepairQueue)) {
	t.Run("sql-repair-queue", func(t *testing.T) {
		satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
			f(ctx, t, db.RepairQueue())
		})
	})
	t.Run("jobq-repair-queue", func(t *testing.T) {
		jobqtest.Run(t, f)
	})
}
