// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package metabasetest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	_ "storj.io/common/dbutil/cockroachutil" // register cockroach driver
	"storj.io/common/testcontext"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/metabasetest"
)

func TestSetup(t *testing.T) {
	metabasetest.Run(t, func(ctx *testcontext.Context, t *testing.T, db *metabase.DB) {
		err := db.Ping(ctx)
		require.NoError(t, err)

		_, err = db.TestingGetState(ctx)
		require.NoError(t, err)
	})
}
