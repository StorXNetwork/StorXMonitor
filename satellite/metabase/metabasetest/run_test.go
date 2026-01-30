// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package metabasetest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/metabasetest"
	_ "github.com/StorXNetwork/StorXMonitor/shared/dbutil/cockroachutil" // register cockroach driver
	"github.com/StorXNetwork/common/testcontext"
)

func TestSetup(t *testing.T) {
	metabasetest.Run(t, func(ctx *testcontext.Context, t *testing.T, db *metabase.DB) {
		err := db.Ping(ctx)
		require.NoError(t, err)

		_, err = db.TestingGetState(ctx)
		require.NoError(t, err)
	})
}
