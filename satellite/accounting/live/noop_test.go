// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package live_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/memory"
	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/StorXMonitor/private/testplanet"
	"github.com/StorXNetwork/StorXMonitor/satellite"
)

func TestNoopCache(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.LiveAccounting.StorageBackend = "noop"
			},
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		satellite := planet.Satellites[0]
		data := testrand.Bytes(memory.Size(100+testrand.Intn(500)) * memory.KiB)

		err := planet.Uplinks[0].Upload(ctx, satellite, "testbucket", "object", data)
		require.NoError(t, err)

		downloaded, err := planet.Uplinks[0].Download(ctx, satellite, "testbucket", "object")
		require.NoError(t, err)
		require.Equal(t, data, downloaded)
	})
}
