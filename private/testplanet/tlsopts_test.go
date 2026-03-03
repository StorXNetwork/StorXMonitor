// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package testplanet_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/private/testplanet"
	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/identity/testidentity"
	"github.com/StorXNetwork/common/peertls/tlsopts"
	"github.com/StorXNetwork/common/rpc"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testcontext"
)

func TestOptions_ServerOption_Peer_CA_Whitelist(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 0, StorageNodeCount: 2, UplinkCount: 0,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sn := planet.StorageNodes[1]
		testidentity.CompleteIdentityVersionsTest(t, func(t *testing.T, version storxnetwork.IDVersion, ident *identity.FullIdentity) {
			tlsOptions, err := tlsopts.NewOptions(ident, tlsopts.Config{
				PeerIDVersions: "*",
			}, nil)
			require.NoError(t, err)

			dialer := rpc.NewDefaultDialer(tlsOptions)

			conn, err := dialer.DialNodeURL(ctx, sn.NodeURL())
			assert.NotNil(t, conn)
			assert.NoError(t, err)

			assert.NoError(t, conn.Close())
		})
	})
}
