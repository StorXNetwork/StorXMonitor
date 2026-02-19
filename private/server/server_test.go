// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server_test

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/private/server"
	"github.com/StorXNetwork/StorXMonitor/private/testplanet"
	"github.com/StorXNetwork/common/errs2"
	"github.com/StorXNetwork/common/identity/testidentity"
	"github.com/StorXNetwork/common/peertls/tlsopts"
	"github.com/StorXNetwork/common/rpc"
	_ "github.com/StorXNetwork/common/rpc/quic"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/sync2"
	"github.com/StorXNetwork/common/testcontext"
)

func TestServer(t *testing.T) {
	ctx := testcontext.New(t)
	log := zaptest.NewLogger(t)
	identity := testidentity.MustPregeneratedIdentity(0, storxnetwork.LatestIDVersion())

	host := "127.0.0.1"
	if hostlist := os.Getenv("STORJ_TEST_HOST"); hostlist != "" {
		host, _, _ = strings.Cut(hostlist, ";")
	}

	tlsOptions, err := tlsopts.NewOptions(identity, tlsopts.Config{
		PeerIDVersions: "latest",
	}, nil)
	require.NoError(t, err)

	instance, err := server.New(log.Named("server"), tlsOptions, server.Config{
		Address:          host + ":0",
		PrivateAddress:   host + ":0",
		TCPFastOpen:      true,
		TCPFastOpenQueue: 256,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, instance.Close())
	}()

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	require.Empty(t, sync2.Concurrently(
		func() error {
			err = instance.Run(serverCtx)
			return errs2.IgnoreCanceled(err)
		},
		func() (err error) {
			defer serverCancel()

			dialer := net.Dialer{}
			conn, err := dialer.DialContext(ctx, "tcp", instance.PrivateAddr().String())
			if err != nil {
				return errs.Wrap(err)
			}
			defer func() { err = errs.Combine(err, conn.Close()) }()

			// prefix is too short, but err is ignored on server side
			_, err = conn.Write([]byte("A"))
			if err != nil {
				return errs.Wrap(err)
			}
			return nil
		},
	))
}

func TestDefaultRoute(t *testing.T) {
	ctx := testcontext.New(t)
	log := zaptest.NewLogger(t)
	identity := testidentity.MustPregeneratedIdentity(0, storxnetwork.LatestIDVersion())

	host := "127.0.0.1"
	if hostlist := os.Getenv("STORJ_TEST_HOST"); hostlist != "" {
		host, _, _ = strings.Cut(hostlist, ";")
	}

	tlsOptions, err := tlsopts.NewOptions(identity, tlsopts.Config{
		PeerIDVersions: "latest",
	}, nil)
	require.NoError(t, err)

	instance, err := server.New(log.Named("server"), tlsOptions, server.Config{
		Address:          host + ":0",
		PrivateAddress:   host + ":0",
		TCPFastOpen:      true,
		TCPFastOpenQueue: 256,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, instance.Close())
	}()

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	errors := sync2.Concurrently(
		func() error {
			err = instance.Run(serverCtx)
			return errs2.IgnoreCanceled(err)
		},
		func() (err error) {
			defer serverCancel()

			dialer := net.Dialer{}
			conn, err := dialer.DialContext(ctx, "tcp", instance.PrivateAddr().String())
			if err != nil {
				return errs.Wrap(err)
			}
			defer func() { err = errs.Combine(err, conn.Close()) }()

			_, err = conn.Write([]byte("longer than DRPC prefix"))
			if err != nil {
				return errs.Wrap(err)
			}

			buff := make([]byte, 10)
			_, err = conn.Read(buff)
			if err != nil {
				return errs.New("read is failed: %v", err)
			}
			return nil
		},
	)
	require.Len(t, errors, 1)
	// the exact wrapped error is different on each OS, but the read should be failed (due to a connection close).
	// linux: connection reset by pear
	// windows: An existing connection was forcibly closed by the remote host
	require.ErrorContains(t, errors[0], "read is failed")
}

func TestHybridConnector_Basic(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		dialer := planet.Uplinks[0].Dialer

		dialer.Connector = rpc.NewHybridConnector()

		conn, err := dialer.Connector.DialContext(ctx, dialer.TLSOptions.ClientTLSConfig(sat.ID()), sat.Addr())
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})
}

func TestHybridConnector_QUICOnly(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      0,
		Reconfigure:      testplanet.DisableTCP,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		identity, err := planet.NewIdentity()
		require.NoError(t, err)

		tlsOptions, err := tlsopts.NewOptions(identity, tlsopts.Config{
			PeerIDVersions: strconv.Itoa(int(storxnetwork.LatestIDVersion().Number)),
		}, nil)
		require.NoError(t, err)

		connector := rpc.NewHybridConnector()

		conn, err := connector.DialContext(ctx, tlsOptions.ClientTLSConfig(sat.ID()), sat.Addr())
		require.NoError(t, err)
		require.Equal(t, "udp", conn.LocalAddr().Network())
		require.NoError(t, conn.Close())
	})
}

func TestHybridConnector_TCPOnly(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      0,
		Reconfigure:      testplanet.DisableQUIC,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		identity, err := planet.NewIdentity()
		require.NoError(t, err)

		tlsOptions, err := tlsopts.NewOptions(identity, tlsopts.Config{
			PeerIDVersions: strconv.Itoa(int(storxnetwork.LatestIDVersion().Number)),
		}, nil)
		require.NoError(t, err)

		connector := rpc.NewHybridConnector()

		conn, err := connector.DialContext(ctx, tlsOptions.ClientTLSConfig(sat.ID()), sat.Addr())
		require.NoError(t, err)
		require.Equal(t, "tcp", conn.LocalAddr().Network())
		require.NoError(t, conn.Close())
	})
}

func TestServer_Stats(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount:   1,
		StorageNodeCount: 0,
		UplinkCount:      1,
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]

		require.NoError(t, planet.Uplinks[0].CreateBucket(ctx, sat, "test"))

		count := 0
		sat.API.Server.Stats(func(key monkit.SeriesKey, field string, val float64) {
			t.Log(key, field, val)
			count++
		})

		require.Equal(t, count, 2)
	})
}
