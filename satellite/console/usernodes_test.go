// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testrand"
)

func TestParseNodeID(t *testing.T) {
	id := testrand.NodeID()

	parsed, err := console.ParseNodeID(id.String())
	require.NoError(t, err)
	require.Equal(t, id, parsed)

	parsed, err = console.ParseNodeID(hex.EncodeToString(id.Bytes()))
	require.NoError(t, err)
	require.Equal(t, id, parsed)

	_, err = console.ParseNodeID("not-a-node-id")
	require.True(t, console.ErrUserNodeInvalid.Has(err))
}

func TestOwnNodesPlacementConstant(t *testing.T) {
	require.Equal(t, storxnetwork.PlacementConstraint(250), nodeselection.OwnNodesPlacement)
}
