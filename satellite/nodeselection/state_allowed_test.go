// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package nodeselection_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
)

func TestState_SelectAllowedIDs(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	allowed := createRandomNodes(3, "1.0.1", false, true)
	other := createRandomNodes(5, "1.0.2", false, true)
	nodes := joinNodes(allowed, other)

	state := nodeselection.InitState(ctx, nodes, map[storxnetwork.PlacementConstraint]nodeselection.Placement{
		0: {Selector: nodeselection.RandomSelector()},
	})

	allowedIDs := make([]storxnetwork.NodeID, len(allowed))
	for i, n := range allowed {
		allowedIDs[i] = n.ID
	}

	selected, err := state.Select(ctx, storxnetwork.NodeID{}, 0, 2, nil, nil, allowedIDs)
	require.NoError(t, err)
	require.Len(t, selected, 2)

	allowedSet := map[storxnetwork.NodeID]struct{}{}
	for _, id := range allowedIDs {
		allowedSet[id] = struct{}{}
	}
	for _, n := range selected {
		_, ok := allowedSet[n.ID]
		require.True(t, ok, "selected node %s not in allowlist", n.ID)
	}

	// Selecting more than available allowed nodes should fail.
	_, err = state.Select(ctx, testrand.NodeID(), 0, 4, nil, nil, allowedIDs)
	require.True(t, nodeselection.ErrNotEnoughNodes.Has(err))
}

func TestState_SelectAllowedIDs_OwnNodesSameSubnet(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	allowed := createRandomNodes(10, "1.0.1", false, true)
	for _, n := range allowed {
		n.LastNet = "127.0.0.0"
	}

	state := nodeselection.InitState(ctx, allowed, map[storxnetwork.PlacementConstraint]nodeselection.Placement{
		nodeselection.OwnNodesPlacement: {
			Selector: nodeselection.AttributeGroupSelector(nodeselection.LastNetAttribute),
		},
	})

	allowedIDs := make([]storxnetwork.NodeID, len(allowed))
	for i, n := range allowed {
		allowedIDs[i] = n.ID
	}

	selected, err := state.Select(ctx, storxnetwork.NodeID{}, nodeselection.OwnNodesPlacement, 10, nil, nil, allowedIDs)
	require.NoError(t, err)
	require.Len(t, selected, 10)
}
