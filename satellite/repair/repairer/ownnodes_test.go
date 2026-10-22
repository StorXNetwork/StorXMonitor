// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package repairer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
)

type fakeOwnNodes struct {
	orgByNode  map[storxnetwork.NodeID]uuid.UUID
	nodesByOrg map[uuid.UUID][]storxnetwork.NodeID
	err        error
}

func (f *fakeOwnNodes) GetByNodeID(ctx context.Context, nodeID storxnetwork.NodeID) (*console.OrgNode, error) {
	if f.err != nil {
		return nil, f.err
	}
	orgID, ok := f.orgByNode[nodeID]
	if !ok {
		return nil, console.ErrOrgNodeNotFound.New("")
	}
	return &console.OrgNode{OrgID: orgID, NodeID: nodeID}, nil
}

func (f *fakeOwnNodes) GetNodeIDsByOrgID(ctx context.Context, orgID uuid.UUID) ([]storxnetwork.NodeID, error) {
	return f.nodesByOrg[orgID], nil
}

func TestOwnNodeAllowedIDs(t *testing.T) {
	orgA := testrand.UUID()
	orgB := testrand.UUID()
	pieceA := testrand.NodeID()
	piecePublic := testrand.NodeID()
	nodeA2 := testrand.NodeID()
	nodeB := testrand.NodeID()

	lookup := &fakeOwnNodes{
		orgByNode: map[storxnetwork.NodeID]uuid.UUID{
			pieceA: orgA,
		},
		nodesByOrg: map[uuid.UUID][]storxnetwork.NodeID{
			orgA: {pieceA, nodeA2},
			orgB: {nodeB},
		},
	}
	repairer := &SegmentRepairer{ownNodes: lookup}

	tests := []struct {
		name      string
		pieces    metabase.Pieces
		placement storxnetwork.PlacementConstraint
		wantIDs   []storxnetwork.NodeID
		wantErr   bool
	}{
		{
			name:      "public placement does not restrict nodes",
			pieces:    metabase.Pieces{{Number: 0, StorageNode: piecePublic}},
			placement: storxnetwork.DefaultPlacement,
		},
		{
			name:      "own-nodes repair stays on the piece org",
			pieces:    metabase.Pieces{{Number: 0, StorageNode: pieceA}},
			placement: nodeselection.OwnNodesPlacement,
			wantIDs:   []storxnetwork.NodeID{pieceA, nodeA2},
		},
		{
			name:      "public piece on own-nodes placement does not fall back",
			pieces:    metabase.Pieces{{Number: 0, StorageNode: piecePublic}},
			placement: nodeselection.OwnNodesPlacement,
			wantErr:   true,
		},
		{
			name: "skips an unclaimed piece and uses the claimed org",
			pieces: metabase.Pieces{
				{Number: 0, StorageNode: piecePublic},
				{Number: 1, StorageNode: pieceA},
			},
			placement: nodeselection.OwnNodesPlacement,
			wantIDs:   []storxnetwork.NodeID{pieceA, nodeA2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := repairer.OwnNodeAllowedIDs(context.Background(), tt.pieces, tt.placement)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantIDs, ids)
		})
	}

	repairer.ownNodes = &fakeOwnNodes{err: errs.New("db down")}
	_, err := repairer.OwnNodeAllowedIDs(context.Background(), metabase.Pieces{{StorageNode: pieceA}}, nodeselection.OwnNodesPlacement)
	require.Error(t, err)
}
