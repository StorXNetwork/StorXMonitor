// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package repairer

import (
	"context"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

// OwnNodeLookup resolves which organization owns a piece and which nodes that organization claimed.
type OwnNodeLookup interface {
	GetByNodeID(ctx context.Context, nodeID storxnetwork.NodeID) (*console.OrgNode, error)
	GetNodeIDsByOrgID(ctx context.Context, orgID uuid.UUID) ([]storxnetwork.NodeID, error)
}

// SetOwnNodes restricts placement-250 repair uploads to the organization that already holds the segment.
func (repairer *SegmentRepairer) SetOwnNodes(nodes OwnNodeLookup) {
	repairer.ownNodes = nodes
}

// OwnNodeAllowedIDs returns the org's claimed nodes for a placement-250 segment.
// An empty result means the segment is not own-nodes. An error means repair must not
// fall back to the public pool.
func (repairer *SegmentRepairer) OwnNodeAllowedIDs(ctx context.Context, pieces metabase.Pieces, placement storxnetwork.PlacementConstraint) ([]storxnetwork.NodeID, error) {
	if placement != nodeselection.OwnNodesPlacement || repairer.ownNodes == nil {
		return nil, nil
	}

	var lookupErr error
	for _, piece := range pieces {
		orgNode, err := repairer.ownNodes.GetByNodeID(ctx, piece.StorageNode)
		if err != nil {
			if console.ErrOrgNodeNotFound.Has(err) {
				continue
			}
			lookupErr = err
			continue
		}
		if orgNode == nil {
			continue
		}
		ids, err := repairer.ownNodes.GetNodeIDsByOrgID(ctx, orgNode.OrgID)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, errs.New("own-nodes repair: organization %s has no claimed nodes", orgNode.OrgID)
		}
		return ids, nil
	}
	if lookupErr != nil {
		return nil, lookupErr
	}
	return nil, errs.New("own-nodes repair: segment pieces are not on a claimed organization")
}
