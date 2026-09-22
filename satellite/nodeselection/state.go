// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package nodeselection

import (
	"context"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/storxnetwork"
)

// ErrNotEnoughNodes is when selecting nodes failed with the given parameters.
var ErrNotEnoughNodes = errs.Class("not enough nodes")

// State includes a stateful selector (indexed nodes) for each placement, plus
// the full node list and placement definitions for request-time allowlisting.
type State struct {
	selectors  map[storxnetwork.PlacementConstraint]NodeSelector
	nodes      []*SelectedNode
	placements PlacementDefinitions
}

var initStateTask = mon.Task()

// InitState initializes the State for each placement.
func InitState(ctx context.Context, nodes []*SelectedNode, placements PlacementDefinitions) State {
	defer initStateTask(&ctx)(nil)
	state := State{
		selectors:  make(map[storxnetwork.PlacementConstraint]NodeSelector),
		nodes:      nodes,
		placements: placements,
	}
	for id, placement := range placements {
		selector := placement.Selector
		if selector == nil {
			selector = RandomSelector()
		}
		var filter = placement.NodeFilter
		if placement.UploadFilter != nil {
			filter = NodeFilters{placement.NodeFilter, placement.UploadFilter}
		}
		state.selectors[id] = selector(ctx, nodes, filter)
	}
	return state
}

var selectTask = mon.Task()

// Select picks the required nodes given a specific placement.
// When allowedIDs is non-empty, only those node IDs may be selected (AllowedNodesFilter),
// intersected with the placement's filters.
func (s State) Select(ctx context.Context, requester storxnetwork.NodeID, p storxnetwork.PlacementConstraint, count int, excluded []storxnetwork.NodeID, alreadySelected []*SelectedNode, allowedIDs []storxnetwork.NodeID) (_ []*SelectedNode, err error) {
	defer selectTask(&ctx)(&err)

	if len(allowedIDs) > 0 {
		return s.selectAllowed(ctx, requester, p, count, excluded, alreadySelected, allowedIDs)
	}

	selector, found := s.selectors[p]
	if !found {
		return nil, Error.New("Placement is not defined: %d", p)
	}
	nodes, err := selector(ctx, requester, count, excluded, alreadySelected)
	if len(nodes) < count {
		return nodes, ErrNotEnoughNodes.New("requested from cache %d, found %d", count, len(nodes))
	}
	return nodes, err
}

func (s State) selectAllowed(ctx context.Context, requester storxnetwork.NodeID, p storxnetwork.PlacementConstraint, count int, excluded []storxnetwork.NodeID, alreadySelected []*SelectedNode, allowedIDs []storxnetwork.NodeID) ([]*SelectedNode, error) {
	placement, found := s.placements[p]
	if !found {
		// Fall back to default placement filters when OwnNodesPlacement (or another
		// allowlist placement) is not explicitly configured.
		placement, found = s.placements[storxnetwork.DefaultPlacement]
		if !found {
			return nil, Error.New("Placement is not defined: %d", p)
		}
	}

	selectorInit := placement.Selector
	if selectorInit == nil {
		selectorInit = RandomSelector()
	}

	var filter NodeFilters
	if placement.NodeFilter != nil {
		filter = append(filter, placement.NodeFilter)
	}
	if placement.UploadFilter != nil {
		filter = append(filter, placement.UploadFilter)
	}
	filter = append(filter, AllowedNodesFilter(allowedIDs))

	selector := selectorInit(ctx, s.nodes, filter)
	nodes, err := selector(ctx, requester, count, excluded, alreadySelected)
	if len(nodes) < count {
		return nodes, ErrNotEnoughNodes.New("requested from cache %d, found %d", count, len(nodes))
	}
	return nodes, err
}
