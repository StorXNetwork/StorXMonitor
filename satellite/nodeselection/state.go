// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package nodeselection

import (
	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/storxnetwork"
)

// ErrNotEnoughNodes is when selecting nodes failed with the given parameters.
var ErrNotEnoughNodes = errs.Class("not enough nodes")

// State includes a stateful selector (indexed nodes) for each placement.
type State map[storxnetwork.PlacementConstraint]NodeSelector

// NewState initializes the State for each placement.
func NewState(nodes []*SelectedNode, placements PlacementDefinitions) State {
	state := make(State)
	for id, placement := range placements {
		selector := placement.Selector
		if selector == nil {
			selector = RandomSelector()
		}
		state[id] = selector(nodes, placement.NodeFilter)
	}
	return state
}

// Select picks the required nodes given a specific placement.
func (s State) Select(p storxnetwork.PlacementConstraint, count int, excluded []storxnetwork.NodeID, alreadySelected []*SelectedNode) ([]*SelectedNode, error) {
	selector, found := s[p]
	if !found {
		return nil, Error.New("Placement is not defined: %d", p)
	}
	nodes, err := selector(count, excluded, alreadySelected)
	if len(nodes) < count {
		return nodes, ErrNotEnoughNodes.New("requested from cache %d, found %d", count, len(nodes))
	}
	return nodes, err
}
