// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package nodeselection

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/storxnetwork"
)

func TestCreateFiltersOwnNodesFallback(t *testing.T) {
	defs := TestPlacementDefinitions()
	node := &SelectedNode{}

	tests := []struct {
		name      storxnetwork.PlacementConstraint
		wantMatch bool
	}{
		{name: storxnetwork.DefaultPlacement, wantMatch: true},
		{name: OwnNodesPlacement, wantMatch: true},
		{name: storxnetwork.PlacementConstraint(99), wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(int(tt.name)), func(t *testing.T) {
			filter, _ := defs.CreateFilters(tt.name)
			require.Equal(t, tt.wantMatch, filter.Match(node))
		})
	}
}
