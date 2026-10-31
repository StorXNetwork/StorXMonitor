// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testrand"
)

func TestExcludeClaimedReputations(t *testing.T) {
	claimedID := testrand.NodeID()
	publicID := testrand.NodeID()
	sharedWallet := "0xshared"

	rows := []NodeReputationEntry{
		{NodeID: claimedID, Wallet: sharedWallet},
		{NodeID: publicID, Wallet: sharedWallet},
		{NodeID: testrand.NodeID(), Wallet: "0xpublic"},
	}
	claimed := map[storxnetwork.NodeID]struct{}{claimedID: {}}

	tests := []struct {
		name    string
		rows    []NodeReputationEntry
		claimed map[storxnetwork.NodeID]struct{}
		wantLen int
		keep    storxnetwork.NodeID
		drop    storxnetwork.NodeID
	}{
		{
			name:    "drops claimed node and keeps public node on the same wallet",
			rows:    rows,
			claimed: claimed,
			wantLen: 2,
			keep:    publicID,
			drop:    claimedID,
		},
		{
			name:    "empty claimed set keeps every row",
			rows:    rows,
			claimed: nil,
			wantLen: 3,
			keep:    claimedID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExcludeClaimedReputations(tt.rows, tt.claimed)
			require.Len(t, got, tt.wantLen)
			foundKeep := false
			for _, row := range got {
				require.NotEqual(t, tt.drop, row.NodeID)
				if row.NodeID == tt.keep {
					foundKeep = true
				}
			}
			require.True(t, foundKeep)
		})
	}
}

func TestSkipClaimedNodesMatch(t *testing.T) {
	inner := &AllowNodes{whiteList: []bool{true, false, true, true}}
	filter := &SkipClaimedNodes{
		inner:   inner,
		blocked: []bool{false, false, true},
	}

	tests := []struct {
		name  string
		alias metabase.NodeAlias
		want  bool
	}{
		{name: "public allowed node", alias: 0, want: true},
		{name: "rejected by inner filter", alias: 1, want: false},
		{name: "claimed node", alias: 2, want: false},
		{name: "alias past blocked list", alias: 3, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, filter.Match(tt.alias))
		})
	}
}
