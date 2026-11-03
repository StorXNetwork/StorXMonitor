// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package overlay_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testrand"
)

type fakeClaimedNodes struct {
	ids   []storxnetwork.NodeID
	calls int
	err   error
}

func (f *fakeClaimedNodes) AllNodeIDs(ctx context.Context) ([]storxnetwork.NodeID, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.ids, nil
}

func TestClaimedNodeSet(t *testing.T) {
	claimed := testrand.NodeID()
	other := testrand.NodeID()

	tests := []struct {
		name    string
		id      storxnetwork.NodeID
		want    bool
		wantErr bool
	}{
		{name: "claimed node", id: claimed, want: true},
		{name: "public node", id: other, want: false},
	}

	src := &fakeClaimedNodes{ids: []storxnetwork.NodeID{claimed}}
	set := overlay.NewClaimedNodeSet(src, time.Minute)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := set.Contains(context.Background(), tt.id)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
	require.Equal(t, 1, src.calls)
}

func TestClaimedNodeSetKeepsSnapshotOnRefreshError(t *testing.T) {
	claimed := testrand.NodeID()
	src := &fakeClaimedNodes{ids: []storxnetwork.NodeID{claimed}}
	set := overlay.NewClaimedNodeSet(src, time.Nanosecond)

	ok, err := set.Contains(context.Background(), claimed)
	require.NoError(t, err)
	require.True(t, ok)

	src.err = context.Canceled
	time.Sleep(time.Millisecond)

	ok, err = set.Contains(context.Background(), claimed)
	require.NoError(t, err)
	require.True(t, ok)
}
