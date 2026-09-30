// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOwnNodesQuotaBytes(t *testing.T) {
	tests := []struct {
		name        string
		storageUsed int64
		freeDisk    int64
		want        int64
	}{
		{name: "disk plus stored data", storageUsed: 1, freeDisk: 4, want: 5},
		{name: "no disk report", storageUsed: 0, freeDisk: 0, want: 0},
		{name: "negative free disk ignored", storageUsed: 3, freeDisk: -1, want: 3},
		{name: "negative stored ignored", storageUsed: -5, freeDisk: 8, want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ownNodesQuotaBytes(tt.storageUsed, tt.freeDisk))
		})
	}
}
