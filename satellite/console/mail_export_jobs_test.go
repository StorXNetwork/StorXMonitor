// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAvailableBandwidthBytes(t *testing.T) {
	tests := []struct {
		name  string
		limit int64
		used  int64
		want  int64
	}{
		{name: "unused quota", limit: 1000, used: 0, want: 1000},
		{name: "partial usage", limit: 1000, used: 250, want: 750},
		{name: "fully used", limit: 1000, used: 1000, want: 0},
		{name: "overused floors at zero", limit: 1000, used: 1500, want: 0},
		{name: "zero limit", limit: 0, used: 0, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, AvailableBandwidthBytes(tt.limit, tt.used))
		})
	}
}
