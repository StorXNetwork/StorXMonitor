// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQuotaLimitForDestination(t *testing.T) {
	const twoGB int64 = 2 << 30
	tests := []struct {
		name  string
		mode  string
		limit int64
		want  int64
	}{
		{name: "external s3 hides the free tier cap", mode: StorageDestinationExternalS3, limit: twoGB, want: 0},
		{name: "default keeps the project cap", mode: StorageDestinationDefault, limit: twoGB, want: twoGB},
		{name: "own nodes keeps the disk cap", mode: StorageDestinationOwnNodes, limit: twoGB, want: twoGB},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, quotaLimitForDestination(tt.mode, tt.limit))
		})
	}
}

func TestQuotaCardStatus(t *testing.T) {
	tests := []struct {
		name        string
		used        int64
		limit       int64
		wantPercent int
		wantLabel   string
	}{
		{name: "no cap", used: 50, limit: 0, wantPercent: 0, wantLabel: "No limit"},
		{name: "empty with no cap", used: 0, limit: 0, wantPercent: 0, wantLabel: "No limit"},
		{name: "half of a known cap", used: 50, limit: 100, wantPercent: 50, wantLabel: "50% Used"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			percent, label := quotaCardStatus(tt.used, tt.limit)
			require.Equal(t, tt.wantPercent, percent)
			require.Equal(t, tt.wantLabel, label)
		})
	}
}

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
