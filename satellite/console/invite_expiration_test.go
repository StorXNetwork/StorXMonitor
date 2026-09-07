// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestParseInviteExpirationOption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{name: "empty defaults to 24h", raw: "", want: 24 * time.Hour},
		{name: "7d", raw: "7d", want: 7 * 24 * time.Hour},
		{name: "7 Days label", raw: "7 Days", want: 7 * 24 * time.Hour},
		{name: "24h", raw: "24h", want: 24 * time.Hour},
		{name: "24 Hours Default label", raw: "24 Hours (Default)", want: 24 * time.Hour},
		{name: "3d", raw: "3d", want: 3 * 24 * time.Hour},
		{name: "30d", raw: "30d", want: 30 * 24 * time.Hour},
		{name: "invalid", raw: "2w", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := console.ParseInviteExpirationOption(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseOptionalVaultExpiration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantNil bool
		want    time.Duration
		wantErr bool
	}{
		{name: "empty means no expiry", raw: "", wantNil: true},
		{name: "30d", raw: "30d", want: 30 * 24 * time.Hour},
		{name: "invalid", raw: "forever", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := console.ParseOptionalVaultExpiration(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.want, *got)
		})
	}
}

func TestFilterActiveMemberGrants(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name   string
		grants []console.MemberBucketGrant
		want   int
	}{
		{
			name: "keeps nil expiry",
			grants: []console.MemberBucketGrant{
				{Bucket: "gmail", ExpiresAt: nil},
			},
			want: 1,
		},
		{
			name: "drops expired",
			grants: []console.MemberBucketGrant{
				{Bucket: "gmail", ExpiresAt: &past},
				{Bucket: "drive", ExpiresAt: &future},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := console.FilterActiveMemberGrants(tt.grants, now)
			require.Len(t, got, tt.want)
		})
	}
}
