// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/grant"
	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestValidateBulkInviteCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{name: "empty", count: 0, wantErr: true},
		{name: "one", count: 1, wantErr: false},
		{name: "max", count: console.MaxBulkProjectInvites, wantErr: false},
		{name: "over max", count: console.MaxBulkProjectInvites + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := console.ValidateBulkInviteCount(tt.count)
			if tt.wantErr {
				require.Error(t, err)
				require.True(t, console.ErrValidation.Has(err))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGrantsFromVaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		email   string
		vaults  []string
		wantLen int
		want0   string
	}{
		{name: "two vaults", email: "a@x.com", vaults: []string{"gmail", "google-drive"}, wantLen: 2, want0: "gmail"},
		{name: "skips empty", email: "a@x.com", vaults: []string{"", "gmail"}, wantLen: 1, want0: "gmail"},
		{name: "empty vaults", email: "a@x.com", vaults: nil, wantLen: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := console.GrantsFromVaults(tt.email, tt.vaults)
			require.Len(t, got, tt.wantLen)
			if tt.wantLen == 0 {
				return
			}
			require.Equal(t, tt.want0, got[0].Bucket)
			require.Equal(t, "a@x.com/", got[0].Prefix)
			require.True(t, got[0].AllowList)
			require.True(t, got[0].AllowDownload)
			require.False(t, got[0].AllowUpload)
			require.False(t, got[0].AllowDelete)
		})
	}
}

func TestValidateBucketNameForMemberACL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bucket  string
		wantErr bool
	}{
		{name: "valid", bucket: "gmail", wantErr: false},
		{name: "valid with dash", bucket: "google-drive", wantErr: false},
		{name: "too short", bucket: "ab", wantErr: true},
		{name: "empty", bucket: "", wantErr: true},
		{name: "starts with dash", bucket: "-gmail", wantErr: true},
		{name: "invalid char", bucket: "my bucket", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := console.ValidateBucketNameForMemberACL(tt.bucket)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateGrantSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		grants  []console.MemberBucketGrantInput
		wantErr bool
	}{
		{
			name: "valid single",
			grants: []console.MemberBucketGrantInput{{
				Bucket: "gmail", Prefix: "a@x.com/", AllowList: true, AllowDownload: true,
			}},
		},
		{
			name: "any valid bucket name ok without registry",
			grants: []console.MemberBucketGrantInput{{
				Bucket: "dropbox", Prefix: "a@x.com/", AllowList: true,
			}},
		},
		{
			name:    "invalid bucket name",
			grants:  []console.MemberBucketGrantInput{{Bucket: "ab", Prefix: "a@x.com/", AllowList: true}},
			wantErr: true,
		},
		{
			name:    "missing trailing slash",
			grants:  []console.MemberBucketGrantInput{{Bucket: "gmail", Prefix: "a@x.com", AllowList: true}},
			wantErr: true,
		},
		{
			name:    "bucket-wide slash only",
			grants:  []console.MemberBucketGrantInput{{Bucket: "gmail", Prefix: "/", AllowList: true}},
			wantErr: true,
		},
		{
			name:    "all false perms",
			grants:  []console.MemberBucketGrantInput{{Bucket: "gmail", Prefix: "a@x.com/"}},
			wantErr: true,
		},
		{
			name: "upload delete only ignored then invalid",
			grants: []console.MemberBucketGrantInput{{
				Bucket: "gmail", Prefix: "a@x.com/", AllowUpload: true, AllowDelete: true,
			}},
			wantErr: true,
		},
		{
			name: "list ok upload delete stripped",
			grants: []console.MemberBucketGrantInput{{
				Bucket: "gmail", Prefix: "a@x.com/",
				AllowList: true, AllowUpload: true, AllowDelete: true,
			}},
		},
		{
			name: "overlap parent child",
			grants: []console.MemberBucketGrantInput{
				{Bucket: "gmail", Prefix: "a@x.com/", AllowList: true},
				{Bucket: "gmail", Prefix: "a@x.com/inbox/", AllowDownload: true},
			},
			wantErr: true,
		},
		{
			name: "sibling ok",
			grants: []console.MemberBucketGrantInput{
				{Bucket: "gmail", Prefix: "a@x.com/", AllowList: true},
				{Bucket: "gmail", Prefix: "b@x.com/", AllowList: true},
			},
		},
		{
			name:   "empty set ok",
			grants: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := console.ValidateGrantSet(tt.grants)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			for _, g := range tt.grants {
				require.False(t, g.AllowUpload)
				require.False(t, g.AllowDelete)
			}
		})
	}
}

func TestIsPrefixAllowedAndFindMatchingGrant(t *testing.T) {
	t.Parallel()

	memberID := uuid.UUID{}
	acl := []console.MemberBucketGrant{
		{MemberID: &memberID, Bucket: "gmail", Prefix: "alice@x.com/", AllowList: true, AllowDownload: true},
		{MemberID: &memberID, Bucket: "gmail", Prefix: "bob@x.com/", AllowList: true},
	}

	tests := []struct {
		name    string
		bucket  string
		prefix  string
		allowed bool
	}{
		{name: "exact", bucket: "gmail", prefix: "alice@x.com/", allowed: true},
		{name: "child", bucket: "gmail", prefix: "alice@x.com/inbox/", allowed: true},
		{name: "sibling", bucket: "gmail", prefix: "carol@x.com/", allowed: false},
		{name: "parent of grant", bucket: "gmail", prefix: "ali", allowed: false},
		{name: "other bucket", bucket: "outlook", prefix: "alice@x.com/", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.allowed, console.IsPrefixAllowed(tt.bucket, tt.prefix, acl))
			match := console.FindMatchingGrant(tt.bucket, tt.prefix, acl)
			if tt.allowed {
				require.NotNil(t, match)
			} else {
				require.Nil(t, match)
			}
		})
	}
}

func TestIntersectPermission(t *testing.T) {
	t.Parallel()

	acl := console.MemberBucketGrant{AllowList: true, AllowDownload: true, AllowUpload: false, AllowDelete: false}
	req := &grant.Permission{AllowList: true, AllowDownload: true, AllowUpload: true, AllowDelete: true}
	out := console.IntersectPermission(req, acl)
	require.True(t, out.AllowList)
	require.True(t, out.AllowDownload)
	require.False(t, out.AllowUpload)
	require.False(t, out.AllowDelete)
}

func TestDefaultInviteGrants(t *testing.T) {
	t.Parallel()

	got := console.DefaultInviteGrants("Alice@X.com", []string{"gmail", "outlook"})
	require.Len(t, got, 2)
	require.Equal(t, "Alice@X.com/", got[0].Prefix)
	require.True(t, got[0].AllowList)
	require.True(t, got[0].AllowDownload)
	require.False(t, got[0].AllowUpload)
	require.Equal(t, "gmail", got[0].Bucket)
	require.Equal(t, "outlook", got[1].Bucket)
}

func TestSummarizeVaultGrants(t *testing.T) {
	t.Parallel()

	earlier := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		grants         []console.MemberBucketGrant
		wantVaults     []string
		wantExpiresNil bool
		wantExpires    time.Time
	}{
		{
			name:           "empty",
			grants:         nil,
			wantVaults:     nil,
			wantExpiresNil: true,
		},
		{
			name: "unique vaults earliest expiry",
			grants: []console.MemberBucketGrant{
				{Bucket: "gmail", ExpiresAt: &later},
				{Bucket: "gmail", ExpiresAt: &earlier},
				{Bucket: "drive", ExpiresAt: nil},
			},
			wantVaults:  []string{"gmail", "drive"},
			wantExpires: earlier,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vaults, exp := console.SummarizeVaultGrants(tt.grants)
			require.Equal(t, tt.wantVaults, vaults)
			if tt.wantExpiresNil {
				require.Nil(t, exp)
				return
			}
			require.NotNil(t, exp)
			require.True(t, exp.Equal(tt.wantExpires))
		})
	}
}
