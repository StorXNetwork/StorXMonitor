// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/grant"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestIntersectMemberAccessRequest(t *testing.T) {
	t.Parallel()

	acl := []console.MemberBucketGrant{
		{Bucket: "gmail", Prefix: "alice@x.com/", AllowList: true, AllowDownload: true},
		{Bucket: "outlook", Prefix: "alice@x.com/", AllowList: true, AllowDownload: true, AllowUpload: true},
	}

	tests := []struct {
		name       string
		prefixes   []grant.SharePrefix
		permission *grant.Permission
		wantErr    bool
		wantList   bool
		wantDown   bool
	}{
		{
			name:     "own prefix ok list download",
			prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: "alice@x.com/"}},
			permission: &grant.Permission{
				AllowList: true, AllowDownload: true, AllowUpload: true, AllowDelete: true,
			},
			wantList: true, wantDown: true,
		},
		{
			name:     "child prefix ok",
			prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: "alice@x.com/inbox/"}},
			permission: &grant.Permission{
				AllowList: true, AllowDownload: true,
			},
			wantList: true, wantDown: true,
		},
		{
			name:     "other email deny",
			prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: "bob@x.com/"}},
			permission: &grant.Permission{
				AllowList: true, AllowDownload: true,
			},
			wantErr: true,
		},
		{
			name:     "parent prefix deny",
			prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: "ali"}},
			permission: &grant.Permission{
				AllowList: true,
			},
			wantErr: true,
		},
		{
			name:     "bucket not in grants deny",
			prefixes: []grant.SharePrefix{{Bucket: "dropbox", Prefix: "alice@x.com/"}},
			permission: &grant.Permission{
				AllowList: true,
			},
			wantErr: true,
		},
		{
			name:     "empty bucket deny",
			prefixes: []grant.SharePrefix{{Bucket: "", Prefix: ""}},
			permission: &grant.Permission{
				AllowList: true,
			},
			wantErr: true,
		},
		{
			name:     "upload delete always denied even if ACL row had upload",
			prefixes: []grant.SharePrefix{{Bucket: "outlook", Prefix: "alice@x.com/"}},
			permission: &grant.Permission{
				AllowList: true, AllowUpload: true, AllowDelete: true,
			},
			wantList: true, wantDown: false,
		},
		{
			name:       "empty prefixes deny",
			prefixes:   nil,
			permission: &grant.Permission{AllowList: true},
			wantErr:    true,
		},
		{
			name: "perms and to empty deny",
			prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: "alice@x.com/"}},
			permission: &grant.Permission{
				AllowUpload: true, AllowDelete: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outPrefixes, outPerm, err := console.IntersectMemberAccessRequest(tt.prefixes, tt.permission, acl)
			if tt.wantErr {
				require.Error(t, err)
				require.True(t, console.ErrForbidden.Has(err))
				return
			}
			require.NoError(t, err)
			require.Len(t, outPrefixes, len(tt.prefixes))
			require.NotNil(t, outPerm)
			require.Equal(t, tt.wantList, outPerm.AllowList)
			require.Equal(t, tt.wantDown, outPerm.AllowDownload)
			require.False(t, outPerm.AllowUpload)
			require.False(t, outPerm.AllowDelete)
		})
	}
}

func TestDefaultInviteGrantsFromRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		email    string
		buckets  []string
		wantLen  int
		wantPref string
	}{
		{name: "empty registry", email: "a@x.com", buckets: nil, wantLen: 0},
		{name: "two buckets", email: "a@x.com", buckets: []string{"gmail", "outlook"}, wantLen: 2, wantPref: "a@x.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := console.DefaultInviteGrants(tt.email, tt.buckets)
			require.Len(t, got, tt.wantLen)
			for i, g := range got {
				require.Equal(t, tt.buckets[i], g.Bucket)
				require.Equal(t, tt.wantPref, g.Prefix)
				require.True(t, g.AllowList)
				require.True(t, g.AllowDownload)
				require.False(t, g.AllowUpload)
				require.False(t, g.AllowDelete)
			}
		})
	}
}
