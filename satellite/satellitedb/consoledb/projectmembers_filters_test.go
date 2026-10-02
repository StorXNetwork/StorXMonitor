// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestResolveProjectMemberListFilters(t *testing.T) {
	owner := testrand.UUID()
	admin := console.RoleAdmin
	member := console.RoleMember
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name               string
		cursor             console.ProjectMembersCursor
		wantMembers        bool
		wantInvites        bool
		wantInviteStatus   string
		wantOwnerMode      string
		wantRole           *console.ProjectMemberRole
	}{
		{
			name:        "defaults include members and invites",
			cursor:      console.ProjectMembersCursor{OwnerID: &owner, Now: now},
			wantMembers: true,
			wantInvites: true,
		},
		{
			name:        "kind members",
			cursor:      console.ProjectMembersCursor{Kind: console.ProjectMemberListKindMembers, OwnerID: &owner, Now: now},
			wantMembers: true,
			wantInvites: false,
		},
		{
			name:             "kind pending defaults to pending invites",
			cursor:           console.ProjectMembersCursor{Kind: console.ProjectMemberListKindPending, OwnerID: &owner, Now: now},
			wantMembers:      false,
			wantInvites:      true,
			wantInviteStatus: console.ProjectMemberListStatusPending,
		},
		{
			name:          "kind admins includes owner",
			cursor:        console.ProjectMembersCursor{Kind: console.ProjectMemberListKindAdmins, OwnerID: &owner, Now: now},
			wantMembers:   true,
			wantInvites:   false,
			wantOwnerMode: "include",
			wantRole:      &admin,
		},
		{
			name:          "role admin includes owner",
			cursor:        console.ProjectMembersCursor{Role: &admin, OwnerID: &owner, Now: now},
			wantMembers:   true,
			wantInvites:   false,
			wantOwnerMode: "include",
			wantRole:      &admin,
		},
		{
			name:          "role member excludes owner",
			cursor:        console.ProjectMembersCursor{Role: &member, OwnerID: &owner, Now: now},
			wantMembers:   true,
			wantInvites:   false,
			wantOwnerMode: "exclude",
			wantRole:      &member,
		},
		{
			name:        "status active drops invites and keeps members",
			cursor:      console.ProjectMembersCursor{Kind: console.ProjectMemberListKindPending, Status: console.ProjectMemberListStatusActive, OwnerID: &owner, Now: now},
			wantMembers: true,
			wantInvites: false,
		},
		{
			name:             "status expired drops members",
			cursor:           console.ProjectMembersCursor{Status: console.ProjectMemberListStatusExpired, OwnerID: &owner, Now: now},
			wantMembers:      false,
			wantInvites:      true,
			wantInviteStatus: console.ProjectMemberListStatusExpired,
		},
		{
			name:             "status pending with kind all",
			cursor:           console.ProjectMembersCursor{Status: console.ProjectMemberListStatusPending, OwnerID: &owner, Now: now},
			wantMembers:      false,
			wantInvites:      true,
			wantInviteStatus: console.ProjectMemberListStatusPending,
		},
		{
			name:             "status expired wins over kind pending",
			cursor:           console.ProjectMembersCursor{Kind: console.ProjectMemberListKindPending, Status: console.ProjectMemberListStatusExpired, OwnerID: &owner, Now: now},
			wantMembers:      false,
			wantInvites:      true,
			wantInviteStatus: console.ProjectMemberListStatusExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveProjectMemberListFilters(tt.cursor)
			require.Equal(t, tt.wantMembers, got.includeMembers)
			require.Equal(t, tt.wantInvites, got.includeInvites)
			require.Equal(t, tt.wantInviteStatus, got.inviteStatus)
			require.Equal(t, tt.wantOwnerMode, got.ownerMode)
			if tt.wantRole == nil {
				require.Nil(t, got.role)
			} else {
				require.NotNil(t, got.role)
				require.Equal(t, *tt.wantRole, *got.role)
			}
			require.Equal(t, now, got.now)
		})
	}
}
