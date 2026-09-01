// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
)

func TestProjectMembersListFilters(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
		usersDB := db.Console().Users()
		projectsDB := db.Console().Projects()
		membersDB := db.Console().ProjectMembers()
		invitesDB := db.Console().ProjectInvitations()

		owner, err := usersDB.Insert(ctx, &console.User{
			ID:           testrand.UUID(),
			Email:        "owner-filter@mail.test",
			PasswordHash: []byte("hash"),
			FullName:     "Owner User",
		})
		require.NoError(t, err)

		adminUser, err := usersDB.Insert(ctx, &console.User{
			ID:           testrand.UUID(),
			Email:        "admin-filter@mail.test",
			PasswordHash: []byte("hash"),
			FullName:     "Admin User",
		})
		require.NoError(t, err)

		memberUser, err := usersDB.Insert(ctx, &console.User{
			ID:           testrand.UUID(),
			Email:        "member-filter@mail.test",
			PasswordHash: []byte("hash"),
			FullName:     "Member User",
		})
		require.NoError(t, err)

		project, err := projectsDB.Insert(ctx, &console.Project{
			Name:        "filter-project",
			Description: "filters",
			OwnerID:     owner.ID,
		})
		require.NoError(t, err)

		_, err = membersDB.Insert(ctx, owner.ID, project.ID, console.RoleMember)
		require.NoError(t, err)
		_, err = membersDB.Insert(ctx, adminUser.ID, project.ID, console.RoleAdmin)
		require.NoError(t, err)
		_, err = membersDB.Insert(ctx, memberUser.ID, project.ID, console.RoleMember)
		require.NoError(t, err)

		now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
		pendingExpiry := now.Add(24 * time.Hour)
		expiredExpiry := now.Add(-time.Hour)

		_, err = invitesDB.Upsert(ctx, &console.ProjectInvitation{
			ProjectID: project.ID,
			Email:     "pending-invite@mail.test",
			InviterID: &owner.ID,
			CreatedAt: now.Add(-time.Hour),
			ExpiresAt: &pendingExpiry,
		})
		require.NoError(t, err)
		_, err = invitesDB.Upsert(ctx, &console.ProjectInvitation{
			ProjectID: project.ID,
			Email:     "expired-invite@mail.test",
			InviterID: &owner.ID,
			CreatedAt: now.Add(-48 * time.Hour),
			ExpiresAt: &expiredExpiry,
		})
		require.NoError(t, err)

		ownerID := owner.ID
		ttl := 168 * time.Hour
		adminRole := console.RoleAdmin

		tests := []struct {
			name            string
			cursor          console.ProjectMembersCursor
			wantMemberIDs   []uuid.UUID
			wantInviteMails []string
			wantTotal       uint64
		}{
			{
				name: "kind members only",
				cursor: console.ProjectMembersCursor{
					Limit: 50, Page: 1, Kind: console.ProjectMemberListKindMembers,
					OwnerID: &ownerID, Now: now, InviteTTL: ttl,
				},
				wantMemberIDs: []uuid.UUID{owner.ID, adminUser.ID, memberUser.ID},
				wantTotal:     3,
			},
			{
				name: "kind pending active invites",
				cursor: console.ProjectMembersCursor{
					Limit: 50, Page: 1, Kind: console.ProjectMemberListKindPending,
					OwnerID: &ownerID, Now: now, InviteTTL: ttl,
				},
				wantInviteMails: []string{"pending-invite@mail.test"},
				wantTotal:       1,
			},
			{
				name: "kind admins includes owner and admin role",
				cursor: console.ProjectMembersCursor{
					Limit: 50, Page: 1, Kind: console.ProjectMemberListKindAdmins,
					OwnerID: &ownerID, Now: now, InviteTTL: ttl,
				},
				wantMemberIDs: []uuid.UUID{owner.ID, adminUser.ID},
				wantTotal:     2,
			},
			{
				name: "role admin includes owner and excludes invites",
				cursor: console.ProjectMembersCursor{
					Limit: 50, Page: 1, Role: &adminRole,
					OwnerID: &ownerID, Now: now, InviteTTL: ttl,
				},
				wantMemberIDs: []uuid.UUID{owner.ID, adminUser.ID},
				wantTotal:     2,
			},
			{
				name: "status expired invites only",
				cursor: console.ProjectMembersCursor{
					Limit: 50, Page: 1, Status: console.ProjectMemberListStatusExpired,
					OwnerID: &ownerID, Now: now, InviteTTL: ttl,
				},
				wantInviteMails: []string{"expired-invite@mail.test"},
				wantTotal:       1,
			},
			{
				name: "status active members only",
				cursor: console.ProjectMembersCursor{
					Limit: 50, Page: 1, Status: console.ProjectMemberListStatusActive,
					OwnerID: &ownerID, Now: now, InviteTTL: ttl,
				},
				wantMemberIDs: []uuid.UUID{owner.ID, adminUser.ID, memberUser.ID},
				wantTotal:     3,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				page, err := membersDB.GetPagedWithInvitationsByProjectID(ctx, project.ID, tt.cursor)
				require.NoError(t, err)
				require.Equal(t, tt.wantTotal, page.TotalCount)
				require.Len(t, page.ProjectMembers, len(tt.wantMemberIDs))
				require.Len(t, page.ProjectInvitations, len(tt.wantInviteMails))

				gotIDs := map[uuid.UUID]struct{}{}
				for _, m := range page.ProjectMembers {
					gotIDs[m.MemberID] = struct{}{}
				}
				for _, id := range tt.wantMemberIDs {
					_, ok := gotIDs[id]
					require.Truef(t, ok, "missing member %s", id)
				}

				gotMails := map[string]struct{}{}
				for _, inv := range page.ProjectInvitations {
					gotMails[inv.Email] = struct{}{}
				}
				for _, mail := range tt.wantInviteMails {
					_, ok := gotMails[mail]
					require.Truef(t, ok, "missing invite %s", mail)
				}
			})
		}
	})
}
