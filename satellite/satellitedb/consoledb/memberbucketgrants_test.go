// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
)

func TestMemberBucketACLRepos(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
		consoleDB := db.Console()
		projects := consoleDB.Projects()
		users := consoleDB.Users()
		registry := consoleDB.ProjectMemberACLBuckets()
		grants := consoleDB.MemberBucketGrants()

		ownerID := testrand.UUID()
		memberID := testrand.UUID()
		projectID := testrand.UUID()
		email := "member@mail.test"

		_, err := users.Insert(ctx, &console.User{ID: ownerID, FullName: "Owner", PasswordHash: testrand.Bytes(8)})
		require.NoError(t, err)
		_, err = users.Insert(ctx, &console.User{ID: memberID, FullName: "Member", PasswordHash: testrand.Bytes(8), Email: email})
		require.NoError(t, err)
		_, err = projects.Insert(ctx, &console.Project{ID: projectID, OwnerID: ownerID})
		require.NoError(t, err)

		t.Run("registry starts empty", func(t *testing.T) {
			rows, err := registry.List(ctx, projectID)
			require.NoError(t, err)
			require.Empty(t, rows)
		})

		t.Run("add and list registry buckets", func(t *testing.T) {
			row, err := registry.Add(ctx, projectID, "gmail")
			require.NoError(t, err)
			require.Equal(t, "gmail", row.BucketName)

			_, err = registry.Add(ctx, projectID, "outlook")
			require.NoError(t, err)

			rows, err := registry.List(ctx, projectID)
			require.NoError(t, err)
			require.Len(t, rows, 2)
		})

		t.Run("duplicate registry bucket rejected", func(t *testing.T) {
			_, err := registry.Add(ctx, projectID, "gmail")
			require.Error(t, err)
		})

		t.Run("pending grants then bind on accept", func(t *testing.T) {
			created, err := grants.CreatePending(ctx, projectID, email, []console.MemberBucketGrantInput{
				{Bucket: "gmail", Prefix: email + "/", AllowList: true, AllowDownload: true},
				{Bucket: "outlook", Prefix: email + "/", AllowList: true, AllowDownload: true},
			}, nil)
			require.NoError(t, err)
			require.Len(t, created, 2)
			require.Nil(t, created[0].MemberID)
			require.Equal(t, strings.ToUpper(email), created[0].InviteEmail)

			pending, err := grants.GetByInviteEmail(ctx, projectID, email)
			require.NoError(t, err)
			require.Len(t, pending, 2)

			require.NoError(t, grants.BindPendingToMember(ctx, projectID, email, memberID))

			active, err := grants.GetByMember(ctx, projectID, memberID)
			require.NoError(t, err)
			require.Len(t, active, 2)
			require.NotNil(t, active[0].MemberID)
			require.Equal(t, memberID, *active[0].MemberID)
		})

		t.Run("replace clears and sets grants", func(t *testing.T) {
			replaced, err := grants.ReplaceForMember(ctx, projectID, memberID, email, []console.MemberBucketGrantInput{
				{Bucket: "gmail", Prefix: "other@mail.test/", AllowList: true},
			}, nil)
			require.NoError(t, err)
			require.Len(t, replaced, 1)
			require.Equal(t, "other@mail.test/", replaced[0].Prefix)

			active, err := grants.GetByMember(ctx, projectID, memberID)
			require.NoError(t, err)
			require.Len(t, active, 1)
		})

		t.Run("replace with empty clears access", func(t *testing.T) {
			replaced, err := grants.ReplaceForMember(ctx, projectID, memberID, email, nil, nil)
			require.NoError(t, err)
			require.Empty(t, replaced)

			active, err := grants.GetByMember(ctx, projectID, memberID)
			require.NoError(t, err)
			require.Empty(t, active)
		})

		t.Run("delete by invite email", func(t *testing.T) {
			_, err := grants.CreatePending(ctx, projectID, "pending@mail.test", []console.MemberBucketGrantInput{
				{Bucket: "gmail", Prefix: "pending@mail.test/", AllowList: true},
			}, nil)
			require.NoError(t, err)
			require.NoError(t, grants.DeleteByInviteEmail(ctx, projectID, "pending@mail.test"))
			rows, err := grants.GetByInviteEmail(ctx, projectID, "pending@mail.test")
			require.NoError(t, err)
			require.Empty(t, rows)
		})

		t.Run("remove registry bucket", func(t *testing.T) {
			require.NoError(t, registry.Remove(ctx, projectID, "outlook"))
			rows, err := registry.List(ctx, projectID)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, "gmail", rows[0].BucketName)
		})
	})
}
