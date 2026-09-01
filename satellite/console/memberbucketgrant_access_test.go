// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/grant"
	"github.com/StorXNetwork/common/macaroon"
	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/private/testplanet"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/secretconstants"
)

func init() {
	// NewAPI requires a non-empty Web3Auth private key; inject a test key when unset.
	if secretconstants.Web3AuthPrivateKey == "" {
		secretconstants.Web3AuthPrivateKey = "3005822d22ae044a3c83683fcdb199fbf5bcbcabc95f2fc8e1b212fe3b7c7710"
	}
}

// configureConsoleForTestPlanet sets console fields required for satellite API/Admin startup in tests.
func configureConsoleForTestPlanet(config *satellite.Config) {
	config.Console.Web3AuthNetworkRPC = "https://erpc.xinfin.network"
	config.Console.Web3AuthContractAddress = "0x8E589D1E3d0F4189cbFe05703dE840678e402ffC"
	config.Console.Web3AuthAddress = "0x29a2F6D5b749b5882DfE866772d656FCaae63E0D"
	config.Console.DeveloperExternalAddress = "http://127.0.0.1:0"
}

// createNamedAPIKey creates a project API key with a unique name (testplanet.CreateAPIKey always uses "root").
func createNamedAPIKey(t *testing.T, ctx *testcontext.Context, sat *testplanet.Satellite, projectID, userID uuid.UUID, name string) *macaroon.APIKey {
	t.Helper()
	secret, err := macaroon.NewSecret()
	require.NoError(t, err)
	key, err := macaroon.NewAPIKey(secret)
	require.NoError(t, err)
	_, err = sat.DB.Console().APIKeys().Create(ctx, key.Head(), console.APIKeyInfo{
		Name:      name,
		ProjectID: projectID,
		CreatedBy: userID,
		Secret:    secret,
		Version:   macaroon.APIKeyVersionMin,
	})
	require.NoError(t, err)
	return key
}

// TestMemberBucketACL_ExistingAccessUnaffected verifies the common one-user / one-project
// path and other existing access roles are unchanged when the ACL feature is OFF, and that
// Owner/Admin still bypass restrictions when the feature is ON.
func TestMemberBucketACL_ExistingAccessUnaffected(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 0,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(_ *zap.Logger, _ int, config *satellite.Config) {
				configureConsoleForTestPlanet(config)
				config.Console.OpenRegistrationEnabled = true
				config.Console.MemberBucketGrantsEnabled = false
			},
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		service := sat.API.Console.Service

		owner, err := sat.AddUser(ctx, console.CreateUser{
			FullName: "Owner User",
			Email:    "owneraccess@mail.test",
		}, 1)
		require.NoError(t, err)
		kind := console.PaidUser
		require.NoError(t, sat.DB.Console().Users().Update(ctx, owner.ID, console.UpdateUserRequest{Kind: &kind}))

		project, err := sat.AddProject(ctx, owner.ID, "solo-project")
		require.NoError(t, err)

		ownerCtx, err := sat.UserContext(ctx, owner.ID)
		require.NoError(t, err)

		apiKey := createNamedAPIKey(t, ctx, sat, project.ID, owner.ID, "owner-root")

		tests := []struct {
			name       string
			prefixes   []grant.SharePrefix
			permission *grant.Permission
		}{
			{name: "owner unrestricted grant", prefixes: nil, permission: nil},
			{
				name:       "owner restricted bucket still ok",
				prefixes:   []grant.SharePrefix{{Bucket: "any-bucket", Prefix: ""}},
				permission: &grant.Permission{AllowList: true, AllowDownload: true},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ag, err := service.CreateAccessGrantForProject(ownerCtx, project.ID, "passphrase", tt.prefixes, tt.permission, apiKey)
				require.NoError(t, err)
				require.NotEmpty(t, ag)
			})
		}

		// Existing Member role with feature OFF must still mint unrestricted credentials.
		member, err := sat.AddUser(ctx, console.CreateUser{
			FullName: "Legacy Member",
			Email:    "legacymember@mail.test",
		}, 1)
		require.NoError(t, err)
		_, err = sat.DB.Console().ProjectMembers().Insert(ctx, member.ID, project.ID, console.RoleMember)
		require.NoError(t, err)

		memberCtx, err := sat.UserContext(ctx, member.ID)
		require.NoError(t, err)
		memberKey := createNamedAPIKey(t, ctx, sat, project.ID, member.ID, "legacy-member-key")

		ag, err := service.CreateAccessGrantForProject(memberCtx, project.ID, "passphrase", nil, nil, memberKey)
		require.NoError(t, err, "feature OFF: Member unrestricted AG must still work")
		require.NotEmpty(t, ag)
	})
}

// TestMemberBucketACL_AccessMatrix covers Owner/Admin bypass, Member fail-closed, and
// invite/registry grant lifecycle when the feature is enabled.
func TestMemberBucketACL_AccessMatrix(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 0,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(_ *zap.Logger, _ int, config *satellite.Config) {
				configureConsoleForTestPlanet(config)
				config.Console.OpenRegistrationEnabled = true
				config.Console.MemberBucketGrantsEnabled = true
			},
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		service := sat.API.Console.Service
		consoleDB := sat.DB.Console()

		owner, err := sat.AddUser(ctx, console.CreateUser{
			FullName: "ACL Owner",
			Email:    "aclowner@mail.test",
		}, 1)
		require.NoError(t, err)
		kind := console.PaidUser
		require.NoError(t, consoleDB.Users().Update(ctx, owner.ID, console.UpdateUserRequest{Kind: &kind}))

		project, err := sat.AddProject(ctx, owner.ID, "acl-project")
		require.NoError(t, err)

		_, err = sat.API.Buckets.Service.CreateBucket(ctx, buckets.Bucket{
			ID:        testrand.UUID(),
			Name:      "gmail",
			ProjectID: project.ID,
			Created:   time.Now(),
		})
		require.NoError(t, err)

		ownerCtx, err := sat.UserContext(ctx, owner.ID)
		require.NoError(t, err)
		ownerKey := createNamedAPIKey(t, ctx, sat, project.ID, owner.ID, "acl-owner-key")

		t.Run("owner unrestricted still works with feature on", func(t *testing.T) {
			ag, err := service.CreateAccessGrantForProject(ownerCtx, project.ID, "passphrase", nil, nil, ownerKey)
			require.NoError(t, err)
			require.NotEmpty(t, ag)
		})

		t.Run("admin unrestricted still works with feature on", func(t *testing.T) {
			admin, err := sat.AddUser(ctx, console.CreateUser{
				FullName: "ACL Admin",
				Email:    "acladmin@mail.test",
			}, 1)
			require.NoError(t, err)
			_, err = consoleDB.ProjectMembers().Insert(ctx, admin.ID, project.ID, console.RoleAdmin)
			require.NoError(t, err)

			adminCtx, err := sat.UserContext(ctx, admin.ID)
			require.NoError(t, err)
			adminKey := createNamedAPIKey(t, ctx, sat, project.ID, admin.ID, "acl-admin-key")

			ag, err := service.CreateAccessGrantForProject(adminCtx, project.ID, "passphrase", nil, nil, adminKey)
			require.NoError(t, err)
			require.NotEmpty(t, ag)
		})

		memberEmail := "aclmember@mail.test"
		member, err := sat.AddUser(ctx, console.CreateUser{
			FullName: "ACL Member",
			Email:    memberEmail,
		}, 1)
		require.NoError(t, err)
		_, err = consoleDB.ProjectMembers().Insert(ctx, member.ID, project.ID, console.RoleMember)
		require.NoError(t, err)

		memberCtx, err := sat.UserContext(ctx, member.ID)
		require.NoError(t, err)
		memberKey := createNamedAPIKey(t, ctx, sat, project.ID, member.ID, "acl-member-key")

		t.Run("member without grants cannot mint unrestricted", func(t *testing.T) {
			_, err := service.CreateAccessGrantForProject(memberCtx, project.ID, "passphrase", nil, nil, memberKey)
			require.Error(t, err)
			require.True(t, console.ErrForbidden.Has(err))
		})

		_, err = service.AddProjectMemberACLBucket(ownerCtx, project.ID, "gmail")
		require.NoError(t, err)

		prefix := memberEmail + "/"
		_, err = service.ReplaceMemberBucketGrants(ownerCtx, project.ID, member.ID, []console.MemberBucketGrantInput{{
			Bucket: "gmail", Prefix: prefix, AllowList: true, AllowDownload: true,
		}}, "")
		require.NoError(t, err)

		agCases := []struct {
			name       string
			prefixes   []grant.SharePrefix
			permission *grant.Permission
			wantErr    bool
		}{
			{
				name:     "member own prefix list download ok",
				prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: prefix}},
				permission: &grant.Permission{
					AllowList: true, AllowDownload: true, AllowUpload: true,
				},
			},
			{
				name:     "member child prefix ok",
				prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: prefix + "inbox/"}},
				permission: &grant.Permission{
					AllowList: true, AllowDownload: true,
				},
			},
			{
				name:     "member other email deny",
				prefixes: []grant.SharePrefix{{Bucket: "gmail", Prefix: "other@mail.test/"}},
				permission: &grant.Permission{
					AllowList: true, AllowDownload: true,
				},
				wantErr: true,
			},
			{
				name:     "member other bucket deny",
				prefixes: []grant.SharePrefix{{Bucket: "outlook", Prefix: prefix}},
				permission: &grant.Permission{
					AllowList: true, AllowDownload: true,
				},
				wantErr: true,
			},
			{
				name:     "member unrestricted deny",
				prefixes: nil, permission: nil,
				wantErr: true,
			},
		}

		for _, tc := range agCases {
			t.Run(tc.name, func(t *testing.T) {
				ag, err := service.CreateAccessGrantForProject(memberCtx, project.ID, "passphrase", tc.prefixes, tc.permission, memberKey)
				if tc.wantErr {
					require.Error(t, err)
					require.True(t, console.ErrForbidden.Has(err))
					return
				}
				require.NoError(t, err)
				require.NotEmpty(t, ag)
			})
		}

		t.Run("invite defaults from registry then accept binds", func(t *testing.T) {
			inviteEmail := "inviteeacl@mail.test"
			invitee, err := sat.AddUser(ctx, console.CreateUser{
				FullName: "Invitee ACL",
				Email:    inviteEmail,
			}, 1)
			require.NoError(t, err)

			_, err = service.InviteNewProjectMember(ownerCtx, project.ID, inviteEmail, nil)
			require.NoError(t, err)

			pending, err := consoleDB.MemberBucketGrants().GetByInviteEmail(ctx, project.ID, inviteEmail)
			require.NoError(t, err)
			require.Len(t, pending, 1)
			require.Equal(t, "gmail", pending[0].Bucket)
			require.Equal(t, inviteEmail+"/", pending[0].Prefix)
			require.Nil(t, pending[0].MemberID)

			inviteeCtx, err := sat.UserContext(ctx, invitee.ID)
			require.NoError(t, err)
			require.NoError(t, service.RespondToProjectInvitation(inviteeCtx, project.ID, console.ProjectInvitationAccept))

			active, err := consoleDB.MemberBucketGrants().GetByMember(ctx, project.ID, invitee.ID)
			require.NoError(t, err)
			require.Len(t, active, 1)
			require.NotNil(t, active[0].MemberID)
			require.Equal(t, invitee.ID, *active[0].MemberID)

			_, err = consoleDB.ProjectInvitations().Get(ctx, project.ID, inviteEmail)
			require.Error(t, err)
		})

		t.Run("empty registry invite creates no default grants", func(t *testing.T) {
			project2, err := sat.AddProject(ctx, owner.ID, "empty-registry")
			require.NoError(t, err)

			email := "emptyreg@mail.test"
			_, err = sat.AddUser(ctx, console.CreateUser{FullName: "Empty Reg", Email: email}, 1)
			require.NoError(t, err)

			_, err = service.InviteNewProjectMember(ownerCtx, project2.ID, email, nil)
			require.NoError(t, err)

			pending, err := consoleDB.MemberBucketGrants().GetByInviteEmail(ctx, project2.ID, email)
			require.NoError(t, err)
			require.Empty(t, pending)
		})

		t.Run("grants empty clears member access", func(t *testing.T) {
			_, err := service.ReplaceMemberBucketGrants(ownerCtx, project.ID, member.ID, []console.MemberBucketGrantInput{}, "")
			require.NoError(t, err)

			_, err = service.CreateAccessGrantForProject(memberCtx, project.ID, "passphrase",
				[]grant.SharePrefix{{Bucket: "gmail", Prefix: prefix}},
				&grant.Permission{AllowList: true, AllowDownload: true},
				memberKey,
			)
			require.Error(t, err)
			require.True(t, console.ErrForbidden.Has(err))
		})
	})
}
