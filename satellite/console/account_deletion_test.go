// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/StorXMonitor/private/testplanet"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestSelfServeAccountDeletionSoftCancelAndLogin(t *testing.T) {
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 0, UplinkCount: 0,
		Reconfigure: testplanet.Reconfigure{
			Satellite: func(log *zap.Logger, index int, config *satellite.Config) {
				config.Console.SelfServeAccountDeleteEnabled = true
			},
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		sat := planet.Satellites[0]
		service := sat.API.Console.Service
		usersDB := sat.DB.Console().Users()

		tests := []struct {
			name string
			run  func(t *testing.T)
		}{
			{
				name: "soft delete sets pending and queue then cancel restores",
				run: func(t *testing.T) {
					user, err := sat.AddUser(ctx, console.CreateUser{
						FullName: "Delete Me",
						Email:    "delete-me@mail.test",
						Password: "password",
					}, 1)
					require.NoError(t, err)

					userCtx := console.WithUser(ctx, user)
					err = service.DeleteAccountRequest(userCtx, console.AccountDeleteRequest{})
					require.NoError(t, err)

					updated, err := usersDB.Get(ctx, user.ID)
					require.NoError(t, err)
					require.Equal(t, console.PendingDeletion, updated.Status)

					req, err := usersDB.GetActiveDeleteRequest(ctx, user.ID)
					require.NoError(t, err)
					require.NotNil(t, req)
					grace := sat.Config.Console.AccountDeleteGracePeriod
					require.True(t, req.DeleteAt.After(time.Now().Add(grace-time.Minute)))
					require.True(t, req.DeleteAt.Before(time.Now().Add(grace+time.Minute)))

					token, err := service.Token(ctx, console.AuthUser{
						Email:    user.Email,
						Password: "password",
					})
					require.NoError(t, err)
					require.True(t, token.AccountPendingDeletion)
					require.NotNil(t, token.DeleteAt)

					pendingCtx := console.WithUser(ctx, updated)
					require.NoError(t, service.CancelAccountDeleteRequest(pendingCtx))

					restored, err := usersDB.Get(ctx, user.ID)
					require.NoError(t, err)
					require.Equal(t, console.Active, restored.Status)

					req, err = usersDB.GetActiveDeleteRequest(ctx, user.ID)
					require.NoError(t, err)
					require.Nil(t, req)
				},
			},
			{
				name: "paid user blocked with active_subscription",
				run: func(t *testing.T) {
					user, err := sat.AddUser(ctx, console.CreateUser{
						FullName: "Paid User",
						Email:    "paid-delete@mail.test",
						Password: "password",
						Kind:     console.PaidUser,
					}, 1)
					require.NoError(t, err)

					err = service.DeleteAccountRequest(console.WithUser(ctx, user), console.AccountDeleteRequest{})
					require.Error(t, err)
					require.True(t, console.ErrForbidden.Has(err))
					require.Contains(t, err.Error(), "active_subscription")
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, tt.run)
		}
	})
}
