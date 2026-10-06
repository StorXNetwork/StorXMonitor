// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
)

func TestBackupCredentialsMicrosoftTenant(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
		credentials := db.Console().BackupCredentials()

		user, err := db.Console().Users().Insert(ctx, &console.User{
			ID:           testrand.UUID(),
			FullName:     "test",
			Email:        "admin@contoso.com",
			PasswordHash: []byte("pass"),
		})
		require.NoError(t, err)
		userID := user.ID

		created, err := credentials.Create(ctx, console.BackupCredential{
			ID:           testrand.UUID(),
			UserID:       userID,
			Provider:     console.BackupProviderMicrosoft,
			Email:        "Admin@Contoso.com",
			AccessToken:  "access",
			RefreshToken: "refresh",
			AccountType:  console.MicrosoftAccountTypeWorkAccount,
			TenantID:     " tenant-1 ",
		})
		require.NoError(t, err)
		require.Equal(t, "admin@contoso.com", created.Email)
		require.Equal(t, "tenant-1", created.TenantID)
		require.Empty(t, created.TenantName)

		got, err := credentials.GetByUserIDAndProvider(ctx, userID, console.BackupProviderMicrosoft)
		require.NoError(t, err)
		require.Equal(t, "tenant-1", got.TenantID)
		require.Equal(t, console.MicrosoftAccountTypeWorkAccount, got.AccountType)

		// A name-only update keeps the stored tenant id.
		require.NoError(t, credentials.UpdateMicrosoftTenant(ctx, created.ID, "", "Contoso"))
		got, err = credentials.GetByUserIDProviderEmail(ctx, userID, console.BackupProviderMicrosoft, "admin@contoso.com")
		require.NoError(t, err)
		require.Equal(t, "tenant-1", got.TenantID)
		require.Equal(t, "Contoso", got.TenantName)

		require.NoError(t, credentials.UpdateMicrosoftTenant(ctx, created.ID, "tenant-2", ""))
		got, err = credentials.GetByUserIDAndProvider(ctx, userID, console.BackupProviderMicrosoft)
		require.NoError(t, err)
		require.Equal(t, "tenant-2", got.TenantID)
		require.Equal(t, "Contoso", got.TenantName)

		require.NoError(t, credentials.UpdateMicrosoftTenant(ctx, created.ID, " ", ""))
		got, err = credentials.GetByUserIDAndProvider(ctx, userID, console.BackupProviderMicrosoft)
		require.NoError(t, err)
		require.Equal(t, "tenant-2", got.TenantID)
	})
}
