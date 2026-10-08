// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
)

func insertBackupCredentialTestUser(ctx *testcontext.Context, t *testing.T, db satellite.DB, email string) *console.User {
	user, err := db.Console().Users().Insert(ctx, &console.User{
		ID:           testrand.UUID(),
		FullName:     "test",
		Email:        email,
		PasswordHash: []byte("pass"),
	})
	require.NoError(t, err)
	return user
}

func TestBackupCredentialsMicrosoftTenant(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
		credentials := db.Console().BackupCredentials()
		userID := insertBackupCredentialTestUser(ctx, t, db, "admin@contoso.com").ID

		created, err := credentials.Create(ctx, console.BackupCredential{
			ID:                testrand.UUID(),
			UserID:            userID,
			Provider:          console.BackupProviderMicrosoft,
			Email:             "Admin@Contoso.com",
			ExternalAccountID: "OID-1",
			AccessToken:       "access",
			RefreshToken:      "refresh",
			AccountType:       console.MicrosoftAccountTypeWorkAccount,
			TenantID:          " tenant-1 ",
		})
		require.NoError(t, err)
		require.Equal(t, "admin@contoso.com", created.Email)
		require.Equal(t, "oid-1", created.ExternalAccountID)
		require.Equal(t, "tenant-1", created.TenantID)
		require.Equal(t, "tenant-1", created.HomeTenantID())
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

func TestBackupCredentialsExternalAccountID(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
		credentials := db.Console().BackupCredentials()
		userID := insertBackupCredentialTestUser(ctx, t, db, "owner@storx.test").ID
		otherUserID := insertBackupCredentialTestUser(ctx, t, db, "other@storx.test").ID

		newMicrosoft := func(userID uuid.UUID, email, oid, tenant string) console.BackupCredential {
			return console.BackupCredential{
				ID:                testrand.UUID(),
				UserID:            userID,
				Provider:          console.BackupProviderMicrosoft,
				Email:             email,
				ExternalAccountID: oid,
				AccessToken:       "access",
				RefreshToken:      "refresh-" + oid,
				TenantID:          tenant,
			}
		}

		first, err := credentials.Create(ctx, newMicrosoft(userID, "alice@contoso.com", "oid-a", "tenant-a"))
		require.NoError(t, err)

		t.Run("two microsoft accounts for one user", func(t *testing.T) {
			second, err := credentials.Create(ctx, newMicrosoft(userID, "alice@fabrikam.com", "oid-b", "tenant-b"))
			require.NoError(t, err)

			list, err := credentials.ListByUserIDAndProvider(ctx, userID, console.BackupProviderMicrosoft)
			require.NoError(t, err)
			require.Len(t, list, 2)
			require.ElementsMatch(t, []uuid.UUID{first.ID, second.ID}, []uuid.UUID{list[0].ID, list[1].ID})

			got, err := credentials.GetByUserIDProviderAndAccount(ctx, userID, console.BackupProviderMicrosoft, "OID-B")
			require.NoError(t, err)
			require.Equal(t, second.ID, got.ID)
			require.Equal(t, "tenant-b", got.HomeTenantID())
		})

		t.Run("same account twice for one user is rejected", func(t *testing.T) {
			_, err := credentials.Create(ctx, newMicrosoft(userID, "renamed@contoso.com", "oid-a", "tenant-a"))
			require.Error(t, err)
		})

		t.Run("same account for another user is allowed", func(t *testing.T) {
			_, err := credentials.Create(ctx, newMicrosoft(otherUserID, "alice@contoso.com", "oid-a", "tenant-a"))
			require.NoError(t, err)

			list, err := credentials.ListByUserIDAndProvider(ctx, userID, console.BackupProviderMicrosoft)
			require.NoError(t, err)
			require.Len(t, list, 2)
		})

		t.Run("email is a label", func(t *testing.T) {
			require.NoError(t, credentials.UpdateEmail(ctx, first.ID, "Alice.New@Contoso.com"))
			got, err := credentials.GetByID(ctx, first.ID)
			require.NoError(t, err)
			require.Equal(t, "alice.new@contoso.com", got.Email)
			require.Equal(t, "oid-a", got.ExternalAccountID)
		})

		t.Run("lookups miss", func(t *testing.T) {
			_, err := credentials.GetByID(ctx, testrand.UUID())
			require.True(t, errors.Is(err, sql.ErrNoRows))

			_, err = credentials.GetByUserIDProviderAndAccount(ctx, userID, console.BackupProviderMicrosoft, "oid-missing")
			require.True(t, errors.Is(err, sql.ErrNoRows))

			list, err := credentials.ListByUserIDAndProvider(ctx, userID, console.BackupProviderGoogle)
			require.NoError(t, err)
			require.Empty(t, list)
		})
	})
}

func TestBackupCredentialsGoogleUnchanged(t *testing.T) {
	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
		credentials := db.Console().BackupCredentials()
		userID := insertBackupCredentialTestUser(ctx, t, db, "owner@storx.test").ID

		created, err := credentials.Create(ctx, console.BackupCredential{
			ID:           testrand.UUID(),
			UserID:       userID,
			Provider:     console.BackupProviderGoogle,
			Email:        "User@Gmail.com",
			AccessToken:  "access",
			RefreshToken: "refresh",
		})
		require.NoError(t, err)
		require.Equal(t, "user@gmail.com", created.ExternalAccountID)

		got, err := credentials.GetByUserIDProviderEmail(ctx, userID, console.BackupProviderGoogle, "user@gmail.com")
		require.NoError(t, err)
		require.Equal(t, created.ID, got.ID)

		got, err = credentials.GetByUserIDAndProvider(ctx, userID, console.BackupProviderGoogle)
		require.NoError(t, err)
		require.Equal(t, created.ID, got.ID)

		// One Google credential per mailbox, as before.
		_, err = credentials.Create(ctx, console.BackupCredential{
			ID:          testrand.UUID(),
			UserID:      userID,
			Provider:    console.BackupProviderGoogle,
			Email:       "user@gmail.com",
			AccessToken: "access",
		})
		require.Error(t, err)

		// A Microsoft account with the same email is a different credential.
		_, err = credentials.Create(ctx, console.BackupCredential{
			ID:                testrand.UUID(),
			UserID:            userID,
			Provider:          console.BackupProviderMicrosoft,
			Email:             "user@gmail.com",
			ExternalAccountID: "oid-1",
			AccessToken:       "access",
		})
		require.NoError(t, err)
	})
}
