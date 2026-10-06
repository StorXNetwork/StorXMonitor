// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/common/uuid"
)

var _ console.BackupCredentials = (*backupCredentials)(nil)

type backupCredentials struct {
	cdb *ConsoleDB
}

// BackupCredentials is a getter for shared backup OAuth credentials repository.
func (db *ConsoleDB) BackupCredentials() console.BackupCredentials {
	return &backupCredentials{cdb: db}
}

// GoogleBackupCredentials keeps the old ConsoleDB accessor name for Google call sites.
func (db *ConsoleDB) GoogleBackupCredentials() console.GoogleBackupCredentials {
	return db.BackupCredentials()
}

func (g *backupCredentials) Create(ctx context.Context, credential console.BackupCredential) (_ *console.BackupCredential, err error) {
	defer mon.Task()(&ctx)(&err)

	provider := strings.TrimSpace(strings.ToLower(credential.Provider))
	if provider == "" {
		provider = console.BackupProviderGoogle
	}
	email := strings.TrimSpace(strings.ToLower(credential.Email))

	optional := dbx.BackupCredentials_Create_Fields{}
	if credential.RefreshToken != "" {
		optional.RefreshToken = dbx.BackupCredentials_RefreshToken(credential.RefreshToken)
	}
	if credential.AccessTokenExpiry != nil {
		optional.AccessTokenExpiry = dbx.BackupCredentials_AccessTokenExpiry(*credential.AccessTokenExpiry)
	}
	if credential.AccountType != "" {
		optional.AccountType = dbx.BackupCredentials_AccountType(credential.AccountType)
	}
	if tenantID := strings.TrimSpace(credential.TenantID); tenantID != "" {
		optional.TenantId = dbx.BackupCredentials_TenantId(tenantID)
	}
	if tenantName := strings.TrimSpace(credential.TenantName); tenantName != "" {
		optional.TenantName = dbx.BackupCredentials_TenantName(tenantName)
	}

	row, err := g.cdb.Create_BackupCredentials(
		ctx,
		dbx.BackupCredentials_Id(credential.ID[:]),
		dbx.BackupCredentials_UserId(credential.UserID[:]),
		dbx.BackupCredentials_Provider(provider),
		dbx.BackupCredentials_Email(email),
		dbx.BackupCredentials_AccessToken(credential.AccessToken),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return backupCredentialFromDBX(row)
}

func (g *backupCredentials) GetByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (_ *console.BackupCredential, err error) {
	defer mon.Task()(&ctx)(&err)

	provider = strings.TrimSpace(strings.ToLower(provider))
	if provider == "" {
		return nil, sql.ErrNoRows
	}

	rows, err := g.cdb.All_BackupCredentials_By_UserId_And_Provider(ctx,
		dbx.BackupCredentials_UserId(userID[:]),
		dbx.BackupCredentials_Provider(provider),
	)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, sql.ErrNoRows
	}

	latest := rows[0]
	for _, row := range rows[1:] {
		if row.UpdatedAt.After(latest.UpdatedAt) {
			latest = row
		}
	}
	return backupCredentialFromDBX(latest)
}

func (g *backupCredentials) GetByUserIDProviderEmail(ctx context.Context, userID uuid.UUID, provider, email string) (_ *console.BackupCredential, err error) {
	defer mon.Task()(&ctx)(&err)

	provider = strings.TrimSpace(strings.ToLower(provider))
	email = strings.TrimSpace(strings.ToLower(email))
	if provider == "" || email == "" {
		return nil, sql.ErrNoRows
	}

	rows, err := g.cdb.All_BackupCredentials_By_UserId_And_Provider(ctx,
		dbx.BackupCredentials_UserId(userID[:]),
		dbx.BackupCredentials_Provider(provider),
	)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		if strings.EqualFold(row.Email, email) {
			return backupCredentialFromDBX(row)
		}
	}
	return nil, sql.ErrNoRows
}

func (g *backupCredentials) UpdateAccountType(ctx context.Context, id uuid.UUID, accountType string) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = g.cdb.Update_BackupCredentials_By_Id(
		ctx,
		dbx.BackupCredentials_Id(id[:]),
		dbx.BackupCredentials_Update_Fields{
			AccountType: dbx.BackupCredentials_AccountType(accountType),
		},
	)
	return err
}

func (g *backupCredentials) UpdateMicrosoftTenant(ctx context.Context, id uuid.UUID, tenantID, tenantName string) (err error) {
	defer mon.Task()(&ctx)(&err)

	tenantID = strings.TrimSpace(tenantID)
	tenantName = strings.TrimSpace(tenantName)
	if tenantID == "" && tenantName == "" {
		return nil
	}

	update := dbx.BackupCredentials_Update_Fields{}
	if tenantID != "" {
		update.TenantId = dbx.BackupCredentials_TenantId(tenantID)
	}
	if tenantName != "" {
		update.TenantName = dbx.BackupCredentials_TenantName(tenantName)
	}
	_, err = g.cdb.Update_BackupCredentials_By_Id(ctx, dbx.BackupCredentials_Id(id[:]), update)
	return err
}

func (g *backupCredentials) UpdateTokens(ctx context.Context, id uuid.UUID, accessToken, refreshToken string, accessTokenExpiry *time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	update := dbx.BackupCredentials_Update_Fields{
		AccessToken: dbx.BackupCredentials_AccessToken(accessToken),
	}
	if refreshToken != "" {
		update.RefreshToken = dbx.BackupCredentials_RefreshToken(refreshToken)
	}
	if accessTokenExpiry != nil {
		update.AccessTokenExpiry = dbx.BackupCredentials_AccessTokenExpiry(*accessTokenExpiry)
	}

	_, err = g.cdb.Update_BackupCredentials_By_Id(ctx, dbx.BackupCredentials_Id(id[:]), update)
	return err
}

func (g *backupCredentials) ClearTokens(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = g.cdb.Update_BackupCredentials_By_Id(
		ctx,
		dbx.BackupCredentials_Id(id[:]),
		dbx.BackupCredentials_Update_Fields{
			AccessToken:       dbx.BackupCredentials_AccessToken(""),
			RefreshToken:      dbx.BackupCredentials_RefreshToken_Null(),
			AccessTokenExpiry: dbx.BackupCredentials_AccessTokenExpiry_Null(),
		},
	)
	return err
}

// DeleteAllByUserID removes all backup credentials for the user.
func (g *backupCredentials) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = g.cdb.ExecContext(ctx, g.cdb.Rebind(`
		DELETE FROM backup_credentials WHERE user_id = ?
	`), userID[:])
	return err
}

func backupCredentialFromDBX(row *dbx.BackupCredentials) (*console.BackupCredential, error) {
	if row == nil {
		return nil, errors.New("nil backup credential row")
	}

	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}

	credential := &console.BackupCredential{
		ID:          id,
		UserID:      userID,
		Provider:    row.Provider,
		Email:       row.Email,
		AccessToken: row.AccessToken,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	if row.RefreshToken != nil {
		credential.RefreshToken = *row.RefreshToken
	}
	if row.AccessTokenExpiry != nil {
		credential.AccessTokenExpiry = row.AccessTokenExpiry
	}
	if row.AccountType != nil {
		credential.AccountType = *row.AccountType
	}
	if row.TenantId != nil {
		credential.TenantID = *row.TenantId
	}
	if row.TenantName != nil {
		credential.TenantName = *row.TenantName
	}
	return credential, nil
}
