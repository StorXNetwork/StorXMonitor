// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ console.GoogleBackupCredentials = (*googleBackupCredentials)(nil)

type googleBackupCredentials struct {
	db dbx.DriverMethods
}

// GoogleBackupCredentials is a getter for Google backup OAuth credentials repository.
func (db *ConsoleDB) GoogleBackupCredentials() console.GoogleBackupCredentials {
	return &googleBackupCredentials{db: db.Methods}
}

func (g *googleBackupCredentials) Create(ctx context.Context, credential console.GoogleBackupCredential) (_ *console.GoogleBackupCredential, err error) {
	defer mon.Task()(&ctx)(&err)

	optional := dbx.GoogleBackupCredentials_Create_Fields{}
	if credential.RefreshToken != "" {
		optional.RefreshToken = dbx.GoogleBackupCredentials_RefreshToken(credential.RefreshToken)
	}
	if credential.AccessTokenExpiry != nil {
		optional.AccessTokenExpiry = dbx.GoogleBackupCredentials_AccessTokenExpiry(*credential.AccessTokenExpiry)
	}
	if credential.AccountType != "" {
		optional.AccountType = dbx.GoogleBackupCredentials_AccountType(credential.AccountType)
	}

	row, err := g.db.Create_GoogleBackupCredentials(
		ctx,
		dbx.GoogleBackupCredentials_Id(credential.ID[:]),
		dbx.GoogleBackupCredentials_UserId(credential.UserID[:]),
		dbx.GoogleBackupCredentials_GoogleEmail(credential.GoogleEmail),
		dbx.GoogleBackupCredentials_AccessToken(credential.AccessToken),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return googleBackupCredentialFromDBX(row)
}

func (g *googleBackupCredentials) GetByUserID(ctx context.Context, userID uuid.UUID) (_ *console.GoogleBackupCredential, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := g.db.All_GoogleBackupCredentials_By_UserId(ctx, dbx.GoogleBackupCredentials_UserId(userID[:]))
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
	return googleBackupCredentialFromDBX(latest)
}

func (g *googleBackupCredentials) UpdateAccountType(ctx context.Context, id uuid.UUID, accountType string) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = g.db.Update_GoogleBackupCredentials_By_Id(
		ctx,
		dbx.GoogleBackupCredentials_Id(id[:]),
		dbx.GoogleBackupCredentials_Update_Fields{
			AccountType: dbx.GoogleBackupCredentials_AccountType(accountType),
		},
	)
	return err
}

func (g *googleBackupCredentials) UpdateTokens(ctx context.Context, id uuid.UUID, accessToken, refreshToken string, accessTokenExpiry *time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	update := dbx.GoogleBackupCredentials_Update_Fields{
		AccessToken: dbx.GoogleBackupCredentials_AccessToken(accessToken),
	}
	if refreshToken != "" {
		update.RefreshToken = dbx.GoogleBackupCredentials_RefreshToken(refreshToken)
	}
	if accessTokenExpiry != nil {
		update.AccessTokenExpiry = dbx.GoogleBackupCredentials_AccessTokenExpiry(*accessTokenExpiry)
	}

	_, err = g.db.Update_GoogleBackupCredentials_By_Id(ctx, dbx.GoogleBackupCredentials_Id(id[:]), update)
	return err
}

func googleBackupCredentialFromDBX(row *dbx.GoogleBackupCredentials) (*console.GoogleBackupCredential, error) {
	if row == nil {
		return nil, errors.New("nil google backup credential row")
	}

	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}

	credential := &console.GoogleBackupCredential{
		ID:          id,
		UserID:      userID,
		GoogleEmail: row.GoogleEmail,
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
	return credential, nil
}
