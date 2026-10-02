// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ console.StorageDestinations = (*storageDestinations)(nil)

type storageDestinations struct {
	db *dbx.DB
}

// GetByUserID returns the storage destination for the user.
func (s *storageDestinations) GetByUserID(ctx context.Context, userID uuid.UUID) (dest *console.StorageDestination, err error) {
	defer mon.Task()(&ctx)(&err)

	row := s.db.QueryRowContext(ctx, s.db.Rebind(`
		SELECT user_id, mode, gateway_access_key_id, gateway_secret_key, gateway_endpoint, updated_at
		FROM user_storage_destinations
		WHERE user_id = ?
	`), userID[:])

	d, err := scanStorageDestination(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrStorageDestinationNotFound.New("")
		}
		return nil, Error.Wrap(err)
	}
	return &d, nil
}

// Upsert inserts or updates the storage destination.
func (s *storageDestinations) Upsert(ctx context.Context, dest *console.StorageDestination) (err error) {
	defer mon.Task()(&ctx)(&err)

	if dest == nil {
		return console.ErrStorageDestinationInvalid.New("nil destination")
	}
	now := time.Now().UTC()
	dest.UpdatedAt = now

	_, getErr := s.GetByUserID(ctx, dest.UserID)
	if getErr == nil {
		_, err = s.db.ExecContext(ctx, s.db.Rebind(`
			UPDATE user_storage_destinations SET
				mode = ?,
				gateway_access_key_id = ?,
				gateway_secret_key = ?,
				gateway_endpoint = ?,
				updated_at = ?
			WHERE user_id = ?
		`),
			dest.Mode,
			nullIfEmpty(dest.GatewayAccessKeyID),
			nullIfEmpty(dest.GatewaySecretKey),
			nullIfEmpty(dest.GatewayEndpoint),
			now,
			dest.UserID[:],
		)
		return Error.Wrap(err)
	}
	if !console.ErrStorageDestinationNotFound.Has(getErr) {
		return Error.Wrap(getErr)
	}

	_, err = s.db.ExecContext(ctx, s.db.Rebind(`
		INSERT INTO user_storage_destinations (
			user_id, mode, gateway_access_key_id, gateway_secret_key, gateway_endpoint, updated_at
		) VALUES (?, ?, ?, ?, ?, ?)
	`),
		dest.UserID[:],
		dest.Mode,
		nullIfEmpty(dest.GatewayAccessKeyID),
		nullIfEmpty(dest.GatewaySecretKey),
		nullIfEmpty(dest.GatewayEndpoint),
		now,
	)
	if err != nil && dbx.IsConstraintError(err) {
		// Race: another writer inserted first — retry as update.
		_, err = s.db.ExecContext(ctx, s.db.Rebind(`
			UPDATE user_storage_destinations SET
				mode = ?,
				gateway_access_key_id = ?,
				gateway_secret_key = ?,
				gateway_endpoint = ?,
				updated_at = ?
			WHERE user_id = ?
		`),
			dest.Mode,
			nullIfEmpty(dest.GatewayAccessKeyID),
			nullIfEmpty(dest.GatewaySecretKey),
			nullIfEmpty(dest.GatewayEndpoint),
			now,
			dest.UserID[:],
		)
	}
	return Error.Wrap(err)
}

// Delete removes the storage destination row.
func (s *storageDestinations) Delete(ctx context.Context, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = s.db.ExecContext(ctx, s.db.Rebind(`
		DELETE FROM user_storage_destinations WHERE user_id = ?
	`), userID[:])
	return Error.Wrap(err)
}

func nullIfEmpty(s string) interface{} {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return s
}

type storageDestScannable interface {
	Scan(dest ...interface{}) error
}

func scanStorageDestination(row storageDestScannable) (console.StorageDestination, error) {
	var (
		userIDRaw []byte
		mode      string
		accessKey sql.NullString
		secretKey sql.NullString
		endpoint  sql.NullString
		updatedAt time.Time
	)
	if err := row.Scan(&userIDRaw, &mode, &accessKey, &secretKey, &endpoint, &updatedAt); err != nil {
		return console.StorageDestination{}, err
	}
	userID, err := uuid.FromBytes(userIDRaw)
	if err != nil {
		return console.StorageDestination{}, err
	}
	return console.StorageDestination{
		UserID:             userID,
		Mode:               mode,
		GatewayAccessKeyID: accessKey.String,
		GatewaySecretKey:   secretKey.String,
		GatewayEndpoint:    endpoint.String,
		UpdatedAt:          updatedAt,
	}, nil
}
