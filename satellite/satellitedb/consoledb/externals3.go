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

var _ console.ExternalS3Backends = (*externalS3Backends)(nil)

type externalS3Backends struct {
	db *dbx.DB
}

// GetByUserID returns the external S3 backend for the user.
func (e *externalS3Backends) GetByUserID(ctx context.Context, userID uuid.UUID) (backend *console.ExternalS3Backend, err error) {
	defer mon.Task()(&ctx)(&err)

	row := e.db.QueryRowContext(ctx, e.db.Rebind(`
		SELECT user_id, status, endpoint, region, access_key_id,
			secret_enc, secret_key_id,
			gateway_access_key_id, gateway_secret_enc, gateway_secret_key_id, gateway_endpoint,
			created_at, updated_at
		FROM user_external_s3_backends
		WHERE user_id = ?
	`), userID[:])

	b, err := scanExternalS3Backend(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrExternalS3NotFound.New("")
		}
		return nil, Error.Wrap(err)
	}
	return &b, nil
}

// Upsert inserts or updates the external S3 backend.
func (e *externalS3Backends) Upsert(ctx context.Context, backend *console.ExternalS3Backend) (err error) {
	defer mon.Task()(&ctx)(&err)
	if backend == nil {
		return console.ErrExternalS3Invalid.New("nil backend")
	}
	now := time.Now().UTC()
	backend.UpdatedAt = now
	if backend.CreatedAt.IsZero() {
		backend.CreatedAt = now
	}

	_, getErr := e.GetByUserID(ctx, backend.UserID)
	if getErr == nil {
		_, err = e.db.ExecContext(ctx, e.db.Rebind(`
			UPDATE user_external_s3_backends SET
				status = ?,
				endpoint = ?,
				region = ?,
				access_key_id = ?,
				secret_enc = ?,
				secret_key_id = ?,
				gateway_access_key_id = ?,
				gateway_secret_enc = ?,
				gateway_secret_key_id = ?,
				gateway_endpoint = ?,
				updated_at = ?
			WHERE user_id = ?
		`),
			backend.Status,
			backend.Endpoint,
			nullIfEmpty(backend.Region),
			backend.AccessKeyID,
			backend.SecretEnc,
			backend.SecretKeyID,
			nullIfEmpty(backend.GatewayAccessKeyID),
			nullableBytes(backend.GatewaySecretEnc),
			nullableInt(backend.GatewaySecretKeyID, len(backend.GatewaySecretEnc) > 0),
			nullIfEmpty(backend.GatewayEndpoint),
			now,
			backend.UserID[:],
		)
		return Error.Wrap(err)
	}
	if !console.ErrExternalS3NotFound.Has(getErr) {
		return Error.Wrap(getErr)
	}

	_, err = e.db.ExecContext(ctx, e.db.Rebind(`
		INSERT INTO user_external_s3_backends (
			user_id, status, endpoint, region, access_key_id,
			secret_enc, secret_key_id,
			gateway_access_key_id, gateway_secret_enc, gateway_secret_key_id, gateway_endpoint,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		backend.UserID[:],
		backend.Status,
		backend.Endpoint,
		nullIfEmpty(backend.Region),
		backend.AccessKeyID,
		backend.SecretEnc,
		backend.SecretKeyID,
		nullIfEmpty(backend.GatewayAccessKeyID),
		nullableBytes(backend.GatewaySecretEnc),
		nullableInt(backend.GatewaySecretKeyID, len(backend.GatewaySecretEnc) > 0),
		nullIfEmpty(backend.GatewayEndpoint),
		backend.CreatedAt,
		now,
	)
	if err != nil && dbx.IsConstraintError(err) {
		return e.Upsert(ctx, backend)
	}
	return Error.Wrap(err)
}

// Delete removes the external S3 backend row.
func (e *externalS3Backends) Delete(ctx context.Context, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = e.db.ExecContext(ctx, e.db.Rebind(`
		DELETE FROM user_external_s3_backends WHERE user_id = ?
	`), userID[:])
	return Error.Wrap(err)
}

func nullableBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullableInt(v int, set bool) interface{} {
	if !set {
		return nil
	}
	return v
}

func scanExternalS3Backend(row scannable) (console.ExternalS3Backend, error) {
	var (
		userIDRaw          []byte
		status             string
		endpoint           string
		region             sql.NullString
		accessKeyID        string
		secretEnc          []byte
		secretKeyID        int
		gatewayAccessKeyID sql.NullString
		gatewaySecretEnc   []byte
		gatewaySecretKeyID sql.NullInt64
		gatewayEndpoint    sql.NullString
		createdAt          time.Time
		updatedAt          time.Time
	)
	if err := row.Scan(
		&userIDRaw, &status, &endpoint, &region, &accessKeyID,
		&secretEnc, &secretKeyID,
		&gatewayAccessKeyID, &gatewaySecretEnc, &gatewaySecretKeyID, &gatewayEndpoint,
		&createdAt, &updatedAt,
	); err != nil {
		return console.ExternalS3Backend{}, err
	}
	userID, err := uuid.FromBytes(userIDRaw)
	if err != nil {
		return console.ExternalS3Backend{}, err
	}
	b := console.ExternalS3Backend{
		UserID:             userID,
		Status:             status,
		Endpoint:           endpoint,
		Region:             region.String,
		AccessKeyID:        accessKeyID,
		SecretEnc:          secretEnc,
		SecretKeyID:        secretKeyID,
		GatewayAccessKeyID: gatewayAccessKeyID.String,
		GatewaySecretEnc:   gatewaySecretEnc,
		GatewayEndpoint:    gatewayEndpoint.String,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
	}
	if gatewaySecretKeyID.Valid {
		b.GatewaySecretKeyID = int(gatewaySecretKeyID.Int64)
	}
	return b, nil
}
