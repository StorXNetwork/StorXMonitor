// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ seller.ResellerResetPasswordTokens = (*resellerResetPasswordTokens)(nil)

type resellerResetPasswordTokens struct {
	db *satelliteDB
}

func (rpt *resellerResetPasswordTokens) Create(ctx context.Context, ownerID uuid.UUID) (secret string, err error) {
	defer mon.Task()(&ctx)(&err)

	secretBytes, err := console.NewResetPasswordSecret()
	if err != nil {
		return "", err
	}

	_, err = rpt.db.Create_ResetPasswordTokenReseller(ctx,
		dbx.ResetPasswordTokenReseller_Secret(secretBytes[:]),
		dbx.ResetPasswordTokenReseller_OwnerId(ownerID[:]),
	)
	if err != nil {
		return "", err
	}

	return secretBytes.String(), nil
}

func (rpt *resellerResetPasswordTokens) GetBySecret(ctx context.Context, secret string) (ownerID uuid.UUID, createdAt time.Time, err error) {
	defer mon.Task()(&ctx)(&err)

	secretBytes, err := console.ResetPasswordSecretFromBase64(secret)
	if err != nil {
		return uuid.UUID{}, time.Time{}, err
	}

	token, err := rpt.db.Get_ResetPasswordTokenReseller_By_Secret(ctx, dbx.ResetPasswordTokenReseller_Secret(secretBytes[:]))
	if err != nil {
		return uuid.UUID{}, time.Time{}, err
	}

	ownerID, err = uuid.FromBytes(token.OwnerId)
	if err != nil {
		return uuid.UUID{}, time.Time{}, err
	}

	return ownerID, token.CreatedAt, nil
}

func (rpt *resellerResetPasswordTokens) GetByOwnerID(ctx context.Context, ownerID uuid.UUID) (secret string, createdAt time.Time, err error) {
	defer mon.Task()(&ctx)(&err)

	token, err := rpt.db.Get_ResetPasswordTokenReseller_By_OwnerId(ctx, dbx.ResetPasswordTokenReseller_OwnerId(ownerID[:]))
	if err != nil {
		return "", time.Time{}, err
	}

	var secretBytes console.ResetPasswordSecret
	copy(secretBytes[:], token.Secret)
	return secretBytes.String(), token.CreatedAt, nil
}

func (rpt *resellerResetPasswordTokens) Delete(ctx context.Context, secret string) (err error) {
	defer mon.Task()(&ctx)(&err)

	secretBytes, err := console.ResetPasswordSecretFromBase64(secret)
	if err != nil {
		return err
	}

	_, err = rpt.db.Delete_ResetPasswordTokenReseller_By_Secret(ctx, dbx.ResetPasswordTokenReseller_Secret(secretBytes[:]))
	if errs.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}
