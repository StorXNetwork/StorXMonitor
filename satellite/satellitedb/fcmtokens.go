// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console/pushnotifications"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that fcmTokens implements pushnotifications.DB.
var _ pushnotifications.DB = (*fcmTokens)(nil)

// ErrFCMTokens represents errors from the fcm_tokens database.
var ErrFCMTokens = errs.Class("fcmtokens")

type fcmTokens struct {
	db *satelliteDB
}

// InsertToken inserts a new FCM token for a user.
func (f *fcmTokens) InsertToken(ctx context.Context, token pushnotifications.FCMToken) (_ pushnotifications.FCMToken, err error) {
	defer mon.Task()(&ctx)(&err)

	var optional dbx.FcmTokens_Create_Fields
	if token.DeviceID != nil {
		optional.DeviceId = dbx.FcmTokens_DeviceId(*token.DeviceID)
	}
	if token.DeviceType != nil {
		optional.DeviceType = dbx.FcmTokens_DeviceType(*token.DeviceType)
	}
	if token.AppVersion != nil {
		optional.AppVersion = dbx.FcmTokens_AppVersion(*token.AppVersion)
	}
	if token.OSVersion != nil {
		optional.OsVersion = dbx.FcmTokens_OsVersion(*token.OSVersion)
	}
	if token.DeviceModel != nil {
		optional.DeviceModel = dbx.FcmTokens_DeviceModel(*token.DeviceModel)
	}
	if token.BrowserName != nil {
		optional.BrowserName = dbx.FcmTokens_BrowserName(*token.BrowserName)
	}
	if token.UserAgent != nil {
		optional.UserAgent = dbx.FcmTokens_UserAgent(*token.UserAgent)
	}
	if token.IPAddress != nil {
		optional.IpAddress = dbx.FcmTokens_IpAddress(*token.IPAddress)
	}

	now := time.Now()
	dbxToken, err := f.db.Create_FcmTokens(ctx,
		dbx.FcmTokens_Id(token.ID[:]),
		dbx.FcmTokens_UserId(token.UserID[:]),
		dbx.FcmTokens_Token(token.Token),
		dbx.FcmTokens_UpdatedAt(now),
		optional)
	if err != nil {
		return token, ErrFCMTokens.Wrap(err)
	}

	return fcmTokenFromDBX(dbxToken)
}

// GetTokensByUserID retrieves all active tokens for a user.
func (f *fcmTokens) GetTokensByUserID(ctx context.Context, userID uuid.UUID) (_ []pushnotifications.FCMToken, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxTokens, err := f.db.All_FcmTokens_By_UserId_And_IsActive_Equal_True(ctx, dbx.FcmTokens_UserId(userID[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return []pushnotifications.FCMToken{}, nil
		}
		return nil, ErrFCMTokens.Wrap(err)
	}

	tokens := make([]pushnotifications.FCMToken, 0, len(dbxTokens))
	for _, dbxToken := range dbxTokens {
		token, err := fcmTokenFromDBX(dbxToken)
		if err != nil {
			return nil, ErrFCMTokens.Wrap(err)
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// GetTokenByID retrieves a token by ID.
func (f *fcmTokens) GetTokenByID(ctx context.Context, tokenID uuid.UUID) (_ pushnotifications.FCMToken, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxToken, err := f.db.Get_FcmTokens_By_Id(ctx, dbx.FcmTokens_Id(tokenID[:]))
	if err != nil {
		return pushnotifications.FCMToken{}, ErrFCMTokens.Wrap(err)
	}

	return fcmTokenFromDBX(dbxToken)
}

// GetTokenByToken retrieves a token by token string.
func (f *fcmTokens) GetTokenByToken(ctx context.Context, token string) (_ pushnotifications.FCMToken, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxToken, err := f.db.Get_FcmTokens_By_Token(ctx, dbx.FcmTokens_Token(token))
	if err != nil {
		return pushnotifications.FCMToken{}, ErrFCMTokens.Wrap(err)
	}

	return fcmTokenFromDBX(dbxToken)
}

// UpdateToken updates an existing token.
func (f *fcmTokens) UpdateToken(ctx context.Context, tokenID uuid.UUID, update pushnotifications.UpdateTokenRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	var updateFields dbx.FcmTokens_Update_Fields
	if update.DeviceID != nil {
		updateFields.DeviceId = dbx.FcmTokens_DeviceId(*update.DeviceID)
	}
	if update.DeviceType != nil {
		updateFields.DeviceType = dbx.FcmTokens_DeviceType(*update.DeviceType)
	}
	if update.AppVersion != nil {
		updateFields.AppVersion = dbx.FcmTokens_AppVersion(*update.AppVersion)
	}
	if update.OSVersion != nil {
		updateFields.OsVersion = dbx.FcmTokens_OsVersion(*update.OSVersion)
	}
	if update.DeviceModel != nil {
		updateFields.DeviceModel = dbx.FcmTokens_DeviceModel(*update.DeviceModel)
	}
	if update.BrowserName != nil {
		updateFields.BrowserName = dbx.FcmTokens_BrowserName(*update.BrowserName)
	}
	if update.UserAgent != nil {
		updateFields.UserAgent = dbx.FcmTokens_UserAgent(*update.UserAgent)
	}
	if update.IsActive != nil {
		updateFields.IsActive = dbx.FcmTokens_IsActive(*update.IsActive)
	}
	updateFields.UpdatedAt = dbx.FcmTokens_UpdatedAt(time.Now())

	_, err = f.db.Update_FcmTokens_By_Id(ctx, dbx.FcmTokens_Id(tokenID[:]), updateFields)
	return ErrFCMTokens.Wrap(err)
}

// DeleteToken deletes a token (soft delete by setting is_active = false).
func (f *fcmTokens) DeleteToken(ctx context.Context, tokenID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = f.db.Update_FcmTokens_By_Id(ctx, dbx.FcmTokens_Id(tokenID[:]), dbx.FcmTokens_Update_Fields{
		IsActive:  dbx.FcmTokens_IsActive(false),
		UpdatedAt: dbx.FcmTokens_UpdatedAt(time.Now()),
	})
	return ErrFCMTokens.Wrap(err)
}

// DeleteTokensByUserID deletes all tokens for a user.
func (f *fcmTokens) DeleteTokensByUserID(ctx context.Context, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = f.db.Delete_FcmTokens_By_UserId(ctx, dbx.FcmTokens_UserId(userID[:]))
	return ErrFCMTokens.Wrap(err)
}

// fcmTokenFromDBX converts a dbx.FcmTokens to pushnotifications.FCMToken.
func fcmTokenFromDBX(dbxToken *dbx.FcmTokens) (pushnotifications.FCMToken, error) {
	id, err := uuid.FromBytes(dbxToken.Id)
	if err != nil {
		return pushnotifications.FCMToken{}, ErrFCMTokens.Wrap(err)
	}

	userID, err := uuid.FromBytes(dbxToken.UserId)
	if err != nil {
		return pushnotifications.FCMToken{}, ErrFCMTokens.Wrap(err)
	}

	token := pushnotifications.FCMToken{
		ID:         id,
		UserID:     userID,
		Token:      dbxToken.Token,
		CreatedAt:  dbxToken.CreatedAt,
		UpdatedAt:  dbxToken.UpdatedAt,
		IsActive:   dbxToken.IsActive,
	}

	if dbxToken.DeviceId != nil {
		deviceID := *dbxToken.DeviceId
		token.DeviceID = &deviceID
	}
	if dbxToken.DeviceType != nil {
		deviceType := *dbxToken.DeviceType
		token.DeviceType = &deviceType
	}
	if dbxToken.AppVersion != nil {
		appVersion := *dbxToken.AppVersion
		token.AppVersion = &appVersion
	}
	if dbxToken.OsVersion != nil {
		osVersion := *dbxToken.OsVersion
		token.OSVersion = &osVersion
	}
	if dbxToken.DeviceModel != nil {
		deviceModel := *dbxToken.DeviceModel
		token.DeviceModel = &deviceModel
	}
	if dbxToken.BrowserName != nil {
		browserName := *dbxToken.BrowserName
		token.BrowserName = &browserName
	}
	if dbxToken.UserAgent != nil {
		userAgent := *dbxToken.UserAgent
		token.UserAgent = &userAgent
	}
	if dbxToken.IpAddress != nil {
		ipAddress := *dbxToken.IpAddress
		token.IPAddress = &ipAddress
	}
	if dbxToken.LastUsedAt != nil {
		token.LastUsedAt = dbxToken.LastUsedAt
	}

	return token, nil
}

