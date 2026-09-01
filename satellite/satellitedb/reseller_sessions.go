// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ seller.WebappSessionResellers = (*webappSessionResellers)(nil)

type webappSessionResellers struct {
	db *satelliteDB
}

func (db *webappSessionResellers) Create(ctx context.Context, id, resellerID uuid.UUID, ip string, expiresAt time.Time) (session seller.WebappSessionReseller, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxSession, err := db.db.Create_WebappSessionReseller(ctx,
		dbx.WebappSessionReseller_Id(id.Bytes()),
		dbx.WebappSessionReseller_ResellerId(resellerID.Bytes()),
		dbx.WebappSessionReseller_IpAddress(ip),
		dbx.WebappSessionReseller_ExpiresAt(expiresAt),
	)
	if err != nil {
		return session, err
	}

	return webappSessionResellerFromDBX(dbxSession)
}

func (db *webappSessionResellers) GetBySessionID(ctx context.Context, sessionID uuid.UUID) (session seller.WebappSessionReseller, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxSession, err := db.db.Get_WebappSessionReseller_By_Id(ctx, dbx.WebappSessionReseller_Id(sessionID.Bytes()))
	if err != nil {
		return session, err
	}

	return webappSessionResellerFromDBX(dbxSession)
}

func (db *webappSessionResellers) DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = db.db.Delete_WebappSessionReseller_By_Id(ctx, dbx.WebappSessionReseller_Id(sessionID.Bytes()))
	return err
}

func (db *webappSessionResellers) DeleteAllByResellerID(ctx context.Context, resellerID uuid.UUID) (deleted int64, err error) {
	defer mon.Task()(&ctx)(&err)

	return db.db.Delete_WebappSessionReseller_By_ResellerId(ctx, dbx.WebappSessionReseller_ResellerId(resellerID.Bytes()))
}

func (db *webappSessionResellers) DeleteAllByResellerIDExcept(ctx context.Context, resellerID uuid.UUID, sessionID uuid.UUID) (deleted int64, err error) {
	defer mon.Task()(&ctx)(&err)

	return db.db.Delete_WebappSessionReseller_By_ResellerId_And_Id_Not(
		ctx,
		dbx.WebappSessionReseller_ResellerId(resellerID.Bytes()),
		dbx.WebappSessionReseller_Id(sessionID.Bytes()),
	)
}

func (db *webappSessionResellers) GetPagedActiveByResellerID(
	ctx context.Context,
	resellerID uuid.UUID,
	expiresAt time.Time,
	cursor seller.ResellerWebappSessionsCursor,
) (page *seller.ResellerWebappSessionsPage, err error) {
	defer mon.Task()(&ctx)(&err)

	if cursor.Limit <= 0 {
		return nil, seller.ErrValidation.New("page cannot be 0 or negative")
	}
	if cursor.Page <= 0 {
		return nil, seller.ErrValidation.New("page cannot be 0 or negative")
	}

	page = &seller.ResellerWebappSessionsPage{
		Limit:          cursor.Limit,
		Offset:         uint64((cursor.Page - 1) * cursor.Limit),
		Order:          cursor.Order,
		OrderDirection: cursor.OrderDirection,
	}

	err = db.db.QueryRowContext(ctx, db.db.Rebind(`
		SELECT COUNT(*) FROM webapp_session_resellers
		WHERE reseller_id = ? AND expires_at > ?
	`), resellerID, expiresAt).Scan(&page.TotalCount)
	if err != nil {
		return nil, err
	}

	if page.TotalCount == 0 {
		return page, nil
	}
	if page.Offset > page.TotalCount-1 {
		return nil, seller.ErrValidation.New("page is out of range")
	}

	query := db.db.Rebind(`
		SELECT id, ip_address, expires_at
		FROM webapp_session_resellers
		WHERE reseller_id = ? AND expires_at > ?
		` + resellerWebappSessionsSortClause(cursor.Order, cursor.OrderDirection) + `
		LIMIT ? OFFSET ?
	`)

	rows, err := db.db.QueryContext(ctx, query, resellerID[:], expiresAt, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	var sessions []seller.WebappSessionReseller
	for rows.Next() {
		s := seller.WebappSessionReseller{ResellerID: resellerID}
		if scanErr := rows.Scan(&s.ID, &s.IP, &s.ExpiresAt); scanErr != nil {
			return nil, scanErr
		}
		sessions = append(sessions, s)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	page.Sessions = sessions
	page.PageCount = uint(page.TotalCount / uint64(cursor.Limit))
	if page.TotalCount%uint64(cursor.Limit) != 0 {
		page.PageCount++
	}
	page.CurrentPage = cursor.Page

	return page, nil
}

func resellerWebappSessionsSortClause(order int8, direction uint8) string {
	dirStr := "ASC"
	if direction == 2 {
		dirStr = "DESC"
	}

	if order == 2 {
		return "ORDER BY expires_at " + dirStr + ", ip_address, reseller_id"
	}
	return "ORDER BY LOWER(ip_address) " + dirStr + ", expires_at, reseller_id"
}

func (db *webappSessionResellers) UpdateExpiration(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = db.db.Update_WebappSessionReseller_By_Id(ctx,
		dbx.WebappSessionReseller_Id(sessionID.Bytes()),
		dbx.WebappSessionReseller_Update_Fields{
			ExpiresAt: dbx.WebappSessionReseller_ExpiresAt(expiresAt),
		},
	)
	return err
}

func webappSessionResellerFromDBX(dbxSession *dbx.WebappSessionReseller) (seller.WebappSessionReseller, error) {
	id, err := uuid.FromBytes(dbxSession.Id)
	if err != nil {
		return seller.WebappSessionReseller{}, err
	}
	resellerID, err := uuid.FromBytes(dbxSession.ResellerId)
	if err != nil {
		return seller.WebappSessionReseller{}, err
	}
	return seller.WebappSessionReseller{
		ID:         id,
		ResellerID: resellerID,
		IP:         dbxSession.IpAddress,
		Status:     dbxSession.Status,
		ExpiresAt:  dbxSession.ExpiresAt,
	}, nil
}
