// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/dbutil/pgutil"
	"storj.io/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

// ensures that *webappSessionDevelopers implements consoleauth.WebappSessionDevelopers.
var _ consoleauth.WebappSessionDevelopers = (*webappSessionDevelopers)(nil)

type webappSessionDevelopers struct {
	db *satelliteDB
}

// Create creates a developer session and returns the session info.
func (db *webappSessionDevelopers) Create(ctx context.Context, id, developerID uuid.UUID, ip string, expiresAt time.Time) (session consoleauth.WebappSessionDeveloper, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxSession, err := db.db.Create_WebappSessionDeveloper(ctx, dbx.WebappSessionDeveloper_Id(id.Bytes()), dbx.WebappSessionDeveloper_DeveloperId(developerID.Bytes()),
		dbx.WebappSessionDeveloper_IpAddress(ip), dbx.WebappSessionDeveloper_ExpiresAt(expiresAt))
	if err != nil {
		return session, err
	}

	return getDeveloperSessionFromDBX(dbxSession)
}

// GetBySessionID gets the session info from the session ID.
func (db *webappSessionDevelopers) GetBySessionID(ctx context.Context, sessionID uuid.UUID) (session consoleauth.WebappSessionDeveloper, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxSession, err := db.db.Get_WebappSessionDeveloper_By_Id(ctx, dbx.WebappSessionDeveloper_Id(sessionID.Bytes()))
	if err != nil {
		return session, err
	}

	return getDeveloperSessionFromDBX(dbxSession)
}

// GetAllByDeveloperId gets all developer sessions with developerID.
func (db *webappSessionDevelopers) GetAllByDeveloperId(ctx context.Context, developerID uuid.UUID) (sessions []consoleauth.WebappSessionDeveloper, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxSessions, err := db.db.All_WebappSessionDeveloper_By_DeveloperId(ctx, dbx.WebappSessionDeveloper_DeveloperId(developerID.Bytes()))
	if err != nil {
		return sessions, err
	}

	for _, dbxs := range dbxSessions {
		s, err := getDeveloperSessionFromDBX(dbxs)
		if err != nil {
			return sessions, err
		}
		sessions = append(sessions, s)
	}

	return sessions, nil
}

// DeleteBySessionID deletes a developer session by ID.
func (db *webappSessionDevelopers) DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = db.db.Delete_WebappSessionDeveloper_By_Id(ctx, dbx.WebappSessionDeveloper_Id(sessionID.Bytes()))

	return err
}

// DeleteAllByDeveloperId deletes all developer sessions by developer ID.
func (db *webappSessionDevelopers) DeleteAllByDeveloperId(ctx context.Context, developerID uuid.UUID) (deleted int64, err error) {
	defer mon.Task()(&ctx)(&err)

	return db.db.Delete_WebappSessionDeveloper_By_DeveloperId(ctx, dbx.WebappSessionDeveloper_DeveloperId(developerID.Bytes()))
}

// UpdateExpiration updates the expiration time of the session.
func (db *webappSessionDevelopers) UpdateExpiration(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = db.db.Update_WebappSessionDeveloper_By_Id(
		ctx,
		dbx.WebappSessionDeveloper_Id(sessionID.Bytes()),
		dbx.WebappSessionDeveloper_Update_Fields{
			ExpiresAt: dbx.WebappSessionDeveloper_ExpiresAt(expiresAt),
		},
	)

	return err
}

// DeleteExpired deletes all sessions that have expired before the provided timestamp.
func (db *webappSessionDevelopers) DeleteExpired(ctx context.Context, now time.Time, asOfSystemTimeInterval time.Duration, pageSize int) (err error) {
	defer mon.Task()(&ctx)(&err)

	if pageSize <= 0 {
		return Error.New("expected page size to be positive; got %d", pageSize)
	}

	var pageCursor uuid.UUID
	selected := make([]uuid.UUID, pageSize)
	aost := db.db.impl.AsOfSystemInterval(asOfSystemTimeInterval)
	for {
		// Select the ID beginning this page of records
		err := db.db.QueryRowContext(ctx, `
			SELECT id FROM webapp_session_developers
			`+aost+`
			WHERE id > $1 AND expires_at < $2
			ORDER BY id LIMIT 1
		`, pageCursor, now).Scan(&pageCursor)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return Error.Wrap(err)
		}

		// Select page of records
		rows, err := db.db.QueryContext(ctx, `
			SELECT id FROM webapp_session_developers
			`+aost+`
			WHERE id >= $1 ORDER BY id LIMIT $2
		`, pageCursor, pageSize)
		if err != nil {
			return Error.Wrap(err)
		}

		var i int
		for i = 0; rows.Next(); i++ {
			if err = rows.Scan(&selected[i]); err != nil {
				return Error.Wrap(err)
			}
		}
		if err = errs.Combine(rows.Err(), rows.Close()); err != nil {
			return Error.Wrap(err)
		}

		// Delete all expired records in the page
		_, err = db.db.ExecContext(ctx, `
			DELETE FROM webapp_session_developers
			WHERE id = ANY($1)
			AND expires_at < $2
		`, pgutil.UUIDArray(selected[:i]), now)
		if err != nil {
			return Error.Wrap(err)
		}

		if i < pageSize {
			return nil
		}

		// Advance the cursor to the next page
		pageCursor = selected[i-1]
	}
}

func getDeveloperSessionFromDBX(dbxSession *dbx.WebappSessionDeveloper) (consoleauth.WebappSessionDeveloper, error) {
	id, err := uuid.FromBytes(dbxSession.Id)
	if err != nil {
		return consoleauth.WebappSessionDeveloper{}, err
	}
	developerID, err := uuid.FromBytes(dbxSession.DeveloperId)
	if err != nil {
		return consoleauth.WebappSessionDeveloper{}, err
	}
	return consoleauth.WebappSessionDeveloper{
		ID:          id,
		DeveloperID: developerID,
		IP:          dbxSession.IpAddress,
		Status:      dbxSession.Status,
		ExpiresAt:   dbxSession.ExpiresAt,
	}, nil
}
