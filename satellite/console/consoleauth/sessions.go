// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleauth

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
)

// WebappSessions is the repository for webapp sessions.
type WebappSessions interface {
	// Create creates a webapp session and returns the session info.
	Create(ctx context.Context, id, userID uuid.UUID, ip, userAgent string, expires time.Time) (WebappSession, error)
	// GetBySessionID gets the session info from the session ID.
	GetBySessionID(ctx context.Context, sessionID uuid.UUID) (WebappSession, error)
	// GetAllByUserID gets all webapp sessions with userID.
	GetAllByUserID(ctx context.Context, userID uuid.UUID) ([]WebappSession, error)
	// GetPagedActiveByUserID gets all active webapp sessions by userID, offset and limit.
	GetPagedActiveByUserID(ctx context.Context, userID uuid.UUID, expiresAt time.Time, cursor WebappSessionsCursor) (*WebappSessionsPage, error)
	// DeleteBySessionID deletes a webapp session by ID.
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
	// DeleteAllByUserID deletes all webapp sessions by user ID.
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	// DeleteAllByUserIDExcept deletes all webapp sessions by user ID except one of sessionID.
	DeleteAllByUserIDExcept(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) (int64, error)
	// UpdateExpiration updates the expiration time of the session.
	UpdateExpiration(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) error
	// DeleteExpired deletes all sessions that have expired before the provided timestamp.
	DeleteExpired(ctx context.Context, now time.Time, asOfSystemTimeInterval time.Duration, pageSize int) error
}

// WebappSession represents a session on the satellite web app.
type WebappSession struct {
	ID                        uuid.UUID
	UserID                    uuid.UUID
	Address                   string
	UserAgent                 string
	Status                    int
	ExpiresAt                 time.Time
	CreatedAt                 time.Time
	IsRequesterCurrentSession bool
}

// WebappSessionDevelopers is the repository for developer sessions.
type WebappSessionDevelopers interface {
	// Create creates a developer session and returns the session info.
	Create(ctx context.Context, id, developerID uuid.UUID, ip string, expires time.Time) (WebappSessionDeveloper, error)
	// GetBySessionID gets the session info from the session ID.
	GetBySessionID(ctx context.Context, sessionID uuid.UUID) (WebappSessionDeveloper, error)
	// GetAllByDeveloperId gets all developer sessions with developerID.
	GetAllByDeveloperId(ctx context.Context, developerID uuid.UUID) ([]WebappSessionDeveloper, error)
	// DeleteBySessionID deletes a developer session by ID.
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
	// DeleteAllByDeveloperId deletes all developer sessions by developer ID.
	DeleteAllByDeveloperId(ctx context.Context, developerID uuid.UUID) (int64, error)
	// UpdateExpiration updates the expiration time of the session.
	UpdateExpiration(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) error
	// DeleteExpired deletes all sessions that have expired before the provided timestamp.
	DeleteExpired(ctx context.Context, now time.Time, asOfSystemTimeInterval time.Duration, pageSize int) error
}

// WebappSessionDeveloper represents a session on the satellite web app for developers.
type WebappSessionDeveloper struct {
	ID          uuid.UUID
	DeveloperID uuid.UUID
	IP          string
	Status      int
	ExpiresAt   time.Time
}

// WebappSessionsOrder is used for querying webapp sessions in specified order.
type WebappSessionsOrder int8

const (
	// UserAgent indicates that we should order by user agent.
	UserAgent WebappSessionsOrder = 1
	// ExpiresAt indicates that we should order by expiration date.
	ExpiresAt WebappSessionsOrder = 2
)

// OrderDirection is used for members in specific order direction.
type OrderDirection uint8

const (
	// Ascending indicates that we should order ascending.
	Ascending OrderDirection = 1
	// Descending indicates that we should order descending.
	Descending OrderDirection = 2
)

// WebappSessionsCursor holds info for webapp sessions cursor pagination.
type WebappSessionsCursor struct {
	Limit          uint
	Page           uint
	Order          WebappSessionsOrder
	OrderDirection OrderDirection
}

// WebappSessionsPage represents a page of webapp sessions.
type WebappSessionsPage struct {
	Sessions []WebappSession `json:"sessions"`

	Limit          uint                `json:"limit"`
	Order          WebappSessionsOrder `json:"order"`
	OrderDirection OrderDirection      `json:"orderDirection"`
	Offset         uint64              `json:"offset"`
	PageCount      uint                `json:"pageCount"`
	CurrentPage    uint                `json:"currentPage"`
	TotalCount     uint64              `json:"totalCount"`
}
