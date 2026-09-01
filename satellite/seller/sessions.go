// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

// GetPagedActiveSessionsReseller returns paged active webapp sessions for the authenticated reseller.
func (s *Service) GetPagedActiveSessionsReseller(ctx context.Context, cursor ResellerWebappSessionsCursor) (*ResellerWebappSessionsPage, error) {
	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	page, err := s.store.WebappSessionResellers().GetPagedActiveByResellerID(ctx, reseller.ID, time.Now(), cursor)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return page, nil
}

// InvalidateSessionReseller invalidates the session by ID.
func (s *Service) InvalidateSessionReseller(ctx context.Context, sessionID uuid.UUID) error {
	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	session, err := s.store.WebappSessionResellers().GetBySessionID(ctx, sessionID)
	if err != nil {
		return Error.Wrap(err)
	}

	if session.ResellerID != reseller.ID {
		return console.ErrUnauthorized.New("session does not belong to the reseller")
	}

	return Error.Wrap(s.store.WebappSessionResellers().DeleteBySessionID(ctx, session.ID))
}
