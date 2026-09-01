// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ seller.ResellerDeleteRequests = (*resellerDeleteRequests)(nil)

type resellerDeleteRequests struct {
	db *satelliteDB
}

func (repo *resellerDeleteRequests) CreateDeleteRequest(ctx context.Context, resellerID uuid.UUID, deleteAt time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	id, err := uuid.New()
	if err != nil {
		return Error.Wrap(err)
	}

	_, err = repo.db.Create_ResellerDeleteRequest(ctx,
		dbx.ResellerDeleteRequest_Id(id[:]),
		dbx.ResellerDeleteRequest_ResellerId(resellerID[:]),
		dbx.ResellerDeleteRequest_Status("INIT"),
		dbx.ResellerDeleteRequest_DeleteAt(deleteAt),
		dbx.ResellerDeleteRequest_Create_Fields{
			Error: dbx.ResellerDeleteRequest_Error_Null(),
		},
	)
	return Error.Wrap(err)
}
