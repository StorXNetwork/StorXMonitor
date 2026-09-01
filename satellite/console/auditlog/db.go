// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package auditlog

import (
	"context"
	"time"
)

type DB interface {
	Insert(ctx context.Context, record Record) error
	List(ctx context.Context, params ListParams) (ListResult, error)
	Count(ctx context.Context, params ListParams) (int, error)
	DeleteBefore(ctx context.Context, before time.Time) (int64, error)
	ListActions(ctx context.Context, actorID string) ([]string, error)
}
