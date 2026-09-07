// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"

	"github.com/StorXNetwork/common/uuid"
)

// invalidateBrandingCache is a no-op placeholder.
// Branding is read directly from the database on each console request because seller and
// console-api run as separate processes and cannot share in-memory cache.
func (s *Service) invalidateBrandingCache(ctx context.Context, resellerID uuid.UUID, previousHosts ...string) {
}
