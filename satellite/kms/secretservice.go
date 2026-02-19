// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package kms

import (
	"context"

	"github.com/StorXNetwork/common/storxnetwork"
)

// SecretsService is a service for retrieving keys.
//
// architecture: Service
type SecretsService interface {
	// GetKeys gets key from the source.
	GetKeys(ctx context.Context) (map[int]*storxnetwork.Key, error)
	// Close closes the service.
	Close() error
}
