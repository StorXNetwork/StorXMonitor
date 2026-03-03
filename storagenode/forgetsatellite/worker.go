// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package forgetsatellite

import (
	"context"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/storxnetwork"
)

// Worker is responsible for completing the cleanup for a given satellite.
type Worker struct {
	log *zap.Logger

	cleaner *Cleaner

	satellite storxnetwork.NodeID
}

// NewWorker instantiates Worker.
func NewWorker(log *zap.Logger, cleaner *Cleaner, satellite storxnetwork.NodeID) *Worker {
	return &Worker{
		log:       log,
		cleaner:   cleaner,
		satellite: satellite,
	}
}

// Run starts the cleanup process for a satellite.
func (w *Worker) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return w.cleaner.Run(ctx, w.satellite)
}
