// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package verify

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"storj.io/storj/satellite/metabase/rangedloop"
)

// ProgressObserver counts and prints progress of metabase loop.
type ProgressObserver struct {
	Log *zap.Logger

	mu                     sync.Mutex
	ProgressPrintFrequency int64
	RemoteSegmentCount     int64
	InlineSegmentCount     int64
}

// Start is called at the beginning of each segment loop.
func (progress *ProgressObserver) Start(context.Context, time.Time) error {
	return nil
}

// Fork creates a Partial to process a chunk of all the segments. It is
// called after Start. It is not called concurrently.
func (progress *ProgressObserver) Fork(context.Context) (rangedloop.Partial, error) {
	return progress, nil
}

// Join is called for each partial returned by Fork.
func (progress *ProgressObserver) Join(context.Context, rangedloop.Partial) error {
	return nil
}

// Finish is called after all segments are processed by all observers.
func (progress *ProgressObserver) Finish(context.Context) error {
	return nil
}

// Process is called repeatedly with batches of segments.
func (progress *ProgressObserver) Process(ctx context.Context, segments []rangedloop.Segment) error {
	progress.mu.Lock()
	defer progress.mu.Unlock()

	for _, segment := range segments {
		if segment.Inline() {
			progress.InlineSegmentCount++
		} else {
			progress.RemoteSegmentCount++
		}
		if (progress.RemoteSegmentCount+progress.InlineSegmentCount)%progress.ProgressPrintFrequency == 0 {
			progress.Report()
		}
	}
	return nil
}

// Report reports the current progress.
func (progress *ProgressObserver) Report() {
	// Progress reporting removed to minimize New Relic storage
}
