// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package queue

import (
	"context"
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

// InjuredSegment contains information about segment which
// should be repaired.
type InjuredSegment struct {
	StreamID uuid.UUID
	Position metabase.SegmentPosition

	SegmentHealth float64
	AttemptedAt   *time.Time
	UpdatedAt     time.Time
	InsertedAt    time.Time

	Placement storxnetwork.PlacementConstraint
}

// Stat contains information about a segment of repair queue.
type Stat struct {
	Count            int
	Placement        storxnetwork.PlacementConstraint
	MaxInsertedAt    time.Time
	MinInsertedAt    time.Time
	MaxAttemptedAt   *time.Time
	MinAttemptedAt   *time.Time
	MinSegmentHealth float64
	MaxSegmentHealth float64
}

// RepairQueue implements queueing for segments that need repairing.
// Implementation can be found at satellite/satellitedb/repairqueue.go.
//
// architecture: Database
type RepairQueue interface {
	// Insert adds an injured segment.
	Insert(ctx context.Context, s *InjuredSegment) (alreadyInserted bool, err error)
	// InsertBatch adds multiple injured segments
	InsertBatch(ctx context.Context, segments []*InjuredSegment) (newlyInsertedSegments []*InjuredSegment, err error)
	// Select gets an injured segment.
	Select(ctx context.Context, includedPlacements []storxnetwork.PlacementConstraint, excludedPlacements []storxnetwork.PlacementConstraint) (*InjuredSegment, error)
	// Delete removes an injured segment.
	Delete(ctx context.Context, s *InjuredSegment) error
	// Clean removes all segments last updated before a certain time
	Clean(ctx context.Context, before time.Time) (deleted int64, err error)
	// SelectN lists limit amount of injured segments.
	SelectN(ctx context.Context, limit int) ([]InjuredSegment, error)
	// Count counts the number of segments in the repair queue.
	Count(ctx context.Context) (count int, err error)

	// Stat returns stat of the current queue state.
	Stat(ctx context.Context) ([]Stat, error)

	// TestingSetAttemptedTime sets attempted time for a segment.
	TestingSetAttemptedTime(ctx context.Context, streamID uuid.UUID, position metabase.SegmentPosition, t time.Time) (rowsAffected int64, err error)
}
