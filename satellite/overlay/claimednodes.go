// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package overlay

import (
	"context"
	"sync"
	"time"

	"github.com/StorXNetwork/common/storxnetwork"
)

// ClaimedNodeSet caches org-claimed node IDs so audit, payout, and farmer
// registration can skip them without a database read per node.
// A nil set or a nil source reports no claimed nodes.
type ClaimedNodeSet struct {
	src DedicatedNodes
	ttl time.Duration

	mu  sync.Mutex
	at  time.Time
	ids map[storxnetwork.NodeID]struct{}
}

// NewClaimedNodeSet returns a cache of claimed node IDs. ttl is how long a
// successful load is reused. A non-positive ttl uses 3 minutes.
func NewClaimedNodeSet(src DedicatedNodes, ttl time.Duration) *ClaimedNodeSet {
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	return &ClaimedNodeSet{src: src, ttl: ttl}
}

// Snapshot returns the claimed node IDs. The returned map must not be modified.
// After a successful load, a later source error returns the previous snapshot.
func (s *ClaimedNodeSet) Snapshot(ctx context.Context) (map[storxnetwork.NodeID]struct{}, error) {
	if s == nil || s.src == nil {
		return nil, nil
	}

	s.mu.Lock()
	if s.ids != nil && time.Since(s.at) < s.ttl {
		ids := s.ids
		s.mu.Unlock()
		return ids, nil
	}
	s.mu.Unlock()

	list, err := s.src.AllNodeIDs(ctx)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.ids != nil {
			return s.ids, nil
		}
		return nil, err
	}

	ids := make(map[storxnetwork.NodeID]struct{}, len(list))
	for _, id := range list {
		ids[id] = struct{}{}
	}

	s.mu.Lock()
	s.ids = ids
	s.at = time.Now()
	s.mu.Unlock()
	return ids, nil
}

// Contains reports whether id is an org-claimed node.
func (s *ClaimedNodeSet) Contains(ctx context.Context, id storxnetwork.NodeID) (bool, error) {
	ids, err := s.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	_, ok := ids[id]
	return ok, nil
}
