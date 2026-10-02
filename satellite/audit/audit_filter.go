// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package audit

import (
	"context"
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
)

// AuditedNodes is an interface for filtering nodes for audit.
type AuditedNodes interface {
	// Reload supposed to initialize state. Called before audit ranged-loop cycle.
	Reload(ctx context.Context) error

	// Match should decide if node is part of the selection or not.
	Match(alias metabase.NodeAlias) bool
}

// AllowNodes will use only nodes that match the filter.
type AllowNodes struct {
	filter     nodeselection.NodeFilter
	db         overlay.DB
	metabaseDB *metabase.DB
	whiteList  []bool
}

// NewFilteredNodes creates a new AllowNodes.
func NewFilteredNodes(filter nodeselection.NodeFilter, db overlay.DB, metabaseDB *metabase.DB) *AllowNodes {
	return &AllowNodes{
		filter:     filter,
		db:         db,
		metabaseDB: metabaseDB,
	}
}

// Reload implements AuditedNodes interface.
func (f *AllowNodes) Reload(ctx context.Context) error {
	nodes, err := f.db.GetAllParticipatingNodes(ctx, -12*time.Hour, 0)
	if err != nil {
		return err
	}

	aliasMap, err := f.metabaseDB.LatestNodesAliasMap(ctx)
	if err != nil {
		return err
	}

	maxAlias := aliasMap.Max()
	if maxAlias == -1 {
		return nil
	}

	f.whiteList = make([]bool, maxAlias+1)

	for _, node := range nodes {
		if f.filter.Match(&node) {
			alias, found := aliasMap.Alias(node.ID)
			if found {
				f.whiteList[alias] = true
			}
		}
	}
	return nil
}

// Match implements AuditedNodes interface.
func (f *AllowNodes) Match(alias metabase.NodeAlias) bool {
	return f.whiteList[alias]
}

// AllNodes is a AuditedNodes that includes all nodes.
type AllNodes struct{}

// Reload implements AuditedNodes interface.
func (a AllNodes) Reload(ctx context.Context) error {
	return nil
}

// Match implements AuditedNodes interface.
func (a AllNodes) Match(alias metabase.NodeAlias) bool {
	return true
}

var _ AuditedNodes = (*AllNodes)(nil)

// SkipClaimedNodes drops org-claimed nodes from the audit queue.
// inner may be nil, in which case every non-claimed node is audited.
type SkipClaimedNodes struct {
	inner   AuditedNodes
	claimed *overlay.ClaimedNodeSet
	meta    *metabase.DB

	blocked []bool
}

// NewSkipClaimedNodes wraps inner so claimed node aliases are not audited.
func NewSkipClaimedNodes(inner AuditedNodes, claimed *overlay.ClaimedNodeSet, meta *metabase.DB) *SkipClaimedNodes {
	return &SkipClaimedNodes{
		inner:   inner,
		claimed: claimed,
		meta:    meta,
	}
}

// Reload loads the inner filter and the claimed-node alias set.
func (s *SkipClaimedNodes) Reload(ctx context.Context) error {
	if s.inner != nil {
		if err := s.inner.Reload(ctx); err != nil {
			return err
		}
	}
	s.blocked = nil
	if s.claimed == nil || s.meta == nil {
		return nil
	}

	ids, err := s.claimed.Snapshot(ctx)
	if err != nil || len(ids) == 0 {
		// A lookup failure must not cancel the audit cycle for public nodes.
		return nil
	}
	aliasMap, err := s.meta.LatestNodesAliasMap(ctx)
	if err != nil {
		return nil
	}
	maxAlias := aliasMap.Max()
	if maxAlias < 0 {
		return nil
	}
	s.blocked = make([]bool, maxAlias+1)
	for id := range ids {
		alias, found := aliasMap.Alias(id)
		if found && int(alias) >= 0 && int(alias) < len(s.blocked) {
			s.blocked[alias] = true
		}
	}
	return nil
}

// Match reports whether alias should be audited.
func (s *SkipClaimedNodes) Match(alias metabase.NodeAlias) bool {
	if s.inner != nil && !s.inner.Match(alias) {
		return false
	}
	idx := int(alias)
	if idx >= 0 && idx < len(s.blocked) && s.blocked[idx] {
		return false
	}
	return true
}

var _ AuditedNodes = (*SkipClaimedNodes)(nil)
