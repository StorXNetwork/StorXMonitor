// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package audit

import (
	"github.com/StorXNetwork/common/storxnetwork"
)

// ExcludeClaimedReputations drops rows whose node ID is in claimed.
// Public nodes that share a wallet with a claimed node are kept.
// A nil or empty claimed set returns rows unchanged.
func ExcludeClaimedReputations(rows []NodeReputationEntry, claimed map[storxnetwork.NodeID]struct{}) []NodeReputationEntry {
	if len(claimed) == 0 || len(rows) == 0 {
		return rows
	}
	filtered := make([]NodeReputationEntry, 0, len(rows))
	for _, row := range rows {
		if _, ok := claimed[row.NodeID]; ok {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func claimedNode(claimed map[storxnetwork.NodeID]struct{}, id storxnetwork.NodeID) bool {
	if len(claimed) == 0 {
		return false
	}
	_, ok := claimed[id]
	return ok
}

func excludeClaimedIDs(ids storxnetwork.NodeIDList, claimed map[storxnetwork.NodeID]struct{}) storxnetwork.NodeIDList {
	if len(claimed) == 0 || len(ids) == 0 {
		return ids
	}
	filtered := make(storxnetwork.NodeIDList, 0, len(ids))
	for _, id := range ids {
		if _, ok := claimed[id]; ok {
			continue
		}
		filtered = append(filtered, id)
	}
	return filtered
}
