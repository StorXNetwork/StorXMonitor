// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

var (
	// ErrUserNodeNotFound is used when a claimed user node mapping is missing.
	ErrUserNodeNotFound = errs.Class("user node not found")

	// ErrUserNodeAlreadyClaimed is used when a node is already claimed by a user.
	ErrUserNodeAlreadyClaimed = errs.Class("user node already claimed")

	// ErrUserNodeInvalid is used when a node id is invalid or the node does not exist.
	ErrUserNodeInvalid = errs.Class("user node invalid")

	// ErrOwnNodesNoNodes is used when own-nodes placement is active but the owner has no claimed nodes.
	ErrOwnNodesNoNodes = errs.Class("no claimed own nodes")
)

// UserNodes is the repository for user ↔ storage node claim mappings.
//
// architecture: Database
type UserNodes interface {
	// GetByUserID returns all nodes claimed by the user.
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]UserNode, error)
	// GetNodeIDsByUserID returns only the node IDs claimed by the user.
	GetNodeIDsByUserID(ctx context.Context, userID uuid.UUID) ([]storxnetwork.NodeID, error)
	// GetByNodeID returns the claim for a node, if any.
	GetByNodeID(ctx context.Context, nodeID storxnetwork.NodeID) (*UserNode, error)
	// Insert creates a claim. Returns ErrUserNodeAlreadyClaimed on unique conflict.
	Insert(ctx context.Context, userID uuid.UUID, nodeID storxnetwork.NodeID) (*UserNode, error)
	// Delete removes a claim for the given user and node.
	Delete(ctx context.Context, userID uuid.UUID, nodeID storxnetwork.NodeID) error
	// AllNodeIDs returns every claimed node ID (for isolating dedicated nodes from public selection).
	AllNodeIDs(ctx context.Context) ([]storxnetwork.NodeID, error)
	// NodeExists reports whether the node is present in the overlay nodes table.
	// operatorEmail is the node's registered operator email when the node exists.
	NodeExists(ctx context.Context, nodeID storxnetwork.NodeID) (exists bool, operatorEmail string, err error)
}

// UserNode is a user ↔ storage node claim.
type UserNode struct {
	UserID    uuid.UUID            `json:"userId"`
	NodeID    storxnetwork.NodeID  `json:"nodeId"`
	CreatedAt time.Time            `json:"createdAt"`
}

// OwnNodesOnlyStatus is the response for GET own-nodes-only.
type OwnNodesOnlyStatus struct {
	Enabled   bool       `json:"enabled"`
	ProjectID uuid.UUID  `json:"projectId"`
	Placement int        `json:"placement"`
}

// ParseNodeID parses a base58 or hex-encoded storage node ID.
func ParseNodeID(s string) (storxnetwork.NodeID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return storxnetwork.NodeID{}, ErrUserNodeInvalid.New("empty node id")
	}
	id, err := storxnetwork.NodeIDFromString(s)
	if err == nil {
		return id, nil
	}
	raw, hexErr := hex.DecodeString(s)
	if hexErr != nil {
		return storxnetwork.NodeID{}, ErrUserNodeInvalid.New("node id is neither base58 nor hex: %s", s)
	}
	id, err = storxnetwork.NodeIDFromBytes(raw)
	if err != nil {
		return storxnetwork.NodeID{}, ErrUserNodeInvalid.Wrap(err)
	}
	return id, nil
}
