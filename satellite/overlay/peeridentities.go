// Copyright (C) 2018 Storj Labs, Inc.
// See LICENSE for copying information.

package overlay

import (
	"context"

	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/storxnetwork"
)

// PeerIdentities stores storagenode peer identities.
//
// architecture: Database
type PeerIdentities interface {
	// Set adds a peer identity entry for a node
	Set(context.Context, storxnetwork.NodeID, *identity.PeerIdentity) error
	// Get gets peer identity
	Get(context.Context, storxnetwork.NodeID) (*identity.PeerIdentity, error)
	// BatchGet gets all nodes peer identities in a transaction
	BatchGet(context.Context, storxnetwork.NodeIDList) ([]*identity.PeerIdentity, error)
}
