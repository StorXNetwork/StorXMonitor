// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package mudplanet

import (
	"context"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/StorXMonitor/storagenode/trust"
	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/identity/testidentity"
	"github.com/StorXNetwork/common/pb"
	"github.com/StorXNetwork/common/signing"
	"github.com/StorXNetwork/common/storxnetwork"
)

// StaticTrust is a trust source that trusts a single satellite with a pregenerated identity.
type StaticTrust struct {
	identity *identity.FullIdentity
}

// NewStaticTrust creates a new StaticTrust instance with a pregenerated identity.
// The idno parameter is used to select a specific pregenerated identity.
func NewStaticTrust(idno int) *StaticTrust {
	return &StaticTrust{
		identity: testidentity.MustPregeneratedIdentity(idno, storxnetwork.LatestIDVersion()),
	}
}

// GetSatellites implements the TrustedSatelliteSource interface.
// It returns a slice containing this instance's identity ID as the only trusted satellite.
func (a StaticTrust) GetSatellites(ctx context.Context) (satellites []storxnetwork.NodeID) {
	return []storxnetwork.NodeID{a.identity.ID}
}

// GetNodeURL implements the TrustedSatelliteSource interface.
// It returns a NodeURL with the provided ID and a fixed localhost address.
func (a StaticTrust) GetNodeURL(ctx context.Context, id storxnetwork.NodeID) (_ storxnetwork.NodeURL, err error) {
	return storxnetwork.NodeURL{
		ID:      id,
		Address: "localhost:0",
	}, nil
}

// VerifySatelliteID implements the TrustedSatelliteSource interface.
// It verifies that the given NodeID matches this instance's identity ID.
func (a StaticTrust) VerifySatelliteID(ctx context.Context, id storxnetwork.NodeID) error {
	if id != a.identity.ID {
		return errs.New("Untrusted satellite")
	}
	return nil
}

// GetSignee implements the TrustedSatelliteSource interface.
// It returns a signing.Signee created from this instance's peer identity.
func (a StaticTrust) GetSignee(ctx context.Context, id pb.NodeID) (signing.Signee, error) {
	return signing.SigneeFromPeerIdentity(a.identity.PeerIdentity()), nil
}

var _ trust.TrustedSatelliteSource = &StaticTrust{}

// TrustAll modifies the modules to use StaticTrust.
// It provides a StaticTrust instance and replaces the TrustedSatelliteSource dependency.
func TrustAll(ball *mud.Ball) {
	mud.Provide[*StaticTrust](ball, func() *StaticTrust {
		return NewStaticTrust(149)
	})
	mud.ReplaceDependency[trust.TrustedSatelliteSource, *StaticTrust](ball)
}
