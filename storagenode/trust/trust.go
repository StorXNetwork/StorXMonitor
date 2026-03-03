// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package trust

import (
	"context"

	"github.com/StorXNetwork/common/pb"
	"github.com/StorXNetwork/common/signing"
	"github.com/StorXNetwork/common/storxnetwork"
)

// TrustedSatelliteSource collects all functions required by other standard services, to handle list of trusted Satellites.
type TrustedSatelliteSource interface {

	// GetSatellites returns the list of trusted satellites.
	GetSatellites(ctx context.Context) (satellites []storxnetwork.NodeID)

	// GetNodeURL returns the URL of the satellite with the given ID.
	GetNodeURL(ctx context.Context, id storxnetwork.NodeID) (_ storxnetwork.NodeURL, err error)

	// VerifySatelliteID checks whether id corresponds to a trusted satellite.
	VerifySatelliteID(ctx context.Context, id storxnetwork.NodeID) error

	// GetSignee returns the signee for the given node ID.
	GetSignee(ctx context.Context, id pb.NodeID) (signing.Signee, error)
}
