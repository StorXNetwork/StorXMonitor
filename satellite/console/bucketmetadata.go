// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/common/storxnetwork"
)

// Placement contains placement info.
type Placement struct {
	DefaultPlacement storxnetwork.PlacementConstraint `json:"defaultPlacement"`
	Location         string                           `json:"location"`
}

// BucketMetadata contains bucket name, versioning and placement info.
type BucketMetadata struct {
	Name       string             `json:"name"`
	Versioning buckets.Versioning `json:"versioning"`
	Placement  Placement          `json:"placement"`
}
