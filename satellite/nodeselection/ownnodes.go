// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package nodeselection

import "github.com/StorXNetwork/common/storxnetwork"

// OwnNodesPlacement is the placement constraint used when a project is
// configured to upload only to storage nodes claimed by the project owner.
//
// Operators should define placement 250 in the satellite placement config so
// that base node filters (online, version, etc.) still apply. Selection then
// intersects those filters with the per-user AllowedIDs allowlist. If
// placement 250 is not configured, allowlist selection falls back to the
// default placement (0) filters.
const OwnNodesPlacement = storxnetwork.PlacementConstraint(250)
