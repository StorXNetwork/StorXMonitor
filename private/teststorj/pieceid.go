// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package teststorj

import (
	"github.com/StorXNetwork/common/storxnetwork"
)

// PieceIDFromBytes converts a byte slice into a piece ID.
func PieceIDFromBytes(b []byte) storxnetwork.PieceID {
	id, _ := storxnetwork.PieceIDFromBytes(fit(b))
	return id
}

// PieceIDFromString decodes a hex encoded piece ID string.
func PieceIDFromString(s string) storxnetwork.PieceID {
	return PieceIDFromBytes([]byte(s))
}
