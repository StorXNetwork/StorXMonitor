// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"github.com/StorXNetwork/common/uuid"
)

// uuidsToBytesArray converts []uuid.UUID into [][]byte.
func uuidsToBytesArray(uuidArr []uuid.UUID) (bytesArr [][]byte) {
	for _, v := range uuidArr {
		bytesArr = append(bytesArr, v.Bytes())
	}
	return
}
