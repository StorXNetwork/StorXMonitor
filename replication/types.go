// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"time"
)

// TableChangeEvent represents a database change event sent to Backuptools.
type TableChangeEvent struct {
	Operation string `json:"operation"`

	Table string `json:"table"`

	Timestamp time.Time `json:"timestamp"`

	Data map[string]interface{} `json:"data,omitempty"`

	OldData map[string]interface{} `json:"old_data,omitempty"`
}
