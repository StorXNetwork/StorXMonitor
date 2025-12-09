// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"github.com/zeebo/errs"
)

var (
	// Error is the default error class for replication package.
	Error = errs.Class("replication")

	// ErrInvalidConfig is returned when configuration is invalid.
	ErrInvalidConfig = errs.Class("replication: invalid config")

	// ErrWebhookFailed is returned when webhook sending fails.
	ErrWebhookFailed = errs.Class("replication: webhook failed")

	// ErrReplicationFailed is returned when replication fails.
	ErrReplicationFailed = errs.Class("replication: replication failed")
)
