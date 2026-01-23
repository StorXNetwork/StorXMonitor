// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"time"

	"storj.io/common/debug"
	"storj.io/common/memory"
	version_checker "github.com/StorXNetwork/StorXMonitor/private/version/checker"
)

// Config contains configurable values for backup service.
type Config struct {
	BackupDir          string        `help:"directory to store backup files" default:"./backups"`
	MaxConcurrentPages int           `help:"maximum number of pages to process concurrently" default:"5"`
	PageSize           int           `help:"number of keys per page" default:"100"`
	RetryAttempts      int           `help:"number of retry attempts for failed operations" default:"3"`
	RetryDelay         time.Duration `help:"delay between retry attempts" default:"5s"`

	// Rate limiting for smart contract calls
	SmartContractRateLimit int `help:"maximum smart contract requests per minute" default:"20"`

	// Following audit pattern for scheduling
	ChoreInterval     time.Duration `help:"how often to run the backup chore" releaseDefault:"24h" devDefault:"1m" testDefault:"$TESTINTERVAL"`
	WorkerConcurrency int           `help:"number of workers to process backup pages" default:"2"`

	// Timeout settings
	SmartContractTimeout time.Duration `help:"timeout for smart contract calls" default:"30s"`
	FileOperationTimeout time.Duration `help:"timeout for file operations" default:"60s"`

	// File size limits
	MaxBackupFileSize memory.Size `help:"maximum size of backup files" default:"1GB"`

	// Retention settings
	RetentionDays int `help:"number of days to keep backup files" default:"30"`

	// Debug configuration
	Debug debug.Config

	// Version configuration
	Version version_checker.Config
}
