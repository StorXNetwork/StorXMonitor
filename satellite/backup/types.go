// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"time"
)

// BackupFinalStatus represents the final status of a backup operation
type BackupFinalStatus struct {
	BackupDate     string    `json:"backup_date"`
	Status         string    `json:"status"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
	TotalPages     int       `json:"total_pages,omitempty"`
	TotalKeys      int       `json:"total_keys,omitempty"`
	BackupFilePath string    `json:"backup_file_path,omitempty"`
	ErrorMessage   string    `json:"error_message,omitempty"`
	Checksum       string    `json:"checksum,omitempty"`
	FileSize       int64     `json:"file_size,omitempty"`
}

// BackupPageStatus represents the status of a single page backup
type BackupPageStatus struct {
	BackupDate   string    `json:"backup_date"`
	PageNumber   int       `json:"page_number"`
	Status       string    `json:"status"`
	CompletedAt  time.Time `json:"completed_at,omitempty"`
	KeysCount    int       `json:"keys_count,omitempty"`
	FilePath     string    `json:"file_path,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
	Checksum     string    `json:"checksum,omitempty"`
	FileSize     int64     `json:"file_size,omitempty"`
}

// KeyValuePair represents a key-value pair from the smart contract
type KeyValuePair struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	VersionID string `json:"version_id"`
}

// BackupStatus constants
const (
	BackupStatusInProgress = "in_progress"
	BackupStatusCompleted  = "completed"
	BackupStatusFailed     = "failed"
)
