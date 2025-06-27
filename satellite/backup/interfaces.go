// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"time"
)

// DB interface for backup operations
type DB interface {
	CreateBackupFinalStatus(ctx context.Context, backupDate string, status string) error
	UpdateBackupFinalStatus(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error
	GetBackupFinalStatus(ctx context.Context, backupDate string) (*BackupFinalStatus, error)
	GetLatestBackupStatus(ctx context.Context) (*BackupFinalStatus, error)
	ListBackupStatuses(ctx context.Context, limit int) ([]*BackupFinalStatus, error)

	CreateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string) error
	UpdateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error
	GetBackupPageStatus(ctx context.Context, backupDate string, pageNumber int) (*BackupPageStatus, error)
	GetBackupPageStatuses(ctx context.Context, backupDate string) ([]*BackupPageStatus, error)

	DeleteOldBackupStatuses(ctx context.Context, olderThan time.Time) error
	DeleteBackupPageStatuses(ctx context.Context, backupDate string) error
}
