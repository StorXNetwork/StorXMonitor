// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/sync2"
	"storj.io/storj/satellite/smartcontract"
)

var mon = monkit.Package()

// Error is the default backup errs class.
var Error = errs.Class("backup")

// Worker contains information for processing backup operations.
type Worker struct {
	log         *zap.Logger
	db          DB
	contract    smartcontract.SocialShareHelper
	config      *Config
	Loop        *sync2.Cycle
	concurrency int
}

// NewWorker instantiates Worker.
func NewWorker(log *zap.Logger, db DB, contract smartcontract.SocialShareHelper, config Config) *Worker {
	return &Worker{
		log:         log,
		db:          db,
		contract:    contract,
		config:      &config,
		Loop:        sync2.NewCycle(config.ChoreInterval),
		concurrency: config.WorkerConcurrency,
	}
}

// Run runs backup service.
func (worker *Worker) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return worker.Loop.Run(ctx, func(ctx context.Context) (err error) {
		defer mon.Task()(&ctx)(&err)
		err = worker.process(ctx)
		if err != nil {
			worker.log.Error("process", zap.Error(Error.Wrap(err)))
		}
		return nil
	})
}

// Close halts the worker.
func (worker *Worker) Close() error {
	worker.Loop.Close()
	return nil
}

// process checks if backup is needed and executes it.
func (worker *Worker) process(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Check if backup already completed today
	today := time.Now().Format("2006-01-02")

	existingStatus, err := worker.db.GetBackupFinalStatus(ctx, today)
	if err == nil && existingStatus.Status == BackupStatusCompleted {
		worker.log.Info("Backup already completed today", zap.String("date", today))
		return nil
	}

	// Start backup process
	return worker.executeBackup(ctx, today)
}

// executeBackup performs the actual backup operation.
func (worker *Worker) executeBackup(ctx context.Context, backupDate string) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Create initial backup status
	err = worker.db.CreateBackupFinalStatus(ctx, backupDate, BackupStatusInProgress)
	if err != nil {
		worker.log.Error("Failed to create backup status", zap.Error(err))
		return err
	}

	// Get total keys from smart contract
	totalKeys, err := worker.contract.GetTotalKeys(ctx)
	if err != nil {
		worker.log.Error("Failed to get total keys", zap.Error(err))
		worker.updateBackupStatusFailed(ctx, backupDate, "Failed to get total keys: "+err.Error())
		return err
	}

	// Calculate total pages
	totalPages := int((totalKeys + uint64(worker.config.PageSize) - 1) / uint64(worker.config.PageSize))

	worker.log.Info("Starting backup",
		zap.String("date", backupDate),
		zap.Uint64("total_keys", totalKeys),
		zap.Int("total_pages", totalPages))

	// Process pages concurrently
	limiter := sync2.NewLimiter(worker.config.MaxConcurrentPages)
	defer limiter.Wait()

	var totalProcessedKeys int
	var totalProcessedPages int
	var lastError error

	for pageNumber := 0; pageNumber < totalPages; pageNumber++ {
		started := limiter.Go(ctx, func() {
			err := worker.processPage(ctx, backupDate, pageNumber)
			if err != nil {
				worker.log.Error("Error processing page",
					zap.Int("page_number", pageNumber),
					zap.Error(err))
				lastError = err
			} else {
				totalProcessedPages++
				// Get page status to count keys
				pageStatus, err := worker.db.GetBackupPageStatus(ctx, backupDate, pageNumber)
				if err == nil {
					totalProcessedKeys += pageStatus.KeysCount
				}
			}
		})
		if !started {
			return ctx.Err()
		}
	}

	// Wait for all pages to complete
	limiter.Wait()

	if lastError != nil {
		worker.updateBackupStatusFailed(ctx, backupDate, "Some pages failed to process: "+lastError.Error())
		return lastError
	}

	// Create final backup archive
	backupFilePath, err := worker.createFinalBackup(ctx, backupDate)
	if err != nil {
		worker.log.Error("Failed to create final backup", zap.Error(err))
		worker.updateBackupStatusFailed(ctx, backupDate, "Failed to create final backup: "+err.Error())
		return err
	}

	// Update backup status to completed
	err = worker.db.UpdateBackupFinalStatus(ctx, backupDate, BackupStatusCompleted, time.Now(), totalPages, totalProcessedKeys, backupFilePath, "", "", 0)
	if err != nil {
		worker.log.Error("Failed to update backup status", zap.Error(err))
		return err
	}

	worker.log.Info("Backup completed successfully",
		zap.String("date", backupDate),
		zap.Int("total_pages", totalPages),
		zap.Int("total_keys", totalProcessedKeys),
		zap.String("backup_file", backupFilePath))

	return nil
}

// processPage processes a single page of backup data.
func (worker *Worker) processPage(ctx context.Context, backupDate string, pageNumber int) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Create page status
	err = worker.db.CreateBackupPageStatus(ctx, backupDate, pageNumber, BackupStatusInProgress)
	if err != nil {
		return err
	}

	// Calculate start index
	startIndex := uint64(pageNumber * worker.config.PageSize)
	count := uint64(worker.config.PageSize)

	// Get page data from smart contract
	keys, values, versionIds, err := worker.contract.GetPaginatedKeyValues(ctx, startIndex, count)
	if err != nil {
		worker.log.Error("Failed to get page data",
			zap.Int("page_number", pageNumber),
			zap.Error(err))
		worker.updatePageStatusFailed(ctx, backupDate, pageNumber, "Failed to get page data: "+err.Error())
		return err
	}

	// Convert to KeyValuePair slice
	keyValuePairs := make([]KeyValuePair, len(keys))
	for i := range keys {
		keyValuePairs[i] = KeyValuePair{
			Key:       keys[i],
			Value:     values[i],
			VersionID: versionIds[i],
		}
	}

	// Save page data to file
	filePath, err := worker.savePageData(backupDate, pageNumber, keyValuePairs)
	if err != nil {
		worker.log.Error("Failed to save page data",
			zap.Int("page_number", pageNumber),
			zap.Error(err))
		worker.updatePageStatusFailed(ctx, backupDate, pageNumber, "Failed to save page data: "+err.Error())
		return err
	}

	// Update page status to completed
	err = worker.db.UpdateBackupPageStatus(ctx, backupDate, pageNumber, BackupStatusCompleted, time.Now(), len(keyValuePairs), filePath, "", "", 0)
	if err != nil {
		worker.log.Error("Failed to update page status",
			zap.Int("page_number", pageNumber),
			zap.Error(err))
		return err
	}

	worker.log.Info("Page processed successfully",
		zap.Int("page_number", pageNumber),
		zap.Int("keys_count", len(keyValuePairs)))

	return nil
}

// updateBackupStatusFailed updates the backup status to failed.
func (worker *Worker) updateBackupStatusFailed(ctx context.Context, backupDate, errorMessage string) {
	err := worker.db.UpdateBackupFinalStatus(ctx, backupDate, BackupStatusFailed, time.Now(), 0, 0, "", errorMessage, "", 0)
	if err != nil {
		worker.log.Error("Failed to update backup status to failed", zap.Error(err))
	}
}

// updatePageStatusFailed updates the page status to failed.
func (worker *Worker) updatePageStatusFailed(ctx context.Context, backupDate string, pageNumber int, errorMessage string) {
	err := worker.db.UpdateBackupPageStatus(ctx, backupDate, pageNumber, BackupStatusFailed, time.Now(), 0, "", errorMessage, "", 0)
	if err != nil {
		worker.log.Error("Failed to update page status to failed", zap.Error(err))
	}
}

// savePageData saves page data to a JSON file.
func (worker *Worker) savePageData(backupDate string, pageNumber int, data []KeyValuePair) (string, error) {
	backupDir := filepath.Join(worker.config.BackupDir, backupDate)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", Error.Wrap(err)
	}
	fileName := fmt.Sprintf("page_%d.json", pageNumber)
	filePath := filepath.Join(backupDir, fileName)
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", Error.Wrap(err)
	}
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return "", Error.Wrap(err)
	}
	worker.log.Debug("Page data saved", zap.String("file_path", filePath), zap.Int("keys_count", len(data)))
	return filePath, nil
}

// createFinalBackup creates the final backup archive.
func (worker *Worker) createFinalBackup(ctx context.Context, backupDate string) (string, error) {
	backupDir := filepath.Join(worker.config.BackupDir, backupDate)
	backupFileName := fmt.Sprintf("backup_%s.json", backupDate)
	backupFilePath := filepath.Join(backupDir, backupFileName)
	pageStatuses, err := worker.db.GetBackupPageStatuses(ctx, backupDate)
	if err != nil {
		return "", Error.Wrap(err)
	}
	var allKeyValuePairs []KeyValuePair
	for _, pageStatus := range pageStatuses {
		if pageStatus.Status == BackupStatusCompleted && pageStatus.FilePath != "" {
			pageData, err := os.ReadFile(pageStatus.FilePath)
			if err != nil {
				worker.log.Warn("Failed to read page file", zap.String("file_path", pageStatus.FilePath), zap.Error(err))
				continue
			}
			var pageKeyValuePairs []KeyValuePair
			if err := json.Unmarshal(pageData, &pageKeyValuePairs); err != nil {
				worker.log.Warn("Failed to unmarshal page data", zap.String("file_path", pageStatus.FilePath), zap.Error(err))
				continue
			}
			allKeyValuePairs = append(allKeyValuePairs, pageKeyValuePairs...)
		}
	}
	backupData := struct {
		BackupDate    string         `json:"backup_date"`
		CreatedAt     time.Time      `json:"created_at"`
		TotalKeys     int            `json:"total_keys"`
		TotalPages    int            `json:"total_pages"`
		KeyValuePairs []KeyValuePair `json:"key_value_pairs"`
	}{
		BackupDate:    backupDate,
		CreatedAt:     time.Now(),
		TotalKeys:     len(allKeyValuePairs),
		TotalPages:    len(pageStatuses),
		KeyValuePairs: allKeyValuePairs,
	}
	jsonData, err := json.MarshalIndent(backupData, "", "  ")
	if err != nil {
		return "", Error.Wrap(err)
	}
	if err := os.WriteFile(backupFilePath, jsonData, 0644); err != nil {
		return "", Error.Wrap(err)
	}
	fileInfo, err := os.Stat(backupFilePath)
	if err != nil {
		return "", Error.Wrap(err)
	}
	checksum, err := worker.calculateFileChecksum(backupFilePath)
	if err != nil {
		return "", Error.Wrap(err)
	}
	err = worker.db.UpdateBackupFinalStatus(ctx, backupDate, BackupStatusCompleted, time.Now(), len(pageStatuses), len(allKeyValuePairs), backupFilePath, "", checksum, fileInfo.Size())
	if err != nil {
		worker.log.Error("Failed to update backup status with file info", zap.Error(err))
	}
	worker.cleanupPageFiles(backupDate)
	worker.log.Info("Final backup created", zap.String("file_path", backupFilePath), zap.Int64("file_size", fileInfo.Size()), zap.String("checksum", checksum))
	return backupFilePath, nil
}

func (worker *Worker) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", Error.Wrap(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", Error.Wrap(err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (worker *Worker) cleanupPageFiles(backupDate string) {
	backupDir := filepath.Join(worker.config.BackupDir, backupDate)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		worker.log.Warn("Failed to read backup directory for cleanup", zap.Error(err))
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" && entry.Name() != fmt.Sprintf("backup_%s.json", backupDate) {
			pageFilePath := filepath.Join(backupDir, entry.Name())
			if err := os.Remove(pageFilePath); err != nil {
				worker.log.Warn("Failed to remove page file", zap.String("file_path", pageFilePath), zap.Error(err))
			} else {
				worker.log.Debug("Removed page file", zap.String("file_path", pageFilePath))
			}
		}
	}
}
