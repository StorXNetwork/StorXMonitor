// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"time"

	"go.uber.org/zap"
	"storj.io/common/version"
)

// Metrics tracks backup service metrics
type Metrics struct {
	// Backup operation metrics
	BackupStarted       int64
	BackupCompleted     int64
	BackupFailed        int64
	BackupDuration      time.Duration
	TotalKeysBackedUp   int64
	TotalPagesProcessed int64

	// Page processing metrics
	PageStarted   int64
	PageCompleted int64
	PageFailed    int64
	PageDuration  time.Duration
	KeysPerPage   int64

	// File management metrics
	FilesCreated   int64
	FilesDeleted   int64
	TotalFileSize  int64
	ChecksumErrors int64

	// Smart contract metrics
	ContractCalls   int64
	ContractErrors  int64
	ContractLatency time.Duration

	// Resource usage metrics
	MemoryUsage      int64
	DiskUsage        int64
	ConcurrencyLevel int64

	// Error tracking
	LastError  error
	ErrorCount int64
	ErrorTypes map[string]int64
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		ErrorTypes: make(map[string]int64),
	}
}

// RecordBackupStarted records the start of a backup operation
func (m *Metrics) RecordBackupStarted() {
	m.BackupStarted++
}

// RecordBackupCompleted records the successful completion of a backup operation
func (m *Metrics) RecordBackupCompleted(duration time.Duration, totalKeys, totalPages int64) {
	m.BackupCompleted++
	m.BackupDuration = duration
	m.TotalKeysBackedUp += totalKeys
	m.TotalPagesProcessed += totalPages
}

// RecordBackupFailed records a failed backup operation
func (m *Metrics) RecordBackupFailed(err error) {
	m.BackupFailed++
	m.ErrorCount++
	m.LastError = err

	errorType := "unknown"
	if err != nil {
		errorType = err.Error()
	}
	m.ErrorTypes[errorType]++
}

// RecordPageStarted records the start of a page processing operation
func (m *Metrics) RecordPageStarted() {
	m.PageStarted++
}

// RecordPageCompleted records the successful completion of a page processing operation
func (m *Metrics) RecordPageCompleted(duration time.Duration, keysCount int64) {
	m.PageCompleted++
	m.PageDuration = duration
	m.KeysPerPage = keysCount
}

// RecordPageFailed records a failed page processing operation
func (m *Metrics) RecordPageFailed(err error) {
	m.PageFailed++
	m.ErrorCount++
	m.LastError = err

	errorType := "unknown"
	if err != nil {
		errorType = err.Error()
	}
	m.ErrorTypes[errorType]++
}

// RecordFileCreated records the creation of a backup file
func (m *Metrics) RecordFileCreated(fileSize int64) {
	m.FilesCreated++
	m.TotalFileSize += fileSize
}

// RecordFileDeleted records the deletion of a backup file
func (m *Metrics) RecordFileDeleted() {
	m.FilesDeleted++
}

// RecordChecksumError records a checksum validation error
func (m *Metrics) RecordChecksumError() {
	m.ChecksumErrors++
}

// RecordContractCall records a smart contract call
func (m *Metrics) RecordContractCall(latency time.Duration) {
	m.ContractCalls++
	m.ContractLatency = latency
}

// RecordContractError records a smart contract error
func (m *Metrics) RecordContractError(err error) {
	m.ContractErrors++
	m.ErrorCount++
	m.LastError = err

	errorType := "contract_error"
	if err != nil {
		errorType = err.Error()
	}
	m.ErrorTypes[errorType]++
}

// RecordResourceUsage records current resource usage
func (m *Metrics) RecordResourceUsage(memoryUsage, diskUsage, concurrencyLevel int64) {
	m.MemoryUsage = memoryUsage
	m.DiskUsage = diskUsage
	m.ConcurrencyLevel = concurrencyLevel
}

// GetMetrics returns a copy of current metrics
func (m *Metrics) GetMetrics() Metrics {
	return *m
}

// Reset resets all metrics to zero
func (m *Metrics) Reset() {
	*m = Metrics{
		ErrorTypes: make(map[string]int64),
	}
}

// MetricsCollector collects and reports metrics
type MetricsCollector struct {
	metrics *Metrics
	log     *zap.Logger
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(log *zap.Logger) *MetricsCollector {
	return &MetricsCollector{
		metrics: NewMetrics(),
		log:     log,
	}
}

// Collect collects metrics from the backup service
func (mc *MetricsCollector) Collect(ctx context.Context) {
	// Log current metrics
	mc.log.Info("Backup service metrics",
		zap.Int64("backup_started", mc.metrics.BackupStarted),
		zap.Int64("backup_completed", mc.metrics.BackupCompleted),
		zap.Int64("backup_failed", mc.metrics.BackupFailed),
		zap.Duration("backup_duration", mc.metrics.BackupDuration),
		zap.Int64("total_keys_backed_up", mc.metrics.TotalKeysBackedUp),
		zap.Int64("total_pages_processed", mc.metrics.TotalPagesProcessed),
		zap.Int64("page_started", mc.metrics.PageStarted),
		zap.Int64("page_completed", mc.metrics.PageCompleted),
		zap.Int64("page_failed", mc.metrics.PageFailed),
		zap.Duration("page_duration", mc.metrics.PageDuration),
		zap.Int64("keys_per_page", mc.metrics.KeysPerPage),
		zap.Int64("files_created", mc.metrics.FilesCreated),
		zap.Int64("files_deleted", mc.metrics.FilesDeleted),
		zap.Int64("total_file_size", mc.metrics.TotalFileSize),
		zap.Int64("checksum_errors", mc.metrics.ChecksumErrors),
		zap.Int64("contract_calls", mc.metrics.ContractCalls),
		zap.Int64("contract_errors", mc.metrics.ContractErrors),
		zap.Duration("contract_latency", mc.metrics.ContractLatency),
		zap.Int64("memory_usage", mc.metrics.MemoryUsage),
		zap.Int64("disk_usage", mc.metrics.DiskUsage),
		zap.Int64("concurrency_level", mc.metrics.ConcurrencyLevel),
		zap.Int64("error_count", mc.metrics.ErrorCount),
		zap.Any("error_types", mc.metrics.ErrorTypes),
	)
}

// GetMetrics returns the current metrics
func (mc *MetricsCollector) GetMetrics() *Metrics {
	return mc.metrics
}

// Structured logging for backup operations
type BackupLogger struct {
	log     *zap.Logger
	metrics *Metrics
}

// NewBackupLogger creates a new backup logger
func NewBackupLogger(log *zap.Logger, metrics *Metrics) *BackupLogger {
	return &BackupLogger{
		log:     log,
		metrics: metrics,
	}
}

// LogBackupStarted logs the start of a backup operation
func (bl *BackupLogger) LogBackupStarted(backupDate string, totalKeys uint64) {
	bl.log.Info("Backup operation started",
		zap.String("backup_date", backupDate),
		zap.Uint64("total_keys", totalKeys),
		zap.String("version", version.Build.Version.String()),
	)
	bl.metrics.RecordBackupStarted()
}

// LogBackupCompleted logs the successful completion of a backup operation
func (bl *BackupLogger) LogBackupCompleted(backupDate string, duration time.Duration, totalKeys, totalPages int64, filePath string, fileSize int64) {
	bl.log.Info("Backup operation completed",
		zap.String("backup_date", backupDate),
		zap.Duration("duration", duration),
		zap.Int64("total_keys", totalKeys),
		zap.Int64("total_pages", totalPages),
		zap.String("file_path", filePath),
		zap.Int64("file_size", fileSize),
		zap.String("version", version.Build.Version.String()),
	)
	bl.metrics.RecordBackupCompleted(duration, totalKeys, totalPages)
}

// LogBackupFailed logs a failed backup operation
func (bl *BackupLogger) LogBackupFailed(backupDate string, err error) {
	bl.log.Error("Backup operation failed",
		zap.String("backup_date", backupDate),
		zap.Error(err),
		zap.String("version", version.Build.Version.String()),
	)
	bl.metrics.RecordBackupFailed(err)
}

// LogPageStarted logs the start of a page processing operation
func (bl *BackupLogger) LogPageStarted(backupDate string, pageNumber int, startIndex, count uint64) {
	bl.log.Debug("Page processing started",
		zap.String("backup_date", backupDate),
		zap.Int("page_number", pageNumber),
		zap.Uint64("start_index", startIndex),
		zap.Uint64("count", count),
	)
	bl.metrics.RecordPageStarted()
}

// LogPageCompleted logs the successful completion of a page processing operation
func (bl *BackupLogger) LogPageCompleted(backupDate string, pageNumber int, duration time.Duration, keysCount int64, filePath string, fileSize int64) {
	bl.log.Debug("Page processing completed",
		zap.String("backup_date", backupDate),
		zap.Int("page_number", pageNumber),
		zap.Duration("duration", duration),
		zap.Int64("keys_count", keysCount),
		zap.String("file_path", filePath),
		zap.Int64("file_size", fileSize),
	)
	bl.metrics.RecordPageCompleted(duration, keysCount)
}

// LogPageFailed logs a failed page processing operation
func (bl *BackupLogger) LogPageFailed(backupDate string, pageNumber int, err error) {
	bl.log.Error("Page processing failed",
		zap.String("backup_date", backupDate),
		zap.Int("page_number", pageNumber),
		zap.Error(err),
	)
	bl.metrics.RecordPageFailed(err)
}

// LogContractCall logs a smart contract call
func (bl *BackupLogger) LogContractCall(method string, duration time.Duration, success bool) {
	level := zap.InfoLevel
	if !success {
		level = zap.ErrorLevel
	}

	bl.log.Check(level, "Smart contract call").Write(
		zap.String("method", method),
		zap.Duration("duration", duration),
		zap.Bool("success", success),
	)

	if success {
		bl.metrics.RecordContractCall(duration)
	} else {
		bl.metrics.RecordContractError(nil)
	}
}

// LogFileOperation logs file operations
func (bl *BackupLogger) LogFileOperation(operation string, filePath string, fileSize int64, err error) {
	if err != nil {
		bl.log.Error("File operation failed",
			zap.String("operation", operation),
			zap.String("file_path", filePath),
			zap.Int64("file_size", fileSize),
			zap.Error(err),
		)
	} else {
		bl.log.Debug("File operation completed",
			zap.String("operation", operation),
			zap.String("file_path", filePath),
			zap.Int64("file_size", fileSize),
		)

		if operation == "create" {
			bl.metrics.RecordFileCreated(fileSize)
		} else if operation == "delete" {
			bl.metrics.RecordFileDeleted()
		}
	}
}

// LogChecksumError logs a checksum validation error
func (bl *BackupLogger) LogChecksumError(filePath string, expectedChecksum, actualChecksum string) {
	bl.log.Error("Checksum validation failed",
		zap.String("file_path", filePath),
		zap.String("expected_checksum", expectedChecksum),
		zap.String("actual_checksum", actualChecksum),
	)
	bl.metrics.RecordChecksumError()
}

// LogResourceUsage logs current resource usage
func (bl *BackupLogger) LogResourceUsage(memoryUsage, diskUsage, concurrencyLevel int64) {
	bl.log.Debug("Resource usage",
		zap.Int64("memory_usage_bytes", memoryUsage),
		zap.Int64("disk_usage_bytes", diskUsage),
		zap.Int64("concurrency_level", concurrencyLevel),
	)
	bl.metrics.RecordResourceUsage(memoryUsage, diskUsage, concurrencyLevel)
}

// LogServiceStart logs the start of the backup service
func (bl *BackupLogger) LogServiceStart(config *Config) {
	bl.log.Info("Backup service started",
		zap.String("backup_dir", config.BackupDir),
		zap.Int("max_concurrent_pages", config.MaxConcurrentPages),
		zap.Int("page_size", config.PageSize),
		zap.Duration("chore_interval", config.ChoreInterval),
		zap.Int("worker_concurrency", config.WorkerConcurrency),
		zap.String("version", version.Build.Version.String()),
	)
}

// LogServiceStop logs the stop of the backup service
func (bl *BackupLogger) LogServiceStop() {
	bl.log.Info("Backup service stopped",
		zap.String("version", version.Build.Version.String()),
	)
}

// LogServiceError logs a service-level error
func (bl *BackupLogger) LogServiceError(err error) {
	bl.log.Error("Backup service error",
		zap.Error(err),
		zap.String("version", version.Build.Version.String()),
	)
	bl.metrics.RecordBackupFailed(err)
}
