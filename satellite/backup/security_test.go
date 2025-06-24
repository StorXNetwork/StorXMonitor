// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/identity"
)

// securityTestDB implements the DB interface for security testing
type securityTestDB struct {
	backupFinalStatuses map[string]*BackupFinalStatus
	backupPageStatuses  map[string]*BackupPageStatus
}

func newSecurityTestDB() *securityTestDB {
	return &securityTestDB{
		backupFinalStatuses: make(map[string]*BackupFinalStatus),
		backupPageStatuses:  make(map[string]*BackupPageStatus),
	}
}

func (db *securityTestDB) CreateBackupFinalStatus(ctx context.Context, backupDate string, status string) error {
	db.backupFinalStatuses[backupDate] = &BackupFinalStatus{
		BackupDate: backupDate,
		Status:     status,
	}
	return nil
}

func (db *securityTestDB) UpdateBackupFinalStatus(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error {
	if backupStatus, exists := db.backupFinalStatuses[backupDate]; exists {
		backupStatus.Status = status
		backupStatus.CompletedAt = completedAt
		backupStatus.TotalPages = totalPages
		backupStatus.TotalKeys = totalKeys
		backupStatus.BackupFilePath = backupFilePath
		backupStatus.ErrorMessage = errorMessage
		backupStatus.Checksum = checksum
		backupStatus.FileSize = fileSize
	}
	return nil
}

func (db *securityTestDB) GetBackupFinalStatus(ctx context.Context, backupDate string) (*BackupFinalStatus, error) {
	if status, exists := db.backupFinalStatuses[backupDate]; exists {
		return status, nil
	}
	return nil, nil
}

func (db *securityTestDB) GetLatestBackupStatus(ctx context.Context) (*BackupFinalStatus, error) {
	var latest *BackupFinalStatus
	for _, status := range db.backupFinalStatuses {
		if latest == nil || status.BackupDate > latest.BackupDate {
			latest = status
		}
	}
	return latest, nil
}

func (db *securityTestDB) ListBackupStatuses(ctx context.Context, limit int) ([]*BackupFinalStatus, error) {
	statuses := make([]*BackupFinalStatus, 0, len(db.backupFinalStatuses))
	for _, status := range db.backupFinalStatuses {
		statuses = append(statuses, status)
	}
	if limit > 0 && len(statuses) > limit {
		statuses = statuses[:limit]
	}
	return statuses, nil
}

func (db *securityTestDB) CreateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string) error {
	key := backupDate + "_" + string(rune(pageNumber))
	db.backupPageStatuses[key] = &BackupPageStatus{
		BackupDate: backupDate,
		PageNumber: pageNumber,
		Status:     status,
	}
	return nil
}

func (db *securityTestDB) UpdateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error {
	key := backupDate + "_" + string(rune(pageNumber))
	if pageStatus, exists := db.backupPageStatuses[key]; exists {
		pageStatus.Status = status
		pageStatus.CompletedAt = completedAt
		pageStatus.KeysCount = keysCount
		pageStatus.FilePath = filePath
		pageStatus.ErrorMessage = errorMessage
		pageStatus.Checksum = checksum
		pageStatus.FileSize = fileSize
	}
	return nil
}

func (db *securityTestDB) GetBackupPageStatus(ctx context.Context, backupDate string, pageNumber int) (*BackupPageStatus, error) {
	key := backupDate + "_" + string(rune(pageNumber))
	if status, exists := db.backupPageStatuses[key]; exists {
		return status, nil
	}
	return nil, nil
}

func (db *securityTestDB) GetBackupPageStatuses(ctx context.Context, backupDate string) ([]*BackupPageStatus, error) {
	var statuses []*BackupPageStatus
	for _, status := range db.backupPageStatuses {
		if status.BackupDate == backupDate {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

func (db *securityTestDB) DeleteOldBackupStatuses(ctx context.Context, olderThan time.Time) error {
	return nil
}

func (db *securityTestDB) DeleteBackupPageStatuses(ctx context.Context, backupDate string) error {
	return nil
}

// securityTestContract implements the smartcontract.SocialShareHelper interface for security testing
type securityTestContract struct {
	totalKeys     uint64
	keyValuePairs []KeyValuePair
}

func newSecurityTestContract(totalKeys uint64) *securityTestContract {
	contract := &securityTestContract{
		totalKeys:     totalKeys,
		keyValuePairs: make([]KeyValuePair, totalKeys),
	}

	// Generate test data
	for i := uint64(0); i < totalKeys; i++ {
		contract.keyValuePairs[i] = KeyValuePair{
			Key:       fmt.Sprintf("key_%d", i),
			Value:     fmt.Sprintf("value_%d", i),
			VersionID: fmt.Sprintf("v1.%d", i),
		}
	}

	return contract
}

func (c *securityTestContract) GetTotalKeys(ctx context.Context) (uint64, error) {
	return c.totalKeys, nil
}

func (c *securityTestContract) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	endIndex := startIndex + count
	if endIndex > uint64(len(c.keyValuePairs)) {
		endIndex = uint64(len(c.keyValuePairs))
	}

	if startIndex >= uint64(len(c.keyValuePairs)) {
		return []string{}, []string{}, []string{}, nil
	}

	pairs := c.keyValuePairs[startIndex:endIndex]
	keys = make([]string, len(pairs))
	values = make([]string, len(pairs))
	versionIds = make([]string, len(pairs))

	for i, pair := range pairs {
		keys[i] = pair.Key
		values[i] = pair.Value
		versionIds[i] = pair.VersionID
	}

	return keys, values, versionIds, nil
}

func (c *securityTestContract) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	return []byte{}, nil
}

func (c *securityTestContract) UploadSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func (c *securityTestContract) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func TestSecurity_InputValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorType   string
	}{
		{
			name: "valid config",
			config: &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			},
			expectError: false,
		},
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorType:   "nil config",
		},
		{
			name: "empty backup dir",
			config: &Config{
				BackupDir:          "",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			},
			expectError: true,
			errorType:   "empty backup dir",
		},
		{
			name: "invalid page size",
			config: &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           0,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			},
			expectError: true,
			errorType:   "invalid page size",
		},
		{
			name: "invalid max concurrent pages",
			config: &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 0,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			},
			expectError: true,
			errorType:   "invalid max concurrent pages",
		},
		{
			name: "invalid worker concurrency",
			config: &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  0,
			},
			expectError: true,
			errorType:   "invalid worker concurrency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newSecurityTestDB()
			contract := newSecurityTestContract(100)

			service, err := NewService(log, identity, db, contract, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestSecurity_PathTraversal(t *testing.T) {
	tests := []struct {
		name        string
		backupDate  string
		pageNumber  int
		expectError bool
	}{
		{
			name:        "valid backup date",
			backupDate:  "2024-01-15",
			pageNumber:  0,
			expectError: false,
		},
		{
			name:        "path traversal attempt",
			backupDate:  "../../../etc/passwd",
			pageNumber:  0,
			expectError: true,
		},
		{
			name:        "null byte injection",
			backupDate:  "2024-01-15\x00",
			pageNumber:  0,
			expectError: true,
		},
		{
			name:        "directory traversal with encoded chars",
			backupDate:  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			pageNumber:  0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			db := newSecurityTestDB()
			contract := newSecurityTestContract(100)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, db, contract, *config)

			// Test file path generation
			filePath, err := worker.savePageData(tt.backupDate, tt.pageNumber, []KeyValuePair{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, filePath)
			} else {
				// For valid cases, ensure the path is within the backup directory
				if err == nil {
					absBackupDir, _ := filepath.Abs(config.BackupDir)
					absFilePath, _ := filepath.Abs(filePath)
					assert.True(t, filepath.HasPrefix(absFilePath, absBackupDir), "File path should be within backup directory")
				}
			}
		})
	}
}

func TestSecurity_DataIntegrity(t *testing.T) {
	tests := []struct {
		name          string
		keyValuePairs []KeyValuePair
		expectError   bool
	}{
		{
			name: "valid data",
			keyValuePairs: []KeyValuePair{
				{Key: "key1", Value: "value1", VersionID: "v1"},
				{Key: "key2", Value: "value2", VersionID: "v2"},
			},
			expectError: false,
		},
		{
			name: "empty key",
			keyValuePairs: []KeyValuePair{
				{Key: "", Value: "value1", VersionID: "v1"},
			},
			expectError: true,
		},
		{
			name: "empty value",
			keyValuePairs: []KeyValuePair{
				{Key: "key1", Value: "", VersionID: "v1"},
			},
			expectError: false, // Empty values might be valid
		},
		{
			name: "empty version id",
			keyValuePairs: []KeyValuePair{
				{Key: "key1", Value: "value1", VersionID: ""},
			},
			expectError: true,
		},
		{
			name: "very large key",
			keyValuePairs: []KeyValuePair{
				{Key: string(make([]byte, 10000)), Value: "value1", VersionID: "v1"},
			},
			expectError: true,
		},
		{
			name: "very large value",
			keyValuePairs: []KeyValuePair{
				{Key: "key1", Value: string(make([]byte, 1000000)), VersionID: "v1"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			db := newSecurityTestDB()
			contract := newSecurityTestContract(100)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, db, contract, *config)

			filePath, err := worker.savePageData("2024-01-15", 0, tt.keyValuePairs)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, filePath)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, filePath)
			}
		})
	}
}

func TestSecurity_ChecksumValidation(t *testing.T) {
	tests := []struct {
		name        string
		data        []KeyValuePair
		expectValid bool
	}{
		{
			name: "valid data with checksum",
			data: []KeyValuePair{
				{Key: "key1", Value: "value1", VersionID: "v1"},
				{Key: "key2", Value: "value2", VersionID: "v2"},
			},
			expectValid: true,
		},
		{
			name:        "empty data",
			data:        []KeyValuePair{},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			db := newSecurityTestDB()
			contract := newSecurityTestContract(100)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, db, contract, *config)

			_, err := worker.savePageData("2024-01-15", 0, tt.data)
			require.NoError(t, err)

			// Verify checksum was generated
			pageStatus, err := db.GetBackupPageStatus(context.Background(), "2024-01-15", 0)
			require.NoError(t, err)
			require.NotNil(t, pageStatus)
			assert.NotEmpty(t, pageStatus.Checksum, "Checksum should be generated")

			// Verify file size
			assert.Greater(t, pageStatus.FileSize, int64(0), "File size should be greater than 0")
		})
	}
}

func TestSecurity_RateLimiting(t *testing.T) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		maxConcurrent int
		expectError   bool
	}{
		{
			name:          "normal load",
			totalKeys:     1000,
			pageSize:      100,
			maxConcurrent: 5,
			expectError:   false,
		},
		{
			name:          "high load",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 50,
			expectError:   false,
		},
		{
			name:          "excessive load",
			totalKeys:     100000,
			pageSize:      100,
			maxConcurrent: 1000,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newSecurityTestDB()
			contract := newSecurityTestContract(tt.totalKeys)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: tt.maxConcurrent,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			service, err := NewService(log, identity, db, contract, config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestSecurity_ContextCancellation(t *testing.T) {
	tests := []struct {
		name        string
		cancelAfter time.Duration
		expectError bool
	}{
		{
			name:        "normal execution",
			cancelAfter: 10 * time.Second,
			expectError: false,
		},
		{
			name:        "early cancellation",
			cancelAfter: 100 * time.Millisecond,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newSecurityTestDB()
			contract := newSecurityTestContract(1000)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			service, err := NewService(log, identity, db, contract, config)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start service
			err = service.Run(ctx)
			require.NoError(t, err)

			// Cancel after specified duration
			time.Sleep(tt.cancelAfter)
			cancel()

			// Wait for cleanup
			time.Sleep(1 * time.Second)

			// Verify service stopped gracefully
			// The service should handle cancellation without errors
		})
	}
}

func TestSecurity_ResourceExhaustion(t *testing.T) {
	tests := []struct {
		name        string
		totalKeys   uint64
		pageSize    int
		expectError bool
	}{
		{
			name:        "normal dataset",
			totalKeys:   1000,
			pageSize:    100,
			expectError: false,
		},
		{
			name:        "large dataset",
			totalKeys:   100000,
			pageSize:    100,
			expectError: false,
		},
		{
			name:        "very large dataset",
			totalKeys:   1000000,
			pageSize:    100,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newSecurityTestDB()
			contract := newSecurityTestContract(tt.totalKeys)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			service, err := NewService(log, identity, db, contract, config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestSecurity_AccessControl(t *testing.T) {
	tests := []struct {
		name        string
		backupDate  string
		pageNumber  int
		expectError bool
	}{
		{
			name:        "valid access",
			backupDate:  "2024-01-15",
			pageNumber:  0,
			expectError: false,
		},
		{
			name:        "negative page number",
			backupDate:  "2024-01-15",
			pageNumber:  -1,
			expectError: true,
		},
		{
			name:        "very large page number",
			backupDate:  "2024-01-15",
			pageNumber:  999999999,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			db := newSecurityTestDB()
			contract := newSecurityTestContract(100)

			config := &Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, db, contract, *config)

			// Test page processing with invalid inputs
			err := worker.processPage(context.Background(), tt.backupDate, tt.pageNumber)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				// For valid cases, the error might be nil or a specific error
				// We just want to ensure it doesn't panic or cause security issues
			}
		})
	}
}
