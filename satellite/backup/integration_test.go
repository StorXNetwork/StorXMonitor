// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// integrationTestDB implements the DB interface for integration testing
type integrationTestDB struct {
	backupFinalStatuses map[string]*BackupFinalStatus
	backupPageStatuses  map[string]*BackupPageStatus
}

func newIntegrationTestDB() *integrationTestDB {
	return &integrationTestDB{
		backupFinalStatuses: make(map[string]*BackupFinalStatus),
		backupPageStatuses:  make(map[string]*BackupPageStatus),
	}
}

func (db *integrationTestDB) CreateBackupFinalStatus(ctx context.Context, backupDate string, status string) error {
	db.backupFinalStatuses[backupDate] = &BackupFinalStatus{
		BackupDate: backupDate,
		Status:     status,
	}
	return nil
}

func (db *integrationTestDB) UpdateBackupFinalStatus(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error {
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

func (db *integrationTestDB) GetBackupFinalStatus(ctx context.Context, backupDate string) (*BackupFinalStatus, error) {
	if status, exists := db.backupFinalStatuses[backupDate]; exists {
		return status, nil
	}
	return nil, nil
}

func (db *integrationTestDB) GetLatestBackupStatus(ctx context.Context) (*BackupFinalStatus, error) {
	var latest *BackupFinalStatus
	for _, status := range db.backupFinalStatuses {
		if latest == nil || status.BackupDate > latest.BackupDate {
			latest = status
		}
	}
	return latest, nil
}

func (db *integrationTestDB) ListBackupStatuses(ctx context.Context, limit int) ([]*BackupFinalStatus, error) {
	statuses := make([]*BackupFinalStatus, 0, len(db.backupFinalStatuses))
	for _, status := range db.backupFinalStatuses {
		statuses = append(statuses, status)
	}
	if limit > 0 && len(statuses) > limit {
		statuses = statuses[:limit]
	}
	return statuses, nil
}

func (db *integrationTestDB) CreateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string) error {
	key := backupDate + "_" + string(rune(pageNumber))
	db.backupPageStatuses[key] = &BackupPageStatus{
		BackupDate: backupDate,
		PageNumber: pageNumber,
		Status:     status,
	}
	return nil
}

func (db *integrationTestDB) UpdateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error {
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

func (db *integrationTestDB) GetBackupPageStatus(ctx context.Context, backupDate string, pageNumber int) (*BackupPageStatus, error) {
	key := backupDate + "_" + string(rune(pageNumber))
	if status, exists := db.backupPageStatuses[key]; exists {
		return status, nil
	}
	return nil, nil
}

func (db *integrationTestDB) GetBackupPageStatuses(ctx context.Context, backupDate string) ([]*BackupPageStatus, error) {
	var statuses []*BackupPageStatus
	for _, status := range db.backupPageStatuses {
		if status.BackupDate == backupDate {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

func (db *integrationTestDB) DeleteOldBackupStatuses(ctx context.Context, olderThan time.Time) error {
	return nil
}

func (db *integrationTestDB) DeleteBackupPageStatuses(ctx context.Context, backupDate string) error {
	return nil
}

// integrationTestContract implements the smartcontract.SocialShareHelper interface for integration testing
type integrationTestContract struct {
	totalKeys             uint64
	keyValuePairs         []KeyValuePair
	getTotalKeys          func(ctx context.Context) (uint64, error)
	getPaginatedKeyValues func(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error)
}

func newIntegrationTestContract(totalKeys uint64) *integrationTestContract {
	contract := &integrationTestContract{
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

func (c *integrationTestContract) GetTotalKeys(ctx context.Context) (uint64, error) {
	if c.getTotalKeys != nil {
		return c.getTotalKeys(ctx)
	}
	return c.totalKeys, nil
}

func (c *integrationTestContract) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	if c.getPaginatedKeyValues != nil {
		return c.getPaginatedKeyValues(ctx, startIndex, count)
	}

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

func (c *integrationTestContract) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	return []byte{}, nil
}

func (c *integrationTestContract) UploadSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func (c *integrationTestContract) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func TestIntegration_CompleteBackupWorkflow(t *testing.T) {
	tests := []struct {
		name           string
		totalKeys      uint64
		pageSize       int
		maxConcurrent  int
		expectedPages  int
		expectedStatus string
	}{
		{
			name:           "small dataset single page",
			totalKeys:      50,
			pageSize:       100,
			maxConcurrent:  5,
			expectedPages:  1,
			expectedStatus: BackupStatusCompleted,
		},
		{
			name:           "medium dataset multiple pages",
			totalKeys:      250,
			pageSize:       100,
			maxConcurrent:  5,
			expectedPages:  3,
			expectedStatus: BackupStatusCompleted,
		},
		{
			name:           "large dataset many pages",
			totalKeys:      1000,
			pageSize:       50,
			maxConcurrent:  10,
			expectedPages:  20,
			expectedStatus: BackupStatusCompleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			db := newIntegrationTestDB()
			contract := newIntegrationTestContract(tt.totalKeys)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: tt.maxConcurrent,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			// Create service
			service, err := NewService(log, db, contract, config)
			require.NoError(t, err)
			require.NotNil(t, service)

			// Start service
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(2 * time.Second)

			// Verify backup was created
			backupDate := time.Now().Format("2006-01-02")
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)
			assert.Equal(t, tt.expectedStatus, finalStatus.Status)
			assert.Equal(t, tt.expectedPages, finalStatus.TotalPages)
			assert.Equal(t, int(tt.totalKeys), finalStatus.TotalKeys)
			assert.NotEmpty(t, finalStatus.BackupFilePath)

			// Verify all pages were processed
			pageStatuses, err := db.GetBackupPageStatuses(ctx, backupDate)
			require.NoError(t, err)
			assert.Len(t, pageStatuses, tt.expectedPages)

			// Verify each page status
			for _, pageStatus := range pageStatuses {
				assert.Equal(t, BackupStatusCompleted, pageStatus.Status)
				assert.NotNil(t, pageStatus.CompletedAt)
				assert.Greater(t, pageStatus.KeysCount, 0)
				assert.NotEmpty(t, pageStatus.FilePath)
				assert.NotEmpty(t, pageStatus.Checksum)
				assert.Greater(t, pageStatus.FileSize, int64(0))
			}

			// Verify backup file exists
			assert.FileExists(t, finalStatus.BackupFilePath)

			// Verify backup file size
			fileInfo, err := os.Stat(finalStatus.BackupFilePath)
			require.NoError(t, err)
			assert.Equal(t, finalStatus.FileSize, fileInfo.Size())
		})
	}
}

func TestIntegration_BackupRetryOnFailure(t *testing.T) {
	tests := []struct {
		name           string
		contractError  bool
		expectedStatus string
	}{
		{
			name:           "successful backup",
			contractError:  false,
			expectedStatus: BackupStatusCompleted,
		},
		{
			name:           "failed backup",
			contractError:  true,
			expectedStatus: BackupStatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			db := newIntegrationTestDB()

			// Create contract that may fail
			contract := &integrationTestContract{
				totalKeys:     100,
				keyValuePairs: make([]KeyValuePair, 100),
			}

			if tt.contractError {
				contract.getTotalKeys = func(ctx context.Context) (uint64, error) {
					return 0, assert.AnError
				}
			}

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			// Create service
			service, err := NewService(log, db, contract, config)
			require.NoError(t, err)

			// Start service
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(2 * time.Second)

			// Verify backup status
			backupDate := time.Now().Format("2006-01-02")
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)
			assert.Equal(t, tt.expectedStatus, finalStatus.Status)

			if tt.contractError {
				assert.NotEmpty(t, finalStatus.ErrorMessage)
			} else {
				assert.Empty(t, finalStatus.ErrorMessage)
			}
		})
	}
}

func TestIntegration_ConcurrentPageProcessing(t *testing.T) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		maxConcurrent int
		expectedTime  time.Duration
	}{
		{
			name:          "sequential processing",
			totalKeys:     500,
			pageSize:      100,
			maxConcurrent: 1,
			expectedTime:  500 * time.Millisecond, // 5 pages * 100ms each
		},
		{
			name:          "concurrent processing",
			totalKeys:     500,
			pageSize:      100,
			maxConcurrent: 5,
			expectedTime:  200 * time.Millisecond, // 5 pages * 100ms each / 5 concurrent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			db := newIntegrationTestDB()

			// Create contract with artificial delay
			contract := &integrationTestContract{
				totalKeys:     tt.totalKeys,
				keyValuePairs: make([]KeyValuePair, tt.totalKeys),
			}

			// Add delay to simulate network latency
			contract.getPaginatedKeyValues = func(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
				time.Sleep(100 * time.Millisecond) // Simulate 100ms delay
				return contract.GetPaginatedKeyValues(ctx, startIndex, count)
			}

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: tt.maxConcurrent,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			// Create service
			service, err := NewService(log, db, contract, config)
			require.NoError(t, err)

			// Start service and measure time
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			startTime := time.Now()
			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(2 * time.Second)
			duration := time.Since(startTime)

			// Verify backup completed
			backupDate := time.Now().Format("2006-01-02")
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)
			assert.Equal(t, BackupStatusCompleted, finalStatus.Status)

			// Verify timing (with some tolerance)
			assert.Less(t, duration, tt.expectedTime*2, "Backup took longer than expected")
		})
	}
}

func TestIntegration_FileManagement(t *testing.T) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		expectedFiles int
	}{
		{
			name:          "single page backup",
			totalKeys:     50,
			pageSize:      100,
			expectedFiles: 1,
		},
		{
			name:          "multiple page backup",
			totalKeys:     250,
			pageSize:      100,
			expectedFiles: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			db := newIntegrationTestDB()
			contract := newIntegrationTestContract(tt.totalKeys)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 5,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			// Create service
			service, err := NewService(log, db, contract, config)
			require.NoError(t, err)

			// Start service
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(2 * time.Second)

			// Verify backup directory structure
			backupDate := time.Now().Format("2006-01-02")
			backupDir := filepath.Join(testDir, backupDate)
			assert.DirExists(t, backupDir)

			// Count page files
			pageFiles, err := filepath.Glob(filepath.Join(backupDir, "page_*.json"))
			require.NoError(t, err)
			assert.Len(t, pageFiles, tt.expectedFiles)

			// Verify each page file
			for _, pageFile := range pageFiles {
				assert.FileExists(t, pageFile)

				// Check file content
				content, err := os.ReadFile(pageFile)
				require.NoError(t, err)
				assert.NotEmpty(t, content)

				// Verify JSON structure
				var pageData []KeyValuePair
				err = json.Unmarshal(content, &pageData)
				require.NoError(t, err)
				assert.Greater(t, len(pageData), 0)
			}

			// Verify final backup file
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)

			if finalStatus.BackupFilePath != "" {
				assert.FileExists(t, finalStatus.BackupFilePath)

				// Check final backup file content
				content, err := os.ReadFile(finalStatus.BackupFilePath)
				require.NoError(t, err)
				assert.NotEmpty(t, content)

				// Verify it's a valid archive
				assert.Contains(t, string(content), "PK") // ZIP file signature
			}
		})
	}
}

func TestIntegration_BackupStatusTracking(t *testing.T) {
	tests := []struct {
		name           string
		totalKeys      uint64
		pageSize       int
		expectedStates []string
	}{
		{
			name:           "normal backup flow",
			totalKeys:      100,
			pageSize:       50,
			expectedStates: []string{BackupStatusInProgress, BackupStatusCompleted},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			db := newIntegrationTestDB()
			contract := newIntegrationTestContract(tt.totalKeys)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 5,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			// Create service
			service, err := NewService(log, db, contract, config)
			require.NoError(t, err)

			// Start service
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(2 * time.Second)

			// Verify backup status progression
			backupDate := time.Now().Format("2006-01-02")
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)

			// Verify final status
			assert.Equal(t, BackupStatusCompleted, finalStatus.Status)
			assert.NotNil(t, finalStatus.CompletedAt)
			assert.Greater(t, finalStatus.TotalPages, 0)
			assert.Equal(t, int(tt.totalKeys), finalStatus.TotalKeys)
			assert.NotEmpty(t, finalStatus.BackupFilePath)
			assert.NotEmpty(t, finalStatus.Checksum)
			assert.Greater(t, finalStatus.FileSize, int64(0))

			// Verify page statuses
			pageStatuses, err := db.GetBackupPageStatuses(ctx, backupDate)
			require.NoError(t, err)
			assert.Len(t, pageStatuses, finalStatus.TotalPages)

			for _, pageStatus := range pageStatuses {
				assert.Equal(t, BackupStatusCompleted, pageStatus.Status)
				assert.NotNil(t, pageStatus.CompletedAt)
				assert.Greater(t, pageStatus.KeysCount, 0)
				assert.NotEmpty(t, pageStatus.FilePath)
				assert.NotEmpty(t, pageStatus.Checksum)
				assert.Greater(t, pageStatus.FileSize, int64(0))
			}

			// Verify latest backup status
			latestStatus, err := db.GetLatestBackupStatus(ctx)
			require.NoError(t, err)
			require.NotNil(t, latestStatus)
			assert.Equal(t, backupDate, latestStatus.BackupDate)

			// Verify backup listing
			statuses, err := db.ListBackupStatuses(ctx, 10)
			require.NoError(t, err)
			assert.Len(t, statuses, 1)
			assert.Equal(t, backupDate, statuses[0].BackupDate)
		})
	}
}
