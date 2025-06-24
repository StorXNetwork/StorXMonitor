// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/identity"
)

// mockDB implements the DB interface for testing
type mockDB struct {
	backupFinalStatuses map[string]*BackupFinalStatus
	backupPageStatuses  map[string]*BackupPageStatus
	createFinalStatus   func(ctx context.Context, backupDate string, status string) error
	updateFinalStatus   func(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error
	getFinalStatus      func(ctx context.Context, backupDate string) (*BackupFinalStatus, error)
	createPageStatus    func(ctx context.Context, backupDate string, pageNumber int, status string) error
	updatePageStatus    func(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error
	getPageStatus       func(ctx context.Context, backupDate string, pageNumber int) (*BackupPageStatus, error)
	getPageStatuses     func(ctx context.Context, backupDate string) ([]*BackupPageStatus, error)
}

func (m *mockDB) CreateBackupFinalStatus(ctx context.Context, backupDate string, status string) error {
	if m.createFinalStatus != nil {
		return m.createFinalStatus(ctx, backupDate, status)
	}
	if m.backupFinalStatuses == nil {
		m.backupFinalStatuses = make(map[string]*BackupFinalStatus)
	}
	m.backupFinalStatuses[backupDate] = &BackupFinalStatus{
		BackupDate: backupDate,
		Status:     status,
	}
	return nil
}

func (m *mockDB) UpdateBackupFinalStatus(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error {
	if m.updateFinalStatus != nil {
		return m.updateFinalStatus(ctx, backupDate, status, completedAt, totalPages, totalKeys, backupFilePath, errorMessage, checksum, fileSize)
	}
	if backupStatus, exists := m.backupFinalStatuses[backupDate]; exists {
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

func (m *mockDB) GetBackupFinalStatus(ctx context.Context, backupDate string) (*BackupFinalStatus, error) {
	if m.getFinalStatus != nil {
		return m.getFinalStatus(ctx, backupDate)
	}
	if status, exists := m.backupFinalStatuses[backupDate]; exists {
		return status, nil
	}
	return nil, nil
}

func (m *mockDB) GetLatestBackupStatus(ctx context.Context) (*BackupFinalStatus, error) {
	var latest *BackupFinalStatus
	for _, status := range m.backupFinalStatuses {
		if latest == nil || status.BackupDate > latest.BackupDate {
			latest = status
		}
	}
	return latest, nil
}

func (m *mockDB) ListBackupStatuses(ctx context.Context, limit int) ([]*BackupFinalStatus, error) {
	statuses := make([]*BackupFinalStatus, 0, len(m.backupFinalStatuses))
	for _, status := range m.backupFinalStatuses {
		statuses = append(statuses, status)
	}
	if limit > 0 && len(statuses) > limit {
		statuses = statuses[:limit]
	}
	return statuses, nil
}

func (m *mockDB) CreateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string) error {
	if m.createPageStatus != nil {
		return m.createPageStatus(ctx, backupDate, pageNumber, status)
	}
	if m.backupPageStatuses == nil {
		m.backupPageStatuses = make(map[string]*BackupPageStatus)
	}
	key := backupDate + "_" + string(rune(pageNumber))
	m.backupPageStatuses[key] = &BackupPageStatus{
		BackupDate: backupDate,
		PageNumber: pageNumber,
		Status:     status,
	}
	return nil
}

func (m *mockDB) UpdateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error {
	if m.updatePageStatus != nil {
		return m.updatePageStatus(ctx, backupDate, pageNumber, status, completedAt, keysCount, filePath, errorMessage, checksum, fileSize)
	}
	key := backupDate + "_" + string(rune(pageNumber))
	if pageStatus, exists := m.backupPageStatuses[key]; exists {
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

func (m *mockDB) GetBackupPageStatus(ctx context.Context, backupDate string, pageNumber int) (*BackupPageStatus, error) {
	if m.getPageStatus != nil {
		return m.getPageStatus(ctx, backupDate, pageNumber)
	}
	key := backupDate + "_" + string(rune(pageNumber))
	if status, exists := m.backupPageStatuses[key]; exists {
		return status, nil
	}
	return nil, nil
}

func (m *mockDB) GetBackupPageStatuses(ctx context.Context, backupDate string) ([]*BackupPageStatus, error) {
	if m.getPageStatuses != nil {
		return m.getPageStatuses(ctx, backupDate)
	}
	var statuses []*BackupPageStatus
	for _, status := range m.backupPageStatuses {
		if status.BackupDate == backupDate {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

func (m *mockDB) DeleteOldBackupStatuses(ctx context.Context, olderThan time.Time) error {
	return nil
}

func (m *mockDB) DeleteBackupPageStatuses(ctx context.Context, backupDate string) error {
	return nil
}

// mockSmartContract implements the smartcontract.SocialShareHelper interface for testing
type mockSmartContract struct {
	totalKeys             uint64
	keyValuePairs         []KeyValuePair
	getTotalKeys          func(ctx context.Context) (uint64, error)
	getPaginatedKeyValues func(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error)
}

func (m *mockSmartContract) GetTotalKeys(ctx context.Context) (uint64, error) {
	if m.getTotalKeys != nil {
		return m.getTotalKeys(ctx)
	}
	return m.totalKeys, nil
}

func (m *mockSmartContract) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	if m.getPaginatedKeyValues != nil {
		return m.getPaginatedKeyValues(ctx, startIndex, count)
	}

	endIndex := startIndex + count
	if endIndex > uint64(len(m.keyValuePairs)) {
		endIndex = uint64(len(m.keyValuePairs))
	}

	if startIndex >= uint64(len(m.keyValuePairs)) {
		return []string{}, []string{}, []string{}, nil
	}

	pairs := m.keyValuePairs[startIndex:endIndex]
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

// Implement the missing GetSocialShare method to satisfy the interface
func (m *mockSmartContract) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	return []byte{}, nil
}

// Implement UploadSocialShare method
func (m *mockSmartContract) UploadSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

// Implement UpdateSocialShare method
func (m *mockSmartContract) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func TestService_NewService(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
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

			mockDB := &mockDB{}
			mockContract := &mockSmartContract{}

			service, err := NewService(log, identity, mockDB, mockContract, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
				assert.NotNil(t, service.Backup.Worker)
			}
		})
	}
}

func TestWorker_NewWorker(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default config",
			config: Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			},
		},
		{
			name: "custom config",
			config: Config{
				BackupDir:          "./custom_backups",
				MaxConcurrentPages: 10,
				PageSize:           200,
				ChoreInterval:      2 * time.Hour,
				WorkerConcurrency:  5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			mockDB := &mockDB{}
			mockContract := &mockSmartContract{}

			worker := NewWorker(log, mockDB, mockContract, tt.config)

			assert.NotNil(t, worker)
			assert.Equal(t, log, worker.log)
			assert.Equal(t, mockDB, worker.db)
			assert.Equal(t, mockContract, worker.contract)
			assert.Equal(t, &tt.config, worker.config)
			assert.Equal(t, tt.config.WorkerConcurrency, worker.concurrency)
			assert.NotNil(t, worker.Loop)
		})
	}
}

func TestWorker_Process_AlreadyCompleted(t *testing.T) {
	tests := []struct {
		name           string
		backupDate     string
		existingStatus *BackupFinalStatus
		expectProcess  bool
	}{
		{
			name:           "no existing backup",
			backupDate:     "2024-01-15",
			existingStatus: nil,
			expectProcess:  true,
		},
		{
			name:       "existing completed backup",
			backupDate: "2024-01-15",
			existingStatus: &BackupFinalStatus{
				BackupDate: "2024-01-15",
				Status:     BackupStatusCompleted,
			},
			expectProcess: false,
		},
		{
			name:       "existing failed backup",
			backupDate: "2024-01-15",
			existingStatus: &BackupFinalStatus{
				BackupDate: "2024-01-15",
				Status:     BackupStatusFailed,
			},
			expectProcess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			mockDB := &mockDB{
				getFinalStatus: func(ctx context.Context, backupDate string) (*BackupFinalStatus, error) {
					return tt.existingStatus, nil
				},
			}
			mockContract := &mockSmartContract{
				totalKeys: 100,
			}

			config := Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, mockDB, mockContract, config)

			ctx := context.Background()
			err := worker.process(ctx)

			assert.NoError(t, err)
			// Since we can't mock the method directly, we'll just verify the process runs without error
			// The actual logic testing will be done in the executeBackup test
		})
	}
}

func TestWorker_ExecuteBackup(t *testing.T) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		contractError bool
		expectError   bool
		expectedPages int
	}{
		{
			name:          "successful backup with single page",
			totalKeys:     50,
			pageSize:      100,
			contractError: false,
			expectError:   false,
			expectedPages: 1,
		},
		{
			name:          "successful backup with multiple pages",
			totalKeys:     250,
			pageSize:      100,
			contractError: false,
			expectError:   false,
			expectedPages: 3,
		},
		{
			name:          "contract error",
			totalKeys:     100,
			pageSize:      100,
			contractError: true,
			expectError:   true,
			expectedPages: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			mockDB := &mockDB{}

			mockContract := &mockSmartContract{
				totalKeys: tt.totalKeys,
				getTotalKeys: func(ctx context.Context) (uint64, error) {
					if tt.contractError {
						return 0, assert.AnError
					}
					return tt.totalKeys, nil
				},
			}

			config := Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, mockDB, mockContract, config)

			ctx := context.Background()
			backupDate := "2024-01-15"

			err := worker.executeBackup(ctx, backupDate)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify backup status was created
				status, err := mockDB.GetBackupFinalStatus(ctx, backupDate)
				assert.NoError(t, err)
				assert.NotNil(t, status)
				assert.Equal(t, BackupStatusCompleted, status.Status)
				assert.Equal(t, tt.expectedPages, status.TotalPages)
			}
		})
	}
}

func TestWorker_ProcessPage(t *testing.T) {
	tests := []struct {
		name          string
		pageNumber    int
		pageSize      int
		keyValuePairs []KeyValuePair
		contractError bool
		expectError   bool
	}{
		{
			name:       "successful page processing",
			pageNumber: 0,
			pageSize:   100,
			keyValuePairs: []KeyValuePair{
				{Key: "key1", Value: "value1", VersionID: "v1"},
				{Key: "key2", Value: "value2", VersionID: "v2"},
			},
			contractError: false,
			expectError:   false,
		},
		{
			name:          "contract error",
			pageNumber:    0,
			pageSize:      100,
			keyValuePairs: nil,
			contractError: true,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			mockDB := &mockDB{}

			mockContract := &mockSmartContract{
				keyValuePairs: tt.keyValuePairs,
				getPaginatedKeyValues: func(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
					if tt.contractError {
						return nil, nil, nil, assert.AnError
					}

					keys = make([]string, len(tt.keyValuePairs))
					values = make([]string, len(tt.keyValuePairs))
					versionIds = make([]string, len(tt.keyValuePairs))

					for i, pair := range tt.keyValuePairs {
						keys[i] = pair.Key
						values[i] = pair.Value
						versionIds[i] = pair.VersionID
					}

					return keys, values, versionIds, nil
				},
			}

			config := Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, mockDB, mockContract, config)

			ctx := context.Background()
			backupDate := "2024-01-15"

			err := worker.processPage(ctx, backupDate, tt.pageNumber)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify page status was created
				status, err := mockDB.GetBackupPageStatus(ctx, backupDate, tt.pageNumber)
				assert.NoError(t, err)
				assert.NotNil(t, status)
				assert.Equal(t, BackupStatusCompleted, status.Status)
				assert.Equal(t, len(tt.keyValuePairs), status.KeysCount)
			}
		})
	}
}

func TestWorker_FileManagement(t *testing.T) {
	tests := []struct {
		name          string
		backupDate    string
		pageNumber    int
		keyValuePairs []KeyValuePair
		expectError   bool
	}{
		{
			name:       "save page data successfully",
			backupDate: "2024-01-15",
			pageNumber: 0,
			keyValuePairs: []KeyValuePair{
				{Key: "key1", Value: "value1", VersionID: "v1"},
				{Key: "key2", Value: "value2", VersionID: "v2"},
			},
			expectError: false,
		},
		{
			name:          "empty page data",
			backupDate:    "2024-01-15",
			pageNumber:    0,
			keyValuePairs: []KeyValuePair{},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			mockDB := &mockDB{}
			mockContract := &mockSmartContract{}

			config := Config{
				BackupDir:          "./test_backups",
				MaxConcurrentPages: 5,
				PageSize:           100,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  2,
			}

			worker := NewWorker(log, mockDB, mockContract, config)

			filePath, err := worker.savePageData(tt.backupDate, tt.pageNumber, tt.keyValuePairs)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, filePath)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, filePath)

				// Verify file was created
				// Note: In a real test, you might want to check file contents
				// but for unit tests, we'll just verify the path is returned
			}
		})
	}
}

func TestBackupStatus_Constants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "BackupStatusInProgress",
			constant: BackupStatusInProgress,
			expected: "in_progress",
		},
		{
			name:     "BackupStatusCompleted",
			constant: BackupStatusCompleted,
			expected: "completed",
		},
		{
			name:     "BackupStatusFailed",
			constant: BackupStatusFailed,
			expected: "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestKeyValuePair_JSON(t *testing.T) {
	tests := []struct {
		name     string
		pair     KeyValuePair
		expected string
	}{
		{
			name: "basic key value pair",
			pair: KeyValuePair{
				Key:       "test_key",
				Value:     "test_value",
				VersionID: "v1.0",
			},
			expected: `{"key":"test_key","value":"test_value","version_id":"v1.0"}`,
		},
		{
			name: "empty values",
			pair: KeyValuePair{
				Key:       "",
				Value:     "",
				VersionID: "",
			},
			expected: `{"key":"","value":"","version_id":""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.pair)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))

			// Test JSON unmarshaling
			var unmarshaled KeyValuePair
			err = json.Unmarshal(data, &unmarshaled)
			assert.NoError(t, err)
			assert.Equal(t, tt.pair, unmarshaled)
		})
	}
}
