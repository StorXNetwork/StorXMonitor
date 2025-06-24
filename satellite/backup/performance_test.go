// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/identity"
)

// performanceTestDB implements the DB interface for performance testing
type performanceTestDB struct {
	backupFinalStatuses map[string]*BackupFinalStatus
	backupPageStatuses  map[string]*BackupPageStatus
}

func newPerformanceTestDB() *performanceTestDB {
	return &performanceTestDB{
		backupFinalStatuses: make(map[string]*BackupFinalStatus),
		backupPageStatuses:  make(map[string]*BackupPageStatus),
	}
}

func (db *performanceTestDB) CreateBackupFinalStatus(ctx context.Context, backupDate string, status string) error {
	db.backupFinalStatuses[backupDate] = &BackupFinalStatus{
		BackupDate: backupDate,
		Status:     status,
	}
	return nil
}

func (db *performanceTestDB) UpdateBackupFinalStatus(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error {
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

func (db *performanceTestDB) GetBackupFinalStatus(ctx context.Context, backupDate string) (*BackupFinalStatus, error) {
	if status, exists := db.backupFinalStatuses[backupDate]; exists {
		return status, nil
	}
	return nil, nil
}

func (db *performanceTestDB) GetLatestBackupStatus(ctx context.Context) (*BackupFinalStatus, error) {
	var latest *BackupFinalStatus
	for _, status := range db.backupFinalStatuses {
		if latest == nil || status.BackupDate > latest.BackupDate {
			latest = status
		}
	}
	return latest, nil
}

func (db *performanceTestDB) ListBackupStatuses(ctx context.Context, limit int) ([]*BackupFinalStatus, error) {
	statuses := make([]*BackupFinalStatus, 0, len(db.backupFinalStatuses))
	for _, status := range db.backupFinalStatuses {
		statuses = append(statuses, status)
	}
	if limit > 0 && len(statuses) > limit {
		statuses = statuses[:limit]
	}
	return statuses, nil
}

func (db *performanceTestDB) CreateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string) error {
	key := backupDate + "_" + string(rune(pageNumber))
	db.backupPageStatuses[key] = &BackupPageStatus{
		BackupDate: backupDate,
		PageNumber: pageNumber,
		Status:     status,
	}
	return nil
}

func (db *performanceTestDB) UpdateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error {
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

func (db *performanceTestDB) GetBackupPageStatus(ctx context.Context, backupDate string, pageNumber int) (*BackupPageStatus, error) {
	key := backupDate + "_" + string(rune(pageNumber))
	if status, exists := db.backupPageStatuses[key]; exists {
		return status, nil
	}
	return nil, nil
}

func (db *performanceTestDB) GetBackupPageStatuses(ctx context.Context, backupDate string) ([]*BackupPageStatus, error) {
	var statuses []*BackupPageStatus
	for _, status := range db.backupPageStatuses {
		if status.BackupDate == backupDate {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}

func (db *performanceTestDB) DeleteOldBackupStatuses(ctx context.Context, olderThan time.Time) error {
	return nil
}

func (db *performanceTestDB) DeleteBackupPageStatuses(ctx context.Context, backupDate string) error {
	return nil
}

// performanceTestContract implements the smartcontract.SocialShareHelper interface for performance testing
type performanceTestContract struct {
	totalKeys     uint64
	keyValuePairs []KeyValuePair
	latency       time.Duration
}

func newPerformanceTestContract(totalKeys uint64, latency time.Duration) *performanceTestContract {
	contract := &performanceTestContract{
		totalKeys:     totalKeys,
		keyValuePairs: make([]KeyValuePair, totalKeys),
		latency:       latency,
	}

	// Generate test data with realistic sizes
	for i := uint64(0); i < totalKeys; i++ {
		contract.keyValuePairs[i] = KeyValuePair{
			Key:       fmt.Sprintf("user_profile_key_%d", i),
			Value:     fmt.Sprintf(`{"user_id":"%d","name":"User %d","email":"user%d@example.com","preferences":{"theme":"dark","notifications":true},"metadata":{"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}}`, i, i, i),
			VersionID: fmt.Sprintf("v1.%d.%d", i, time.Now().Unix()),
		}
	}

	return contract
}

func (c *performanceTestContract) GetTotalKeys(ctx context.Context) (uint64, error) {
	time.Sleep(c.latency)
	return c.totalKeys, nil
}

func (c *performanceTestContract) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	time.Sleep(c.latency)

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

func (c *performanceTestContract) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	return []byte{}, nil
}

func (c *performanceTestContract) UploadSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func (c *performanceTestContract) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return nil
}

func BenchmarkBackup_Throughput(b *testing.B) {
	tests := []struct {
		name      string
		totalKeys uint64
		pageSize  int
		latency   time.Duration
	}{
		{
			name:      "small_dataset_fast_network",
			totalKeys: 1000,
			pageSize:  100,
			latency:   1 * time.Millisecond,
		},
		{
			name:      "medium_dataset_fast_network",
			totalKeys: 10000,
			pageSize:  100,
			latency:   1 * time.Millisecond,
		},
		{
			name:      "large_dataset_fast_network",
			totalKeys: 100000,
			pageSize:  100,
			latency:   1 * time.Millisecond,
		},
		{
			name:      "small_dataset_slow_network",
			totalKeys: 1000,
			pageSize:  100,
			latency:   100 * time.Millisecond,
		},
		{
			name:      "medium_dataset_slow_network",
			totalKeys: 10000,
			pageSize:  100,
			latency:   100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Setup
			testDir := b.TempDir()
			log := zaptest.NewLogger(b)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(b, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, tt.latency)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 10,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Start service
				ctx, cancel := context.WithCancel(context.Background())

				startTime := time.Now()
				err = service.Run(ctx)

				// Wait for backup to complete
				time.Sleep(5 * time.Second)
				duration := time.Since(startTime)

				// Verify backup completed
				backupDate := time.Now().Format("2006-01-02")
				finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
				require.NoError(b, err)
				require.NotNil(b, finalStatus)
				assert.Equal(b, BackupStatusCompleted, finalStatus.Status)

				// Report metrics
				b.ReportMetric(float64(tt.totalKeys)/duration.Seconds(), "keys/sec")
				b.ReportMetric(duration.Seconds(), "duration_sec")

				cancel()
			}
		})
	}
}

func BenchmarkBackup_Concurrency(b *testing.B) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		maxConcurrent int
		latency       time.Duration
	}{
		{
			name:          "low_concurrency",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 1,
			latency:       10 * time.Millisecond,
		},
		{
			name:          "medium_concurrency",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 5,
			latency:       10 * time.Millisecond,
		},
		{
			name:          "high_concurrency",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 20,
			latency:       10 * time.Millisecond,
		},
		{
			name:          "very_high_concurrency",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 50,
			latency:       10 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Setup
			testDir := b.TempDir()
			log := zaptest.NewLogger(b)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(b, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, tt.latency)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: tt.maxConcurrent,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Start service
				ctx, cancel := context.WithCancel(context.Background())

				startTime := time.Now()
				err = service.Run(ctx)

				// Wait for backup to complete
				time.Sleep(5 * time.Second)
				duration := time.Since(startTime)

				// Verify backup completed
				backupDate := time.Now().Format("2006-01-02")
				finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
				require.NoError(b, err)
				require.NotNil(b, finalStatus)
				assert.Equal(b, BackupStatusCompleted, finalStatus.Status)

				// Report metrics
				b.ReportMetric(float64(tt.totalKeys)/duration.Seconds(), "keys/sec")
				b.ReportMetric(duration.Seconds(), "duration_sec")
				b.ReportMetric(float64(tt.maxConcurrent), "concurrency")

				cancel()
			}
		})
	}
}

func BenchmarkBackup_MemoryUsage(b *testing.B) {
	tests := []struct {
		name      string
		totalKeys uint64
		pageSize  int
	}{
		{
			name:      "small_dataset",
			totalKeys: 1000,
			pageSize:  100,
		},
		{
			name:      "medium_dataset",
			totalKeys: 10000,
			pageSize:  100,
		},
		{
			name:      "large_dataset",
			totalKeys: 100000,
			pageSize:  100,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Setup
			testDir := b.TempDir()
			log := zaptest.NewLogger(b)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(b, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, 1*time.Millisecond)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 10,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Record memory before
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				beforeAlloc := m.Alloc

				// Start service
				ctx, cancel := context.WithCancel(context.Background())

				err = service.Run(ctx)

				// Wait for backup to complete
				time.Sleep(5 * time.Second)

				// Record memory after
				runtime.ReadMemStats(&m)
				afterAlloc := m.Alloc

				// Verify backup completed
				backupDate := time.Now().Format("2006-01-02")
				finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
				require.NoError(b, err)
				require.NotNil(b, finalStatus)
				assert.Equal(b, BackupStatusCompleted, finalStatus.Status)

				// Report memory usage
				memoryUsed := afterAlloc - beforeAlloc
				b.ReportMetric(float64(memoryUsed), "memory_bytes")
				b.ReportMetric(float64(memoryUsed)/float64(tt.totalKeys), "memory_per_key")

				cancel()

				// Force garbage collection
				runtime.GC()
			}
		})
	}
}

func BenchmarkBackup_PageSizeOptimization(b *testing.B) {
	tests := []struct {
		name      string
		totalKeys uint64
		pageSize  int
		latency   time.Duration
	}{
		{
			name:      "small_pages",
			totalKeys: 10000,
			pageSize:  10,
			latency:   10 * time.Millisecond,
		},
		{
			name:      "medium_pages",
			totalKeys: 10000,
			pageSize:  100,
			latency:   10 * time.Millisecond,
		},
		{
			name:      "large_pages",
			totalKeys: 10000,
			pageSize:  1000,
			latency:   10 * time.Millisecond,
		},
		{
			name:      "very_large_pages",
			totalKeys: 10000,
			pageSize:  10000,
			latency:   10 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Setup
			testDir := b.TempDir()
			log := zaptest.NewLogger(b)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(b, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, tt.latency)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 10,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Start service
				ctx, cancel := context.WithCancel(context.Background())

				startTime := time.Now()
				err = service.Run(ctx)

				// Wait for backup to complete
				time.Sleep(5 * time.Second)
				duration := time.Since(startTime)

				// Verify backup completed
				backupDate := time.Now().Format("2006-01-02")
				finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
				require.NoError(b, err)
				require.NotNil(b, finalStatus)
				assert.Equal(b, BackupStatusCompleted, finalStatus.Status)

				// Report metrics
				b.ReportMetric(float64(tt.totalKeys)/duration.Seconds(), "keys/sec")
				b.ReportMetric(duration.Seconds(), "duration_sec")
				b.ReportMetric(float64(tt.pageSize), "page_size")

				cancel()
			}
		})
	}
}

func TestPerformance_LoadTest(t *testing.T) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		maxConcurrent int
		expectedTime  time.Duration
	}{
		{
			name:          "load_test_small",
			totalKeys:     1000,
			pageSize:      100,
			maxConcurrent: 5,
			expectedTime:  10 * time.Second,
		},
		{
			name:          "load_test_medium",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 10,
			expectedTime:  30 * time.Second,
		},
		{
			name:          "load_test_large",
			totalKeys:     100000,
			pageSize:      100,
			maxConcurrent: 20,
			expectedTime:  120 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, 5*time.Millisecond)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: tt.maxConcurrent,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(t, err)

			// Start service and measure time
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			startTime := time.Now()
			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete with timeout
			timeout := tt.expectedTime + 30*time.Second
			done := make(chan bool)
			go func() {
				for {
					backupDate := time.Now().Format("2006-01-02")
					finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
					if err == nil && finalStatus != nil && finalStatus.Status == BackupStatusCompleted {
						done <- true
						return
					}
					time.Sleep(1 * time.Second)
				}
			}()

			select {
			case <-done:
				duration := time.Since(startTime)
				t.Logf("Backup completed in %v", duration)

				// Verify backup completed successfully
				backupDate := time.Now().Format("2006-01-02")
				finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
				require.NoError(t, err)
				require.NotNil(t, finalStatus)
				assert.Equal(t, BackupStatusCompleted, finalStatus.Status)
				assert.Equal(t, int(tt.totalKeys), finalStatus.TotalKeys)

				// Performance assertions
				assert.Less(t, duration, tt.expectedTime, "Backup took longer than expected")

				// Calculate throughput
				throughput := float64(tt.totalKeys) / duration.Seconds()
				t.Logf("Throughput: %.2f keys/sec", throughput)
				assert.Greater(t, throughput, 10.0, "Throughput should be at least 10 keys/sec")

			case <-time.After(timeout):
				t.Fatalf("Backup did not complete within %v", timeout)
			}
		})
	}
}

func TestPerformance_Throughput(t *testing.T) {
	tests := []struct {
		name      string
		totalKeys uint64
		pageSize  int
		latency   time.Duration
	}{
		{
			name:      "small_dataset_fast_network",
			totalKeys: 1000,
			pageSize:  100,
			latency:   1 * time.Millisecond,
		},
		{
			name:      "medium_dataset_fast_network",
			totalKeys: 10000,
			pageSize:  100,
			latency:   1 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, tt.latency)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: 10,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(t, err)

			// Start service
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			startTime := time.Now()
			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(5 * time.Second)
			duration := time.Since(startTime)

			// Verify backup completed
			backupDate := time.Now().Format("2006-01-02")
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)
			assert.Equal(t, BackupStatusCompleted, finalStatus.Status)

			// Calculate and report throughput
			throughput := float64(tt.totalKeys) / duration.Seconds()
			t.Logf("Throughput: %.2f keys/sec", throughput)
			t.Logf("Duration: %.2f seconds", duration.Seconds())

			// Performance assertions
			assert.Greater(t, throughput, 10.0, "Throughput should be at least 10 keys/sec")
		})
	}
}

func TestPerformance_Concurrency(t *testing.T) {
	tests := []struct {
		name          string
		totalKeys     uint64
		pageSize      int
		maxConcurrent int
		latency       time.Duration
	}{
		{
			name:          "low_concurrency",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 1,
			latency:       10 * time.Millisecond,
		},
		{
			name:          "high_concurrency",
			totalKeys:     10000,
			pageSize:      100,
			maxConcurrent: 20,
			latency:       10 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			testDir := t.TempDir()
			log := zaptest.NewLogger(t)

			identity, err := identity.NewFullIdentity(context.Background(), identity.NewCAOptions{
				Difficulty:  0,
				Concurrency: 1,
			})
			require.NoError(t, err)

			db := newPerformanceTestDB()
			contract := newPerformanceTestContract(tt.totalKeys, tt.latency)

			config := &Config{
				BackupDir:          testDir,
				MaxConcurrentPages: tt.maxConcurrent,
				PageSize:           tt.pageSize,
				ChoreInterval:      time.Hour,
				WorkerConcurrency:  4,
			}

			// Create service
			service, err := NewService(log, identity, db, contract, config)
			require.NoError(t, err)

			// Start service
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			startTime := time.Now()
			err = service.Run(ctx)
			require.NoError(t, err)

			// Wait for backup to complete
			time.Sleep(5 * time.Second)
			duration := time.Since(startTime)

			// Verify backup completed
			backupDate := time.Now().Format("2006-01-02")
			finalStatus, err := db.GetBackupFinalStatus(ctx, backupDate)
			require.NoError(t, err)
			require.NotNil(t, finalStatus)
			assert.Equal(t, BackupStatusCompleted, finalStatus.Status)

			// Calculate and report throughput
			throughput := float64(tt.totalKeys) / duration.Seconds()
			t.Logf("Concurrency: %d", tt.maxConcurrent)
			t.Logf("Throughput: %.2f keys/sec", throughput)
			t.Logf("Duration: %.2f seconds", duration.Seconds())

			// Performance assertions
			assert.Greater(t, throughput, 10.0, "Throughput should be at least 10 keys/sec")
		})
	}
}
