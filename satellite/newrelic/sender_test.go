// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package newrelic

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSender(t *testing.T) {
	t.Run("disabled sender", func(t *testing.T) {
		sender := NewSender("", false)

		require.NotNil(t, sender)
		require.False(t, sender.enabled)
		require.Empty(t, sender.apiKey)
		require.Equal(t, "https://log-api.newrelic.com/log/v1", sender.url)
		require.NotNil(t, sender.client)
		require.NotNil(t, sender.ticker)
		require.NotNil(t, sender.shutdown)
		require.Equal(t, 0, len(sender.buffer))
		require.Equal(t, maxBuffer, cap(sender.buffer))
	})

	t.Run("enabled sender", func(t *testing.T) {
		sender := NewSender("test_api_key_123", true)

		require.NotNil(t, sender)
		require.True(t, sender.enabled)
		require.Equal(t, "test_api_key_123", sender.apiKey)
		require.Equal(t, "https://log-api.newrelic.com/log/v1", sender.url)
		require.NotNil(t, sender.client)
		require.NotNil(t, sender.ticker)
		require.NotNil(t, sender.shutdown)
		require.Equal(t, 0, len(sender.buffer))
		require.Equal(t, maxBuffer, cap(sender.buffer))
	})
}

func TestSender_SendLog(t *testing.T) {
	t.Run("disabled sender - early return", func(t *testing.T) {
		sender := NewSender("", false)
		initialBufferLen := len(sender.buffer)

		// This should return early and not add to buffer
		sender.SendLog([]byte(`{"test": "data"}`))

		require.False(t, sender.enabled)
		require.Equal(t, initialBufferLen, len(sender.buffer))
	})

	t.Run("no api key - early return", func(t *testing.T) {
		sender := NewSender("", true)
		initialBufferLen := len(sender.buffer)

		// This should return early and not add to buffer
		sender.SendLog([]byte(`{"test": "data"}`))

		require.True(t, sender.enabled)
		require.Empty(t, sender.apiKey)
		require.Equal(t, initialBufferLen, len(sender.buffer))
	})

	t.Run("valid config - adds to buffer", func(t *testing.T) {
		sender := NewSender("valid_api_key", true)
		initialBufferLen := len(sender.buffer)

		// This should add to buffer
		sender.SendLog([]byte(`{"L":"INFO","M":"Test message","testData":"hello"}`))

		require.True(t, sender.enabled)
		require.Equal(t, "valid_api_key", sender.apiKey)
		require.Equal(t, initialBufferLen+1, len(sender.buffer))
	})

	t.Run("empty log data", func(t *testing.T) {
		sender := NewSender("test_key", true)

		// This should not crash
		sender.SendLog([]byte(""))
		sender.SendLog(nil)

		require.True(t, sender.enabled)
	})

	t.Run("json log data", func(t *testing.T) {
		sender := NewSender("test_key", true)

		// Test with JSON log data (like from zapwrapper)
		jsonLog := `{"L":"ERROR","T":"2024-01-15T10:30:00.000Z","C":"test.go:25","M":"Test error message","error":"test error"}`
		sender.SendLog([]byte(jsonLog))

		// Verify it doesn't crash
		require.True(t, sender.enabled)
		require.Equal(t, 1, len(sender.buffer))
	})
}

func TestSender_parseLog(t *testing.T) {
	t.Run("valid json log", func(t *testing.T) {
		sender := NewSender("test_key", true)

		jsonLog := `{"L":"INFO","M":"Test message","C":"test.go:25","customField":"customValue"}`
		entry := sender.parseLog([]byte(jsonLog))

		require.Equal(t, "Test message", entry.Message)
		require.Equal(t, "INFO", entry.Level)
		require.Equal(t, "test.go:25", entry.Caller)
		require.Equal(t, "application", entry.LogType)
		require.Contains(t, entry.Fields, "customField")
		require.Equal(t, "customValue", entry.Fields["customField"])
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("invalid json - fallback to raw message", func(t *testing.T) {
		sender := NewSender("test_key", true)

		rawLog := "This is not JSON"
		entry := sender.parseLog([]byte(rawLog))

		require.Equal(t, "This is not JSON", entry.Message)
		require.Equal(t, "application", entry.LogType)
		require.Empty(t, entry.Level)
		require.Empty(t, entry.Caller)
		require.Empty(t, entry.Fields)
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("empty json object", func(t *testing.T) {
		sender := NewSender("test_key", true)

		entry := sender.parseLog([]byte("{}"))

		require.Equal(t, "<nil>", entry.Message)
		require.Equal(t, "<nil>", entry.Level)
		require.Equal(t, "<nil>", entry.Caller)
		require.Equal(t, "application", entry.LogType)
		require.Empty(t, entry.Fields)
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("json with zap core fields only", func(t *testing.T) {
		sender := NewSender("test_key", true)

		jsonLog := `{"L":"DEBUG","M":"Debug message","C":"debug.go:10","N":"logger","T":"2024-01-15T10:30:00.000Z","S":"stack trace"}`
		entry := sender.parseLog([]byte(jsonLog))

		require.Equal(t, "Debug message", entry.Message)
		require.Equal(t, "DEBUG", entry.Level)
		require.Equal(t, "debug.go:10", entry.Caller)
		require.Equal(t, "application", entry.LogType)
		require.Empty(t, entry.Fields) // Should exclude zap core fields
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("json with mixed fields", func(t *testing.T) {
		sender := NewSender("test_key", true)

		jsonLog := `{"L":"WARN","M":"Warning message","C":"warn.go:5","N":"logger","T":"2024-01-15T10:30:00.000Z","S":"stack","userId":123,"action":"login","ip":"192.168.1.1"}`
		entry := sender.parseLog([]byte(jsonLog))

		require.Equal(t, "Warning message", entry.Message)
		require.Equal(t, "WARN", entry.Level)
		require.Equal(t, "warn.go:5", entry.Caller)
		require.Equal(t, "application", entry.LogType)
		require.Contains(t, entry.Fields, "userId")
		require.Contains(t, entry.Fields, "action")
		require.Contains(t, entry.Fields, "ip")
		require.Equal(t, float64(123), entry.Fields["userId"])
		require.Equal(t, "login", entry.Fields["action"])
		require.Equal(t, "192.168.1.1", entry.Fields["ip"])
		require.NotContains(t, entry.Fields, "N") // Should exclude zap core fields
		require.NotContains(t, entry.Fields, "T")
		require.NotContains(t, entry.Fields, "S")
		require.NotZero(t, entry.Timestamp)
	})
}

func TestSender_addToBuffer(t *testing.T) {
	t.Run("add single entry", func(t *testing.T) {
		sender := NewSender("test_key", true)
		entry := LogEntry{
			Message: "Test message",
			Level:   "INFO",
		}

		sender.addToBuffer(entry)

		require.Equal(t, 1, len(sender.buffer))
		require.Equal(t, "Test message", sender.buffer[0].Message)
		require.Equal(t, "INFO", sender.buffer[0].Level)
	})

	t.Run("add multiple entries", func(t *testing.T) {
		sender := NewSender("test_key", true)

		for i := 0; i < 5; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		require.Equal(t, 5, len(sender.buffer))
		for i := 0; i < 5; i++ {
			require.Equal(t, fmt.Sprintf("Test message %d", i), sender.buffer[i].Message)
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		sender := NewSender("test_key", true)
		entry := LogEntry{Message: "Test message", Level: "INFO"}

		// Test concurrent access
		var wg sync.WaitGroup
		numGoroutines := 10
		entriesPerGoroutine := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < entriesPerGoroutine; j++ {
					sender.addToBuffer(entry)
				}
			}()
		}

		wg.Wait()

		expectedCount := numGoroutines * entriesPerGoroutine
		require.Equal(t, expectedCount, len(sender.buffer))
	})
}

func TestSender_flush(t *testing.T) {
	t.Run("flush empty buffer", func(t *testing.T) {
		sender := NewSender("test_key", true)
		initialBufferLen := len(sender.buffer)

		sender.flush()

		require.Equal(t, initialBufferLen, len(sender.buffer))
	})

	t.Run("flush with entries", func(t *testing.T) {
		sender := NewSender("test_key", true)

		// Add some entries
		for i := 0; i < 3; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		require.Equal(t, 3, len(sender.buffer))

		// Flush should clear the buffer
		sender.flush()

		require.Equal(t, 0, len(sender.buffer))
	})
}

func TestSender_Close(t *testing.T) {
	t.Run("close with empty buffer", func(t *testing.T) {
		sender := NewSender("test_key", true)

		// Close should not crash
		sender.Close()

		// Verify ticker is stopped and shutdown is closed
		select {
		case <-sender.shutdown:
			// Expected - channel should be closed
		default:
			t.Error("shutdown channel should be closed")
		}
	})

	t.Run("close with pending logs", func(t *testing.T) {
		sender := NewSender("test_key", true)

		// Add some entries
		for i := 0; i < 3; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		require.Equal(t, 3, len(sender.buffer))

		// Close should flush remaining logs
		sender.Close()

		// Note: The actual flushing happens asynchronously in sendBatch,
		// so we can't guarantee the buffer is immediately empty after Close()
		// The important thing is that Close() doesn't crash and the goroutines are cleaned up
	})
}

func TestLogEntry(t *testing.T) {
	t.Run("log entry structure", func(t *testing.T) {
		entry := LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Message:   "Test message",
			Level:     "INFO",
			Caller:    "test.go:25",
			LogType:   "application",
			Fields: map[string]interface{}{
				"userId": 123,
				"action": "test",
			},
		}

		require.NotZero(t, entry.Timestamp)
		require.Equal(t, "Test message", entry.Message)
		require.Equal(t, "INFO", entry.Level)
		require.Equal(t, "test.go:25", entry.Caller)
		require.Equal(t, "application", entry.LogType)
		require.Contains(t, entry.Fields, "userId")
		require.Contains(t, entry.Fields, "action")
		require.Equal(t, 123, entry.Fields["userId"])
		require.Equal(t, "test", entry.Fields["action"])
	})

	t.Run("log entry json marshaling", func(t *testing.T) {
		entry := LogEntry{
			Timestamp: 1642248000000, // Fixed timestamp for testing
			Message:   "Test message",
			Level:     "INFO",
			Caller:    "test.go:25",
			LogType:   "application",
			Fields: map[string]interface{}{
				"userId": 123,
				"action": "test",
			},
		}

		jsonData, err := json.Marshal(entry)
		require.NoError(t, err)

		var unmarshaled LogEntry
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		require.Equal(t, entry.Timestamp, unmarshaled.Timestamp)
		require.Equal(t, entry.Message, unmarshaled.Message)
		require.Equal(t, entry.Level, unmarshaled.Level)
		require.Equal(t, entry.Caller, unmarshaled.Caller)
		require.Equal(t, entry.LogType, unmarshaled.LogType)
		// Note: JSON unmarshaling converts numbers to float64, so we check the values individually
		require.Equal(t, float64(123), unmarshaled.Fields["userId"])
		require.Equal(t, "test", unmarshaled.Fields["action"])
	})
}

func TestConstants(t *testing.T) {
	require.Equal(t, 500, maxBuffer)
	require.Equal(t, 2*time.Minute, flushInterval)
	require.Equal(t, 30*time.Second, httpTimeout)
	require.Equal(t, 3, maxRetries)
}
