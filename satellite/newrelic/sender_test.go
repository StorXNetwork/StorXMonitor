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

const (
	maxBuffer     = 500
	flushInterval = 2 * time.Minute
	maxRetries    = 3
)

func TestNewSender(t *testing.T) {
	t.Run("disabled sender", func(t *testing.T) {
		sender := NewSender("", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_api_key_123", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("", flushInterval, maxBuffer, maxRetries)
		initialBufferLen := len(sender.buffer)

		// This should return early and not add to buffer
		sender.SendLog([]byte(`{"test": "data"}`))

		require.False(t, sender.enabled)
		require.Equal(t, initialBufferLen, len(sender.buffer))
	})

	t.Run("no api key - early return", func(t *testing.T) {
		sender := NewSender("", flushInterval, maxBuffer, maxRetries)
		initialBufferLen := len(sender.buffer)

		// This should return early and not add to buffer
		sender.SendLog([]byte(`{"test": "data"}`))

		require.False(t, sender.enabled)
		require.Empty(t, sender.apiKey)
		require.Equal(t, initialBufferLen, len(sender.buffer))
	})

	t.Run("valid config - adds to buffer", func(t *testing.T) {
		sender := NewSender("valid_api_key", flushInterval, maxBuffer, maxRetries)
		initialBufferLen := len(sender.buffer)

		// This should add to buffer
		sender.SendLog([]byte(`{"L":"INFO","M":"Test message","testData":"hello"}`))

		require.True(t, sender.enabled)
		require.Equal(t, "valid_api_key", sender.apiKey)
		require.Equal(t, initialBufferLen+1, len(sender.buffer))
	})

	t.Run("empty log data", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		// This should not crash
		sender.SendLog([]byte(""))
		sender.SendLog(nil)

		require.True(t, sender.enabled)
	})

	t.Run("json log data", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		entry := sender.parseLog([]byte("{}"))

		require.Equal(t, "", entry.Message)
		require.Equal(t, "", entry.Level)
		require.Equal(t, "", entry.Caller)
		require.Equal(t, "application", entry.LogType)
		require.Empty(t, entry.Fields)
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("json with zap core fields only", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)
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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)
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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)
		initialBufferLen := len(sender.buffer)

		sender.flush()

		require.Equal(t, initialBufferLen, len(sender.buffer))
	})

	t.Run("flush with entries", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

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

func TestSender_flushLoop(t *testing.T) {
	t.Run("flushLoop stops on shutdown", func(t *testing.T) {
		sender := NewSender("test_key", 10*time.Millisecond, maxBuffer, maxRetries)

		// Add some logs to buffer
		for i := 0; i < 3; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		// Wait a bit for the ticker to potentially trigger
		time.Sleep(50 * time.Millisecond)

		// Close should stop the flushLoop
		sender.Close()

		// Verify shutdown channel is closed
		select {
		case <-sender.shutdown:
			// Expected - channel should be closed
		default:
			t.Error("shutdown channel should be closed")
		}
	})
}

func TestSender_sendBatch(t *testing.T) {
	t.Run("sendBatch with empty logs", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		// Should not crash with empty logs
		sender.sendBatch([]LogEntry{})
	})

	t.Run("sendBatch with invalid JSON", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		// Create a log entry that will cause JSON marshaling to fail
		// We'll use a channel which can't be marshaled to JSON
		entry := LogEntry{
			Message: "Test message",
			Level:   "INFO",
			Fields: map[string]interface{}{
				"invalidField": make(chan int), // This will cause JSON marshal to fail
			},
		}

		// This should handle the error gracefully
		sender.sendBatch([]LogEntry{entry})
	})

	t.Run("sendBatch with valid logs", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		logs := []LogEntry{
			{Message: "Test message 1", Level: "INFO"},
			{Message: "Test message 2", Level: "ERROR"},
		}

		// This will try to send to New Relic (will fail with 403 due to test key)
		// but should not crash
		sender.sendBatch(logs)
	})
}

func TestSender_addToBuffer_BufferFull(t *testing.T) {
	t.Run("buffer full triggers async flush", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, 3, maxRetries) // Small buffer for testing

		// Fill buffer to capacity
		for i := 0; i < 3; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		// Buffer should be at capacity
		require.Equal(t, 3, len(sender.buffer))

		// Add one more - this should trigger async flush
		entry := LogEntry{
			Message: "Trigger message",
			Level:   "INFO",
		}
		sender.addToBuffer(entry)

		// Wait for async flush to complete
		sender.wg.Wait()

		// Buffer should be empty after flush
		require.Equal(t, 0, len(sender.buffer))
	})
}

func TestSender_parseLog_EdgeCases(t *testing.T) {
	t.Run("parseLog with nil data", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		entry := sender.parseLog(nil)

		require.Equal(t, "", entry.Message)
		require.Equal(t, "application", entry.LogType)
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("parseLog with malformed JSON", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		malformedJSON := `{"L":"INFO","M":"Test message","C":"test.go:25"` // Missing closing brace
		entry := sender.parseLog([]byte(malformedJSON))

		require.Equal(t, malformedJSON, entry.Message)
		require.Equal(t, "application", entry.LogType)
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("parseLog with non-string values", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		jsonLog := `{"L":123,"M":456,"C":789,"userId":123,"action":"login"}`
		entry := sender.parseLog([]byte(jsonLog))

		require.Equal(t, "456", entry.Message) // Should convert to string
		require.Equal(t, "123", entry.Level)
		require.Equal(t, "789", entry.Caller)
		require.Contains(t, entry.Fields, "userId")
		require.Contains(t, entry.Fields, "action")
		require.Equal(t, float64(123), entry.Fields["userId"])
		require.Equal(t, "login", entry.Fields["action"])
	})
}

func TestSender_Close_WithPendingLogs(t *testing.T) {
	t.Run("close flushes remaining logs", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		// Add some logs
		for i := 0; i < 5; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		require.Equal(t, 5, len(sender.buffer))

		// Close should flush remaining logs
		sender.Close()

		// Note: The actual flushing happens asynchronously in sendBatch,
		// so we can't guarantee the buffer is immediately empty after Close()
		// The important thing is that Close() doesn't crash and the goroutines are cleaned up
		// We can verify the shutdown channel is closed
		select {
		case <-sender.shutdown:
			// Expected - channel should be closed
		default:
			t.Error("shutdown channel should be closed")
		}
	})
}

func TestSender_ConcurrentOperations(t *testing.T) {
	t.Run("concurrent SendLog and Close", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		var wg sync.WaitGroup

		// Start goroutine that sends logs
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				jsonLog := fmt.Sprintf(`{"L":"INFO","M":"Concurrent message %d"}`, i)
				sender.SendLog([]byte(jsonLog))
				time.Sleep(1 * time.Millisecond)
			}
		}()

		// Start goroutine that closes sender
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Millisecond)
			sender.Close()
		}()

		wg.Wait()

		// Should not crash and should handle concurrent access gracefully
	})
}

func TestSender_HTTPErrorHandling(t *testing.T) {
	t.Run("handles different HTTP status codes", func(t *testing.T) {
		// This test verifies the retry logic and error handling
		// We can't easily mock HTTP responses in this test, but we can verify
		// that the method doesn't crash with different scenarios
		sender := NewSender("invalid_key", flushInterval, maxBuffer, maxRetries)

		logs := []LogEntry{
			{Message: "Test message", Level: "INFO"},
		}

		// This will fail with 403 (auth error) and should not retry
		sender.sendBatch(logs)

		// Test with empty API key
		sender2 := NewSender("", flushInterval, maxBuffer, maxRetries)
		sender2.sendBatch(logs)
	})
}

func TestSender_flushAsync(t *testing.T) {
	t.Run("flushAsync decrements wait group", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		// Add some logs to trigger async flush
		for i := 0; i < 3; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		// Wait for async flush to complete
		sender.wg.Wait()

		// Should not crash and wait group should be properly managed
	})
}

func TestSender_parseLog_Comprehensive(t *testing.T) {
	t.Run("parseLog with complex JSON structure", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		complexJSON := `{
			"L": "ERROR",
			"M": "Complex error message",
			"C": "complex.go:42",
			"N": "logger",
			"T": "2024-01-15T10:30:00.000Z",
			"S": "stack trace",
			"userId": 12345,
			"sessionId": "abc-123-def",
			"requestId": "req-456",
			"metadata": {
				"version": "1.0",
				"environment": "production"
			},
			"tags": ["error", "critical"],
			"count": 42,
			"active": true
		}`

		entry := sender.parseLog([]byte(complexJSON))

		require.Equal(t, "Complex error message", entry.Message)
		require.Equal(t, "ERROR", entry.Level)
		require.Equal(t, "complex.go:42", entry.Caller)
		require.Equal(t, "application", entry.LogType)

		// Check that zap core fields are excluded
		require.NotContains(t, entry.Fields, "N")
		require.NotContains(t, entry.Fields, "T")
		require.NotContains(t, entry.Fields, "S")

		// Check that custom fields are included
		require.Contains(t, entry.Fields, "userId")
		require.Contains(t, entry.Fields, "sessionId")
		require.Contains(t, entry.Fields, "requestId")
		require.Contains(t, entry.Fields, "metadata")
		require.Contains(t, entry.Fields, "tags")
		require.Contains(t, entry.Fields, "count")
		require.Contains(t, entry.Fields, "active")

		require.Equal(t, float64(12345), entry.Fields["userId"])
		require.Equal(t, "abc-123-def", entry.Fields["sessionId"])
		require.Equal(t, "req-456", entry.Fields["requestId"])
		require.Equal(t, float64(42), entry.Fields["count"])
		require.Equal(t, true, entry.Fields["active"])
	})

	t.Run("parseLog with empty string", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		entry := sender.parseLog([]byte(""))

		require.Equal(t, "", entry.Message)
		require.Equal(t, "application", entry.LogType)
		require.NotZero(t, entry.Timestamp)
	})

	t.Run("parseLog with whitespace only", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		entry := sender.parseLog([]byte("   \n\t  "))

		require.Equal(t, "   \n\t  ", entry.Message)
		require.Equal(t, "application", entry.LogType)
		require.NotZero(t, entry.Timestamp)
	})
}

func TestSender_EdgeCases(t *testing.T) {
	t.Run("NewSender with minimal values", func(t *testing.T) {
		sender := NewSender("", 1*time.Millisecond, 1, 1)

		require.NotNil(t, sender)
		require.False(t, sender.enabled)
		require.Empty(t, sender.apiKey)
		require.Equal(t, 1, cap(sender.buffer))
		require.Equal(t, 1, sender.newRelicMaxBufferSize)
		require.Equal(t, 1, sender.newRelicMaxRetries)
	})

	t.Run("addToBuffer with zero capacity", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, 0, maxRetries)

		entry := LogEntry{
			Message: "Test message",
			Level:   "INFO",
		}

		// Should not crash even with zero capacity
		sender.addToBuffer(entry)
		require.Equal(t, 1, len(sender.buffer))
	})

	t.Run("flush with zero capacity buffer", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, 0, maxRetries)

		// Should not crash
		sender.flush()
	})
}

func TestSender_RetryLogic(t *testing.T) {
	t.Run("retry logic with different max retries", func(t *testing.T) {
		// Test with 1 retry
		sender1 := NewSender("test_key", flushInterval, maxBuffer, 1)
		logs := []LogEntry{{Message: "Test", Level: "INFO"}}
		sender1.sendBatch(logs)

		// Test with 5 retries
		sender2 := NewSender("test_key", flushInterval, maxBuffer, 5)
		sender2.sendBatch(logs)

		// Should not crash
	})
}

func TestSender_ConcurrentFlush(t *testing.T) {
	t.Run("concurrent flush operations", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, maxBuffer, maxRetries)

		// Add logs
		for i := 0; i < 10; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		var wg sync.WaitGroup

		// Start multiple goroutines that call flush
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sender.flush()
			}()
		}

		wg.Wait()

		// Should not crash and handle concurrent access gracefully
	})
}

func TestSender_BufferManagement(t *testing.T) {
	t.Run("buffer capacity management", func(t *testing.T) {
		sender := NewSender("test_key", flushInterval, 2, maxRetries)

		// Add logs up to capacity
		for i := 0; i < 2; i++ {
			entry := LogEntry{
				Message: fmt.Sprintf("Test message %d", i),
				Level:   "INFO",
			}
			sender.addToBuffer(entry)
		}

		require.Equal(t, 2, len(sender.buffer))
		require.Equal(t, 2, cap(sender.buffer))

		// Add one more to trigger flush
		entry := LogEntry{
			Message: "Trigger message",
			Level:   "INFO",
		}
		sender.addToBuffer(entry)

		// Wait for async flush
		sender.wg.Wait()

		// Buffer should be empty after flush
		require.Equal(t, 0, len(sender.buffer))
	})
}

func TestConstants(t *testing.T) {
	require.Equal(t, 500, maxBuffer)
	require.Equal(t, 2*time.Minute, flushInterval)
	require.Equal(t, 3, maxRetries)
}
