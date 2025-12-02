// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package newrelic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Sender struct {
	apiKey                string
	enabled               bool // true if apiKey is not empty
	url                   string
	client                *http.Client
	buffer                []LogEntry
	mu                    sync.Mutex
	flushing              bool      // prevents concurrent flush operations
	lastAuthError         time.Time // track last auth error to avoid spam
	ticker                *time.Ticker
	shutdown              chan struct{}
	wg                    sync.WaitGroup
	newRelicTimeInterval  time.Duration
	newRelicMaxBufferSize int
	newRelicMaxRetries    int
}

type LogEntry struct {
	Timestamp int64                  `json:"timestamp"`
	Message   string                 `json:"message"`
	Level     string                 `json:"level,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
	Stack     string                 `json:"stack,omitempty"`
	LogType   string                 `json:"logtype"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

func NewSender(apiKey string, newRelicTimeInterval time.Duration, newRelicMaxBufferSize int, newRelicMaxRetries int) *Sender {
	// Validate API key format
	enabled := apiKey != ""
	if enabled && !isValidAPIKey(apiKey) {
		log.Printf("[New Relic] Warning: API key format may be invalid. Expected USER key (starts with 'NRAK-') or INGEST key. Got: %s...", maskAPIKey(apiKey))
	}

	s := &Sender{
		apiKey:                apiKey,
		enabled:               enabled,
		url:                   "https://log-api.newrelic.com/log/v1",
		client:                &http.Client{Timeout: 30 * time.Second},
		buffer:                make([]LogEntry, 0, newRelicMaxBufferSize),
		flushing:              false,
		shutdown:              make(chan struct{}),
		newRelicTimeInterval:  newRelicTimeInterval,
		newRelicMaxBufferSize: newRelicMaxBufferSize,
		newRelicMaxRetries:    newRelicMaxRetries,
	}
	s.ticker = time.NewTicker(newRelicTimeInterval)
	go s.flushLoop()
	return s
}

// isValidAPIKey validates the API key format
// USER keys start with "NRAK-", INGEST keys are typically hex strings
func isValidAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}
	// Check for USER key format (NRAK-...)
	if strings.HasPrefix(apiKey, "NRAK-") {
		return true
	}
	// Check for INGEST key format (hex string, typically 32+ chars)
	if len(apiKey) >= 32 {
		return true
	}
	return false
}

// maskAPIKey masks the API key for logging (shows first 8 chars)
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "****"
	}
	return apiKey[:8] + "****"
}

func (s *Sender) SendLog(data []byte) {
	if !s.enabled {
		fmt.Println("New Relic is disabled")
		return
	}

	entry := s.parseLog(data)
	s.addToBuffer(entry)
}

func (s *Sender) parseLog(data []byte) LogEntry {
	var logData map[string]interface{}
	if err := json.Unmarshal(data, &logData); err != nil {
		// Fix: When JSON unmarshal fails, logData is nil, so we can't access logData["T"]
		// Return early with proper fallback
		return LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Message:   string(data),
			LogType:   "application",
		}
	}

	entry := LogEntry{
		Timestamp: s.getTimestamp(logData["T"]),
		Message:   s.getStringValue(logData["M"]),
		Level:     s.getStringValue(logData["L"]),
		Caller:    s.getStringValue(logData["C"]),
		LogType:   "application",
		Fields:    make(map[string]interface{}),
		Stack:     s.getStringValue(logData["S"]),
	}

	// Add extra fields (excluding zap core fields)
	for k, v := range logData {
		if k != "M" && k != "L" && k != "C" && k != "N" && k != "T" && k != "S" {
			entry.Fields[k] = v
		}
	}

	return entry
}

func (s *Sender) getTimestamp(v interface{}) int64 {
	if v == nil {
		return time.Now().UnixMilli()
	}

	// Try to parse as time string first
	if str, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339, str); err == nil {
			return t.UnixMilli()
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", str); err == nil {
			return t.UnixMilli()
		}
	}

	// Try to convert to int64
	if timestamp, ok := v.(int64); ok {
		return timestamp
	}
	if timestamp, ok := v.(float64); ok {
		return int64(timestamp)
	}

	// Fallback to current time
	return time.Now().UnixMilli()
}

// getStringValue safely converts interface{} to string
func (s *Sender) getStringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", v)
}

func (s *Sender) addToBuffer(entry LogEntry) {
	s.mu.Lock()
	bufferFull := len(s.buffer) >= s.newRelicMaxBufferSize
	if bufferFull && !s.flushing {
		s.flushing = true
		s.wg.Add(1)
		go s.flushAsync()
	}
	s.buffer = append(s.buffer, entry)
	s.mu.Unlock()
}

func (s *Sender) flushLoop() {
	for {
		select {
		case <-s.ticker.C:
			s.flush()
		case <-s.shutdown:
			return
		}
	}
}

func (s *Sender) flush() {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}

	logs := make([]LogEntry, len(s.buffer))
	copy(logs, s.buffer)
	s.buffer = s.buffer[:0]
	s.mu.Unlock()

	s.sendBatch(logs)
}

// Flush manually flushes the buffer (public method for testing/manual flushing)
func (s *Sender) Flush() {
	s.mu.Lock()
	if s.flushing {
		s.mu.Unlock()
		return // Already flushing
	}
	s.flushing = true
	s.mu.Unlock()

	s.flush()

	s.mu.Lock()
	s.flushing = false
	s.mu.Unlock()
}

func (s *Sender) flushAsync() {
	defer func() {
		s.mu.Lock()
		s.flushing = false
		s.mu.Unlock()
		s.wg.Done()
	}()
	s.flush()
}

func (s *Sender) sendBatch(logs []LogEntry) {
	if len(logs) == 0 {
		return
	}

	payload, err := json.Marshal(logs)
	if err != nil {
		log.Printf("[New Relic] Error marshaling logs to JSON: %v", err)
		return
	}

	for attempt := 1; attempt <= s.newRelicMaxRetries; attempt++ {
		req, err := http.NewRequest("POST", s.url, bytes.NewReader(payload))
		if err != nil {
			log.Printf("[New Relic] Error creating HTTP request (attempt %d/%d): %v", attempt, s.newRelicMaxRetries, err)
			if attempt < s.newRelicMaxRetries {
				time.Sleep(time.Second * time.Duration(attempt))
				continue
			}
			return
		}

		req.Header.Set("Api-Key", s.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			log.Printf("[New Relic] Error sending logs to New Relic (attempt %d/%d): %v", attempt, s.newRelicMaxRetries, err)
			if attempt < s.newRelicMaxRetries {
				time.Sleep(time.Second * time.Duration(attempt))
				continue
			}
			return
		}

		// Read response body for error details
		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if attempt > 1 {
				log.Printf("[New Relic] Successfully sent %d logs to New Relic after %d attempts", len(logs), attempt)
			}
			return
		}

		// Handle error responses
		errorMsg := "unknown error"
		if readErr == nil && len(bodyBytes) > 0 {
			errorMsg = string(bodyBytes)
			// Limit error message length
			if len(errorMsg) > 500 {
				errorMsg = errorMsg[:500] + "..."
			}
		}

		if resp.StatusCode == 403 {
			// Rate limit auth error messages to avoid spam (log at most once per minute)
			s.mu.Lock()
			shouldLog := time.Since(s.lastAuthError) > time.Minute
			if shouldLog {
				s.lastAuthError = time.Now()
			}
			s.mu.Unlock()

			if shouldLog {
				errorDetails := errorMsg
				if errorMsg == "unknown error" || errorMsg == "{}" {
					errorDetails = "empty response body"
				}
				log.Printf("[New Relic] Authentication error (403): %s", errorDetails)
				log.Printf("[New Relic] Possible causes:")
				log.Printf("[New Relic]   1. API key is invalid or expired")
				log.Printf("[New Relic]   2. API key doesn't have Log API permissions")
				log.Printf("[New Relic]   3. Account doesn't have Log API feature enabled")
				log.Printf("[New Relic]   4. API key type mismatch (using INGEST key instead of USER key)")
				log.Printf("[New Relic] Please verify your API key in New Relic dashboard. Logs will not be sent until fixed.")
			}
			return // Auth error, no retry
		}

		if resp.StatusCode == 404 {
			// Rate limit 404 error messages to avoid spam (log at most once per minute)
			s.mu.Lock()
			shouldLog := time.Since(s.lastAuthError) > time.Minute
			if shouldLog {
				s.lastAuthError = time.Now()
			}
			s.mu.Unlock()

			if shouldLog {
				errorDetails := errorMsg
				if errorMsg == "unknown error" || errorMsg == "{}" {
					errorDetails = "endpoint not found"
				}
				log.Printf("[New Relic] Endpoint not found (404): %s", errorDetails)
				log.Printf("[New Relic] Endpoint URL: %s", s.url)
				log.Printf("[New Relic] Possible causes:")
				log.Printf("[New Relic]   1. Incorrect API endpoint URL")
				log.Printf("[New Relic]   2. API endpoint structure has changed")
				log.Printf("[New Relic]   3. Account/region-specific endpoint required")
				log.Printf("[New Relic]   4. API key doesn't have access to Log API")
				log.Printf("[New Relic] Please verify the endpoint URL and API key permissions.")
			}
			return // Endpoint error, no retry
		}

		log.Printf("[New Relic] HTTP error %d (attempt %d/%d): %s", resp.StatusCode, attempt, s.newRelicMaxRetries, errorMsg)

		if attempt < s.newRelicMaxRetries {
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}

	log.Printf("[New Relic] Failed to send %d logs to New Relic after %d attempts", len(logs), s.newRelicMaxRetries)
}

func (s *Sender) Close() {
	s.ticker.Stop()
	close(s.shutdown)
	s.wg.Wait()

	// Flush remaining logs
	s.mu.Lock()
	if len(s.buffer) > 0 {
		logs := make([]LogEntry, len(s.buffer))
		copy(logs, s.buffer)
		s.mu.Unlock()
		s.sendBatch(logs)
	} else {
		s.mu.Unlock()
	}
}
