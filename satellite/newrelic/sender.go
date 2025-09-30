// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package newrelic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	LogType   string                 `json:"logtype"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

func NewSender(apiKey string, newRelicTimeInterval time.Duration, newRelicMaxBufferSize int, newRelicMaxRetries int) *Sender {
	s := &Sender{
		apiKey:                apiKey,
		enabled:               apiKey != "", // true if apiKey is not empty
		url:                   "https://log-api.newrelic.com/log/v1",
		client:                &http.Client{Timeout: 30 * time.Second},
		buffer:                make([]LogEntry, 0, newRelicMaxBufferSize),
		shutdown:              make(chan struct{}),
		newRelicTimeInterval:  newRelicTimeInterval,
		newRelicMaxBufferSize: newRelicMaxBufferSize,
		newRelicMaxRetries:    newRelicMaxRetries,
	}
	s.ticker = time.NewTicker(newRelicTimeInterval)
	go s.flushLoop()
	return s
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
		return LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Message:   string(data),
			LogType:   "application",
		}
	}

	entry := LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Message:   s.getStringValue(logData["M"]),
		Level:     s.getStringValue(logData["L"]),
		Caller:    s.getStringValue(logData["C"]),
		LogType:   "application",
		Fields:    make(map[string]interface{}),
	}

	// Add extra fields (excluding zap core fields)
	for k, v := range logData {
		if k != "M" && k != "L" && k != "C" && k != "N" && k != "T" && k != "S" {
			entry.Fields[k] = v
		}
	}

	return entry
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
	defer s.mu.Unlock()

	s.buffer = append(s.buffer, entry)

	if len(s.buffer) >= s.newRelicMaxBufferSize {
		s.wg.Add(1)
		go s.flushAsync()
	}
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

func (s *Sender) flushAsync() {
	defer s.wg.Done()
	s.flush()
}

func (s *Sender) sendBatch(logs []LogEntry) {
	payload, err := json.Marshal(logs)
	if err != nil {
		return
	}

	for attempt := 1; attempt <= s.newRelicMaxRetries; attempt++ {

		req, err := http.NewRequest("POST", s.url, bytes.NewReader(payload))
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}

		req.Header.Set("Api-Key", s.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}

		if resp.StatusCode == 403 {
			return // Auth error, no retry
		}

		time.Sleep(time.Second * time.Duration(attempt))
	}

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
