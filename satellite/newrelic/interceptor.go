// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package newrelic

import (
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

// LogInterceptor intercepts zap logs and sends them to New Relic
type LogInterceptor struct {
	sender   *Sender
	logLevel zapcore.Level
}

// NewLogInterceptor creates a new LogInterceptor with log level filtering
func NewLogInterceptor(apiKey string, enabled bool, logLevel string, newRelicTimeInterval time.Duration, newRelicMaxBufferSize int, newRelicMaxRetries int) *LogInterceptor {
	return &LogInterceptor{
		sender:   NewSender(apiKey, enabled, newRelicTimeInterval, newRelicMaxBufferSize, newRelicMaxRetries),
		logLevel: parseLogLevel(logLevel),
	}
}

// InterceptLog intercepts a log entry and sends it to New Relic
func (li *LogInterceptor) InterceptLog(entry zapcore.Entry) {
	parsedEntry, jsonFields := li.parseLog(entry)

	// Check if this log level should be sent to New Relic
	if parsedEntry.Level < li.logLevel {
		return
	}

	// Create structured log data
	logData := map[string]interface{}{
		"L":       parsedEntry.Level.String(),
		"M":       parsedEntry.Message,
		"C":       parsedEntry.Caller.String(),
		"N":       parsedEntry.LoggerName,
		"T":       parsedEntry.Time.Format("2006-01-02T15:04:05.000Z0700"),
		"S":       parsedEntry.Stack,
		"process": parsedEntry.LoggerName,
	}

	// Add parsed JSON fields
	for key, value := range jsonFields {
		logData[key] = value
	}

	// Send to New Relic
	if jsonData, err := json.Marshal(logData); err == nil {
		li.sender.SendLog(jsonData)
	}
}

// parseLog parses Storj's structured log format: LEVEL\tLOGGER\tCALLER\tMESSAGE\t{JSON}
func (li *LogInterceptor) parseLog(entry zapcore.Entry) (zapcore.Entry, map[string]interface{}) {
	parts := strings.Split(entry.Message, "\t")
	if len(parts) < 4 {
		return entry, make(map[string]interface{})
	}

	// Parse log components
	level := parseLogLevel(parts[0])
	_, caller, message := parts[1], parts[2], parts[3]

	// Parse optional JSON fields
	jsonFields := make(map[string]interface{})
	if len(parts) > 4 {
		jsonStr := strings.Join(parts[4:], "\t")
		_ = json.Unmarshal([]byte(jsonStr), &jsonFields)
	}

	return zapcore.Entry{
		Level:      level,
		Time:       entry.Time,
		Message:    message,
		Caller:     zapcore.NewEntryCaller(0, caller, 0, caller != ""),
		LoggerName: entry.LoggerName,
		Stack:      entry.Stack,
	}, jsonFields
}

// parseLogLevel converts a string log level to zapcore.Level
func parseLogLevel(logLevel string) zapcore.Level {
	switch strings.ToLower(logLevel) {
	case "error":
		return zapcore.ErrorLevel
	case "warn":
		return zapcore.WarnLevel
	case "info":
		return zapcore.InfoLevel
	case "debug", "trace":
		return zapcore.DebugLevel
	default:
		return zapcore.DebugLevel
	}
}

// Close closes the interceptor and flushes remaining logs
func (li *LogInterceptor) Close() {
	li.sender.Close()
}
