// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package newrelic

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

// LogInterceptor intercepts zap logs and sends them to New Relic
type LogInterceptor struct {
	sender   *Sender
	logLevel zapcore.Level
}

// parseLogLevelString parses a log level string to zapcore.Level
// Handles common variations: "debug", "DEBUG", "info", "INFO", "warn", "WARN", "error", "ERROR"
// Defaults to InfoLevel if parsing fails (safer than DebugLevel)
func parseLogLevelString(levelStr string) zapcore.Level {
	levelStr = strings.ToLower(strings.TrimSpace(levelStr))
	switch levelStr {
	case "panic", "fatal":
		return zapcore.PanicLevel
	case "error":
		return zapcore.ErrorLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "info":
		return zapcore.InfoLevel
	case "debug", "trace":
		return zapcore.DebugLevel
	default:
		// Default to InfoLevel for safety (blocks DEBUG logs from New Relic)
		return zapcore.InfoLevel
	}
}

// NewLogInterceptor creates a new LogInterceptor with log level filtering.
// Recommended log level: "info" or higher to minimize New Relic storage consumption.
// If logLevel is empty or invalid, defaults to InfoLevel (blocks DEBUG logs).
func NewLogInterceptor(apiKey string, logLevel string, newRelicTimeInterval time.Duration, newRelicMaxBufferSize int, newRelicMaxRetries int) *LogInterceptor {
	parsedLevel := parseLogLevelString(logLevel)
	return &LogInterceptor{
		sender:   NewSender(apiKey, newRelicTimeInterval, newRelicMaxBufferSize, newRelicMaxRetries),
		logLevel: parsedLevel,
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
	jsonData, err := json.Marshal(logData)
	if err != nil {
		log.Printf("[New Relic] Error marshaling log entry to JSON: %v. Message: %s", err, parsedEntry.Message)
		return
	}
	li.sender.SendLog(jsonData)
}

// parseLog parses Storj's structured log format: LEVEL\tLOGGER\tCALLER\tMESSAGE\t{JSON}
func (li *LogInterceptor) parseLog(entry zapcore.Entry) (zapcore.Entry, map[string]interface{}) {
	parts := strings.Split(entry.Message, "\t")
	if len(parts) < 4 {
		return entry, make(map[string]interface{})
	}

	// Parse log components
	loggerName, caller, message := parts[1], parts[2], parts[3]

	// Parse optional JSON fields
	jsonFields := make(map[string]interface{})
	if len(parts) > 4 {
		jsonStr := strings.Join(parts[4:], "\t")
		_ = json.Unmarshal([]byte(jsonStr), &jsonFields)
	}

	return zapcore.Entry{
		Level:      entry.Level,
		Time:       entry.Time,
		Message:    message,
		Caller:     zapcore.NewEntryCaller(0, caller, 0, caller != ""),
		LoggerName: loggerName,
		Stack:      entry.Stack,
	}, jsonFields
}

// Close closes the interceptor and flushes remaining logs
func (li *LogInterceptor) Close() {
	li.sender.Close()
}
