// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package newrelic

import (
	"encoding/json"
	"strings"

	"go.uber.org/zap/zapcore"
)

// LogInterceptor intercepts zap logs and sends them to New Relic
type LogInterceptor struct {
	sender *Sender
}

// NewLogInterceptor creates a new LogInterceptor
func NewLogInterceptor(apiKey string, enabled bool) *LogInterceptor {
	return &LogInterceptor{sender: NewSender(apiKey, enabled)}
}

// InterceptLog intercepts a log entry and sends it to New Relic
func (li *LogInterceptor) InterceptLog(entry zapcore.Entry) {
	parsedEntry, jsonFields := li.parseLog(entry)

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

	// Send JSON payload
	if jsonData, err := json.Marshal(logData); err == nil {
		li.sender.SendLog(jsonData)
	}
	// Silently ignore JSON marshal errors
}

// parseLog parses Storj's structured log format: LEVEL\tLOGGER\tCALLER\tMESSAGE\t{JSON}
func (li *LogInterceptor) parseLog(entry zapcore.Entry) (zapcore.Entry, map[string]interface{}) {
	parts := strings.Split(entry.Message, "\t")
	if len(parts) < 4 {
		return entry, make(map[string]interface{})
	}

	level := li.parseLevel(parts[0])
	_, caller, message := parts[1], parts[2], parts[3]

	// Parse optional JSON fields
	jsonFields := make(map[string]interface{})
	if len(parts) > 4 {
		jsonStr := strings.Join(parts[4:], "\t")
		_ = json.Unmarshal([]byte(jsonStr), &jsonFields) // ignore errors safely
	}

	entryCaller := zapcore.NewEntryCaller(0, caller, 0, caller != "")

	return zapcore.Entry{
		Level:      level,
		Time:       entry.Time,
		Message:    message,
		Caller:     entryCaller,
		LoggerName: entry.LoggerName, // Keep the original process name from newRelicWriter
		Stack:      entry.Stack,
	}, jsonFields
}

// parseLevel converts a string log level to zapcore.Level
func (li *LogInterceptor) parseLevel(levelStr string) zapcore.Level {
	l := strings.ToUpper(levelStr)
	switch {
	case strings.Contains(l, "ERROR"), strings.Contains(l, "ERR"):
		return zapcore.ErrorLevel
	case strings.Contains(l, "WARN"):
		return zapcore.WarnLevel
	case strings.Contains(l, "DEBUG"):
		return zapcore.DebugLevel
	default:
		return zapcore.InfoLevel
	}
}

// Close closes the interceptor and flushes remaining logs
func (li *LogInterceptor) Close() {
	li.sender.Close()
}
