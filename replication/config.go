// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

// TableConfig holds configuration for a specific table to replicate.
type TableConfig struct {
	Table      string   `yaml:"table" json:"table"`
	Events     []string `yaml:"events" json:"events"`
	WebhookURL string   `yaml:"webhook_url" json:"webhook_url"`
}

type TableConfigs []TableConfig

var _ pflag.Value = (*TableConfigs)(nil)

func (TableConfigs) Type() string { return "replication.TableConfigs" }

func (tc *TableConfigs) String() string {
	if tc == nil || len(*tc) == 0 {
		return ""
	}
	configs, err := json.Marshal(*tc)
	if err != nil {
		return ""
	}
	return string(configs)
}

func (tc *TableConfigs) Set(s string) error {
	if s == "" {
		*tc = nil
		return nil
	}
	configs := make([]TableConfig, 0)
	err := json.Unmarshal([]byte(s), &configs)
	if err != nil {
		return err
	}
	*tc = configs
	return nil
}

// Config holds configuration for the replication service.
type Config struct {
	SourceDB string `help:"PostgreSQL connection string for replication (optional, uses main database if not set)"`

	SlotName string `help:"name of the replication slot" default:"backuptools_slot"`

	PublicationName string `help:"name of the publication" default:"backuptools_pub"`

	WebhookURL string `help:"default webhook endpoint URL in Backuptools"`

	WebhookPublicKey string `help:"path to RSA public key file for encrypting webhook payloads"`

	Tables TableConfigs `help:"table configurations in JSON format: [{\"table\":\"\",\"events\":[\"\"],\"webhook_url\":\"\"},...]"`

	MaxRetries int `help:"maximum number of retry attempts for failed webhooks" default:"3"`

	RetryDelay time.Duration `help:"initial delay between retry attempts" default:"5s"`

	StatusUpdateInterval time.Duration `help:"interval for sending standby status updates" default:"10s"`

	WebhookTimeout time.Duration `help:"timeout for webhook HTTP requests" default:"30s"`

	WorkerPoolSize int `help:"number of worker goroutines for processing webhooks" default:"10"`

	EventChannelBuffer int `help:"buffer size for event channel (backpressure control)" default:"1000"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.SlotName == "" {
		return ErrInvalidConfig.New("SlotName is required")
	}
	if c.PublicationName == "" {
		return ErrInvalidConfig.New("PublicationName is required")
	}
	if c.WebhookPublicKey == "" {
		return ErrInvalidConfig.New("WebhookPublicKey is required")
	}

	validEvents := map[string]bool{
		"INSERT": true,
		"UPDATE": true,
		"DELETE": true,
	}

	tableNames := make(map[string]bool)
	for i, table := range c.Tables {
		if table.Table == "" {
			return ErrInvalidConfig.New("table name is required for table config at index %d", i)
		}

		if tableNames[table.Table] {
			return ErrInvalidConfig.New("duplicate table name: %s", table.Table)
		}
		tableNames[table.Table] = true

		for _, event := range table.Events {
			eventUpper := strings.ToUpper(event)
			if !validEvents[eventUpper] {
				return ErrInvalidConfig.New("invalid event '%s' for table '%s'. Valid events: INSERT, UPDATE, DELETE", event, table.Table)
			}
		}

		if table.WebhookURL == "" && c.WebhookURL == "" {
			return ErrInvalidConfig.New("WebhookURL is required (either default or for table '%s')", table.Table)
		}
	}

	if len(c.Tables) == 0 && c.WebhookURL == "" {
		return ErrInvalidConfig.New("WebhookURL is required when no tables are configured")
	}
	if c.MaxRetries < 0 {
		return ErrInvalidConfig.New("MaxRetries must be non-negative")
	}
	if c.RetryDelay < 0 {
		return ErrInvalidConfig.New("RetryDelay must be non-negative")
	}
	if c.StatusUpdateInterval < 0 {
		return ErrInvalidConfig.New("StatusUpdateInterval must be non-negative")
	}
	if c.WebhookTimeout < 0 {
		return ErrInvalidConfig.New("WebhookTimeout must be non-negative")
	}
	if c.WorkerPoolSize < 1 {
		return ErrInvalidConfig.New("WorkerPoolSize must be at least 1")
	}
	if c.EventChannelBuffer < 1 {
		return ErrInvalidConfig.New("EventChannelBuffer must be at least 1")
	}
	return nil
}

// GetTableNames returns a list of all table names configured for replication.
func (c *Config) GetTableNames() []string {
	if len(c.Tables) == 0 {
		return nil
	}
	names := make([]string, len(c.Tables))
	for i, table := range c.Tables {
		names[i] = table.Table
	}
	return names
}

// GetTableConfig returns the configuration for a specific table, or nil if not found.
func (c *Config) GetTableConfig(tableName string) *TableConfig {
	for i := range c.Tables {
		if c.Tables[i].Table == tableName {
			return &c.Tables[i]
		}
	}
	return nil
}

// ShouldReplicateEvent checks if an event should be replicated for a given table.
func (c *Config) ShouldReplicateEvent(tableName, operation string) bool {
	tableConfig := c.GetTableConfig(tableName)
	if tableConfig == nil {
		return true
	}

	if len(tableConfig.Events) == 0 {
		return true
	}

	operationUpper := strings.ToUpper(operation)
	for _, event := range tableConfig.Events {
		if strings.ToUpper(event) == operationUpper {
			return true
		}
	}

	return false
}

// GetWebhookURL returns the webhook URL for a specific table.
func (c *Config) GetWebhookURL(tableName string) string {
	tableConfig := c.GetTableConfig(tableName)
	if tableConfig != nil && tableConfig.WebhookURL != "" {
		return tableConfig.WebhookURL
	}
	return c.WebhookURL
}
