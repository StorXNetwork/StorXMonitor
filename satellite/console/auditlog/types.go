// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package auditlog

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/StorXNetwork/common/uuid"
)

type Status string

const (
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

type Event struct {
	ActorID   string
	Action    string
	Resource  string
	Message   string
	IPAddress string
	Status    Status
}

type ActorDisplay struct {
	Name  string
	Email string
}

func ApplyActorDisplay(records []Record, display ActorDisplay) {
	name := display.Name
	if name == "" {
		name = display.Email
	}
	for i := range records {
		records[i].ActorName = name
		records[i].ActorEmail = display.Email
	}
}

type Record struct {
	ID         uuid.UUID `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ActorID    string    `json:"actor_id,omitempty"`
	ActorName  string    `json:"actor"`
	ActorEmail string    `json:"actor_email,omitempty"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	Message    string    `json:"message"`
	IPAddress  string    `json:"ip_address"`
	Status     Status    `json:"status"`
}

type ListParams struct {
	ActorID string
	Action  string
	Status  string
	Search  string
	From    *time.Time
	To      *time.Time
	Limit   int
	Cursor  string
}

type ListResult struct {
	Items      []Record
	NextCursor string
	TotalCount int
}

type Config struct {
	WorkerCount     int `help:"number of async audit log workers" default:"4"`
	ChannelCapacity int `help:"audit log async channel capacity" default:"1000"`
	RetentionDays   int `help:"days to retain audit logs" default:"180"`
	MaxExportDays   int `help:"max date range for CSV export in days" default:"90"`
	MaxExportRows   int `help:"max rows per CSV export" default:"100000"`
}

func (c *Config) RegisterFlags(fs *pflag.FlagSet) {
	fs.IntVar(&c.WorkerCount, "audit-log-worker-count", c.WorkerCount, "number of async audit log workers")
	fs.IntVar(&c.ChannelCapacity, "audit-log-channel-capacity", c.ChannelCapacity, "audit log async channel capacity")
	fs.IntVar(&c.RetentionDays, "audit-retention-days", c.RetentionDays, "days to retain audit logs")
	fs.IntVar(&c.MaxExportDays, "audit-max-export-days", c.MaxExportDays, "max date range for CSV export in days")
	fs.IntVar(&c.MaxExportRows, "audit-max-export-rows", c.MaxExportRows, "max rows per CSV export")
}
