// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zeebo/errs"
)

// Mail export job status values (gateway-mt contract).
const (
	MailExportStatusQueued     = "QUEUED"
	MailExportStatusProcessing = "PROCESSING"
	MailExportStatusSucceeded  = "SUCCEEDED"
	MailExportStatusFailed     = "FAILED"
	MailExportStatusExpired    = "EXPIRED"
	MailExportStatusCancelled  = "CANCELLED"
)

// ErrMailExportJobNotFound is returned when a mail export job is missing.
var ErrMailExportJobNotFound = errs.Class("mail export job not found")

// MailExportJob is a Satellite mail_export_jobs row (no download_url).
type MailExportJob struct {
	ID             string          `json:"id"`
	UserID         string          `json:"userId"`
	ProjectID      string          `json:"projectId"`
	AccessKeyID    string          `json:"accessKeyId"`
	Bucket         string          `json:"bucket"`
	Format         string          `json:"format"`
	Mode           string          `json:"mode"`
	Prefix         string          `json:"prefix,omitempty"`
	Keys           []string        `json:"keys,omitempty"`
	KeysJSON       json.RawMessage `json:"keysJson,omitempty"`
	AccessGrant    string          `json:"accessGrant,omitempty"`
	Status         string          `json:"status"`
	RetryCount     int             `json:"retryCount"`
	Progress       int             `json:"progress"`
	ProcessedFiles int64           `json:"processedFiles"`
	TotalFiles     int64           `json:"totalFiles"`
	ProcessedBytes int64           `json:"processedBytes"`
	TotalBytes     int64           `json:"totalBytes"`
	CurrentObject  string          `json:"currentObject,omitempty"`
	ArchiveBucket  string          `json:"archiveBucket,omitempty"`
	ArchiveKey     string          `json:"archiveKey,omitempty"`
	ArchiveName              string          `json:"archiveName,omitempty"`
	ErrorMessage             string          `json:"errorMessage,omitempty"`
	LastDownloadChargeID     string          `json:"lastDownloadChargeId,omitempty"`
	LastDownloadChargedBytes *int64          `json:"lastDownloadChargedBytes,omitempty"`
	CreatedAt                time.Time       `json:"createdAt"`
	StartedAt                *time.Time      `json:"startedAt,omitempty"`
	CompletedAt              *time.Time      `json:"completedAt,omitempty"`
	ExpiresAt                *time.Time      `json:"expiresAt,omitempty"`
}

// CreateMailExportJob holds fields for inserting a QUEUED job.
type CreateMailExportJob struct {
	ID          string
	UserID      string
	ProjectID   string
	AccessKeyID string
	Bucket      string
	Format      string
	Mode        string
	Prefix      string
	Keys        []string
	TotalFiles  int64
	TotalBytes  int64
	AccessGrant string
}

// PatchMailExportJob holds optional fields for updating a job.
type PatchMailExportJob struct {
	Status         *string
	RetryCount     *int
	Progress       *int
	ProcessedFiles *int64
	TotalFiles     *int64
	ProcessedBytes *int64
	TotalBytes     *int64
	CurrentObject  *string
	ArchiveBucket  *string
	ArchiveKey     *string
	ArchiveName              *string
	ErrorMessage             *string
	LastDownloadChargeID     *string
	LastDownloadChargedBytes *int64
	StartedAt                *time.Time
	CompletedAt              *time.Time
	ExpiresAt                *time.Time
}

// MailExportJobs is the repository for mail export jobs.
type MailExportJobs interface {
	Create(ctx context.Context, job CreateMailExportJob) (*MailExportJob, error)
	Get(ctx context.Context, id string) (*MailExportJob, error)
	Claim(ctx context.Context) (*MailExportJob, error)
	Patch(ctx context.Context, id string, patch PatchMailExportJob) (*MailExportJob, error)
	Cancel(ctx context.Context, id string) (*MailExportJob, error)
	Expire(ctx context.Context) ([]MailExportJob, error)
	RequeueStale(ctx context.Context, olderThan time.Duration) (int, error)
}
