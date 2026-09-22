// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

var (
	// ErrExternalS3NotFound is used when no external S3 backend row exists.
	ErrExternalS3NotFound = errs.Class("external s3 backend not found")
	// ErrExternalS3Invalid is used for invalid external S3 backend input.
	ErrExternalS3Invalid = errs.Class("external s3 backend invalid")
	// ErrExternalS3NeedsReauth is used when legacy rows lack encrypted source secret.
	ErrExternalS3NeedsReauth = errs.Class("external s3 needs reauth")
)

// External S3 backend status values.
const (
	ExternalS3StatusActive       = "active"
	ExternalS3StatusNeedsReauth  = "needs_reauth"
	ExternalS3StatusDisabled     = "disabled"

	// externalS3LocalKeyID marks secrets encrypted with AuthTokenSecret-derived key (no KMS).
	externalS3LocalKeyID = 0
)

// ExternalS3Backends is the repository for per-user external S3 app credentials.
//
// architecture: Database
type ExternalS3Backends interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*ExternalS3Backend, error)
	Upsert(ctx context.Context, backend *ExternalS3Backend) error
	Delete(ctx context.Context, userID uuid.UUID) error
}

// ExternalS3Backend stores the user's S3-compatible app credentials (encrypted)
// plus a rebuildable gateway key cache. No storage "mode" — own-nodes stays separate.
type ExternalS3Backend struct {
	UserID uuid.UUID `json:"userId"`
	Status string    `json:"status"`

	Endpoint    string `json:"endpoint"`
	Region      string `json:"region"`
	AccessKeyID string `json:"accessKeyId"`

	SecretEnc   []byte `json:"-"`
	SecretKeyID int    `json:"-"`

	GatewayAccessKeyID  string `json:"gatewayAccessKeyId,omitempty"`
	GatewaySecretEnc    []byte `json:"-"`
	GatewaySecretKeyID  int    `json:"-"`
	GatewayEndpoint     string `json:"gatewayEndpoint,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// UpsertExternalS3Request is the body for PUT /external-s3 (raw app credentials once).
type UpsertExternalS3Request struct {
	Endpoint    string `json:"endpoint"`
	AccessKeyID string `json:"access_key_id"`
	SecretKey   string `json:"secret_key"`
	Region      string `json:"region"`
}

// ExternalS3Response is returned to the owner UI (no secrets).
type ExternalS3Response struct {
	Enabled             bool   `json:"enabled"`
	Status              string `json:"status,omitempty"`
	Endpoint            string `json:"endpoint,omitempty"`
	Region              string `json:"region,omitempty"`
	AccessKeyID         string `json:"access_key_id,omitempty"`
	GatewayAccessKeyID  string `json:"gateway_access_key_id,omitempty"`
	GatewayEndpoint     string `json:"gateway_endpoint,omitempty"`
	// GatewaySecretKey is returned only from ensure/register so vault can unlock.
	GatewaySecretKey string `json:"gateway_secret_key,omitempty"`
}

// NormalizeExternalS3Region maps empty/global/auto to us-east-1.
func NormalizeExternalS3Region(region string) string {
	r := strings.TrimSpace(strings.ToLower(region))
	switch r {
	case "", "global", "auto", "default", "aws":
		return "us-east-1"
	default:
		return strings.TrimSpace(region)
	}
}
