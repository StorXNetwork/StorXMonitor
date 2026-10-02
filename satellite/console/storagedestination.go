// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

var (
	// ErrStorageDestinationNotFound is used when no destination row exists.
	ErrStorageDestinationNotFound = errs.Class("storage destination not found")
	// ErrStorageDestinationInvalid is used for invalid mode or incomplete gateway credentials.
	ErrStorageDestinationInvalid = errs.Class("storage destination invalid")
)

// Storage destination mode values.
const (
	StorageDestinationDefault    = "default"
	StorageDestinationExternalS3 = "external_s3"
	StorageDestinationOwnNodes   = "own_nodes"

	// GatewayS3TokenType marks a Backup-Tools storx_token as gateway S3 credentials
	// (works with any S3-compatible app behind the gateway, not AWS-only).
	GatewayS3TokenType = "gateway_s3"
)

// StorageDestinations is the repository for per-user storage destination settings.
//
// architecture: Database
type StorageDestinations interface {
	// GetByUserID returns the destination for the user, or ErrStorageDestinationNotFound.
	GetByUserID(ctx context.Context, userID uuid.UUID) (*StorageDestination, error)
	// Upsert inserts or updates the destination for the user.
	Upsert(ctx context.Context, dest *StorageDestination) error
	// Delete removes the destination row for the user.
	Delete(ctx context.Context, userID uuid.UUID) error
}

// StorageDestination is the user's chosen backup/vault storage backend.
type StorageDestination struct {
	UserID              uuid.UUID `json:"userId"`
	Mode                string    `json:"mode"`
	GatewayAccessKeyID  string    `json:"accessKeyId,omitempty"`
	GatewaySecretKey    string    `json:"secretKey,omitempty"`
	GatewayEndpoint     string    `json:"endpoint,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

// StorageDestinationResponse is the API response (secrets included for the owner session).
type StorageDestinationResponse struct {
	Mode         string                  `json:"mode"`
	AccessKeyID  string                  `json:"access_key_id,omitempty"`
	SecretKey    string                  `json:"secret_key,omitempty"`
	Endpoint     string                  `json:"endpoint,omitempty"`
	OwnNodes     *OwnNodesCapacityStatus `json:"own_nodes,omitempty"`
}

// UpsertStorageDestinationRequest is the body for PUT /storage-destination.
type UpsertStorageDestinationRequest struct {
	Mode        string `json:"mode"`
	AccessKeyID string `json:"access_key_id"`
	SecretKey   string `json:"secret_key"`
	Endpoint    string `json:"endpoint"`
}

// GatewayS3Token is the JSON shape stored in Backup-Tools storx_token for external S3.
type GatewayS3Token struct {
	Type        string `json:"type"`
	AccessKeyID string `json:"access_key_id"`
	SecretKey   string `json:"secret_key"`
	Endpoint    string `json:"endpoint"`
}

// EncodeGatewayS3Token serializes gateway credentials for Backup-Tools.
func EncodeGatewayS3Token(accessKeyID, secretKey, endpoint string) (string, error) {
	accessKeyID = strings.TrimSpace(accessKeyID)
	secretKey = strings.TrimSpace(secretKey)
	endpoint = strings.TrimSpace(endpoint)
	if accessKeyID == "" || secretKey == "" || endpoint == "" {
		return "", ErrStorageDestinationInvalid.New("incomplete gateway credentials")
	}
	b, err := json.Marshal(GatewayS3Token{
		Type:        GatewayS3TokenType,
		AccessKeyID: accessKeyID,
		SecretKey:   secretKey,
		Endpoint:    endpoint,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseGatewayS3Token parses a storx_token that may be a gateway S3 credential blob.
// Returns (nil, false) if the token is a normal StorX access grant.
func ParseGatewayS3Token(token string) (*GatewayS3Token, bool) {
	token = strings.TrimSpace(token)
	if token == "" || token[0] != '{' {
		return nil, false
	}
	var t GatewayS3Token
	if err := json.Unmarshal([]byte(token), &t); err != nil {
		return nil, false
	}
	if t.Type != GatewayS3TokenType {
		return nil, false
	}
	if strings.TrimSpace(t.AccessKeyID) == "" || strings.TrimSpace(t.SecretKey) == "" || strings.TrimSpace(t.Endpoint) == "" {
		return nil, false
	}
	return &t, true
}

// NormalizeStorageDestinationMode validates and normalizes a mode string.
func NormalizeStorageDestinationMode(mode string) (string, error) {
	switch strings.TrimSpace(mode) {
	case "", StorageDestinationDefault:
		return StorageDestinationDefault, nil
	case StorageDestinationExternalS3:
		return StorageDestinationExternalS3, nil
	case StorageDestinationOwnNodes:
		return StorageDestinationOwnNodes, nil
	default:
		return "", ErrStorageDestinationInvalid.New("unknown mode %q", mode)
	}
}
