// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

// GetStorageDestination returns the current user's storage destination (defaults to default mode).
// Deprecated for external S3 — use GetExternalS3. Kept for own_nodes UI mode compatibility.
func (s *Service) GetStorageDestination(ctx context.Context) (resp *StorageDestinationResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	// Prefer dedicated external S3 table when active.
	if backend, bErr := s.store.ExternalS3Backends().GetByUserID(ctx, user.ID); bErr == nil &&
		backend.Status == ExternalS3StatusActive {
		return &StorageDestinationResponse{
			Mode:        StorageDestinationExternalS3,
			AccessKeyID: backend.GatewayAccessKeyID,
			Endpoint:    backend.GatewayEndpoint,
		}, nil
	}

	dest, err := s.store.StorageDestinations().GetByUserID(ctx, user.ID)
	if err != nil {
		if ErrStorageDestinationNotFound.Has(err) {
			return &StorageDestinationResponse{Mode: StorageDestinationDefault}, nil
		}
		return nil, Error.Wrap(err)
	}
	return storageDestinationToResponse(dest), nil
}

// SetStorageDestination upserts the current user's storage destination mode (own_nodes/default).
// External S3 credentials must use UpsertExternalS3.
func (s *Service) SetStorageDestination(ctx context.Context, req UpsertStorageDestinationRequest) (resp *StorageDestinationResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	mode, err := NormalizeStorageDestinationMode(req.Mode)
	if err != nil {
		return nil, ErrValidation.Wrap(err)
	}
	if mode == StorageDestinationExternalS3 {
		return nil, ErrValidation.New("use PUT /external-s3 to save S3 credentials")
	}

	dest := &StorageDestination{
		UserID: user.ID,
		Mode:   mode,
	}
	if err = s.store.StorageDestinations().Upsert(ctx, dest); err != nil {
		return nil, Error.Wrap(err)
	}
	return storageDestinationToResponse(dest), nil
}

// ResolveBackupStorxToken returns either a gateway_s3 JSON token (external S3)
// or a freshly minted StorX access grant for Backup-Tools.
func (s *Service) ResolveBackupStorxToken(ctx context.Context, userID, projectID uuid.UUID) (token string, err error) {
	defer mon.Task()(&ctx)(&err)

	backend, getErr := s.store.ExternalS3Backends().GetByUserID(ctx, userID)
	if getErr == nil && backend != nil && backend.Status == ExternalS3StatusActive {
		accessKeyID, secretKey, endpoint, ensureErr := s.EnsureExternalS3Gateway(ctx, userID)
		if ensureErr != nil {
			return "", Error.Wrap(ensureErr)
		}
		token, err = EncodeGatewayS3Token(accessKeyID, secretKey, endpoint)
		if err != nil {
			return "", ErrExternalS3Invalid.Wrap(err)
		}
		return token, nil
	}
	if getErr != nil && !ErrExternalS3NotFound.Has(getErr) {
		s.log.Warn("lookup external s3 backend failed", zap.Error(getErr), zap.String("user_id", userID.String()))
		return "", Error.Wrap(getErr)
	}

	return s.CreateAccessGrantForManagedProject(ctx, projectID)
}

func storageDestinationToResponse(dest *StorageDestination) *StorageDestinationResponse {
	if dest == nil {
		return &StorageDestinationResponse{Mode: StorageDestinationDefault}
	}
	resp := &StorageDestinationResponse{Mode: dest.Mode}
	if dest.Mode == StorageDestinationExternalS3 {
		resp.AccessKeyID = dest.GatewayAccessKeyID
		resp.SecretKey = dest.GatewaySecretKey
		resp.Endpoint = dest.GatewayEndpoint
	}
	return resp
}
