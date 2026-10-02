// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

const (
	// DiskTagAllocated is the check-in tag for a node's allocated disk bytes.
	DiskTagAllocated = "storx_allocated_disk"
	// DiskTagUsed is the check-in tag for bytes used inside that allocation.
	DiskTagUsed = "storx_used_disk"
)

// ownNodesQuotaBytes is the storage and bandwidth cap for an own-nodes project.
// Disk free space plus data already stored is the capacity of the deployed nodes.
// Upload and download share that same number. Zero means no positive disk report yet.
func ownNodesQuotaBytes(storageUsed, freeDisk int64) int64 {
	if freeDisk < 0 {
		freeDisk = 0
	}
	if storageUsed < 0 {
		storageUsed = 0
	}
	sum := storageUsed + freeDisk
	if sum < 0 {
		return 0
	}
	return sum
}

// applyOwnNodesQuota replaces the free-tier 2GB storage and bandwidth caps for an
// own-nodes project with the capacity of the deployed nodes. Upload and download
// share that number. Public projects are left unchanged.
func (s *Service) applyOwnNodesQuota(ctx context.Context, projectID uuid.UUID, limits *ProjectUsageLimits) {
	if limits == nil || s.store == nil {
		return
	}
	orgID, err := s.store.Projects().GetOwnNodesOrgID(ctx, projectID)
	if err != nil || orgID == nil || orgID.IsZero() {
		return
	}
	allocated, diskUsed, err := s.store.OrgNodes().DiskTotalsByOrgID(ctx, *orgID)
	if err != nil {
		s.log.Warn("own-nodes disk quota lookup failed", zap.Error(err), zap.Stringer("project", projectID))
		return
	}
	var quota int64
	if allocated > 0 {
		quota = allocated
		if diskUsed > 0 {
			limits.StorageUsed = diskUsed
		}
	} else {
		freeDisk, freeErr := s.store.OrgNodes().SumFreeDiskByOrgID(ctx, *orgID)
		if freeErr != nil {
			s.log.Warn("own-nodes free disk lookup failed", zap.Error(freeErr), zap.Stringer("project", projectID))
			return
		}
		quota = ownNodesQuotaBytes(limits.StorageUsed, freeDisk)
	}
	oldStorage := limits.StorageLimit
	oldBandwidth := limits.BandwidthLimit
	limits.StorageLimit = quota
	limits.BandwidthLimit = quota
	limits.UserSetStorageLimit = nil
	limits.UserSetBandwidthLimit = nil
	if quota <= 0 || s.projectUsage == nil || (quota == oldStorage && quota == oldBandwidth) {
		return
	}
	if err := s.projectUsage.SetProjectStorageAndBandwidthLimits(ctx, projectID, quota, quota); err != nil {
		s.log.Warn("own-nodes disk quota persist failed", zap.Error(err), zap.Stringer("project", projectID))
	}
}

// hideExternalS3Quota drops the free-tier cap from the dashboard numbers when the
// project owner stores data on an external S3 bucket. The satellite cannot read
// that bucket's capacity, so the card shows usage only.
func (s *Service) hideExternalS3Quota(ctx context.Context, projectID uuid.UUID, limits *ProjectUsageLimits) {
	if limits == nil || !s.projectUsesExternalS3(ctx, projectID) {
		return
	}
	limits.StorageLimit = quotaLimitForDestination(StorageDestinationExternalS3, limits.StorageLimit)
	limits.BandwidthLimit = quotaLimitForDestination(StorageDestinationExternalS3, limits.BandwidthLimit)
	limits.UserSetStorageLimit = nil
	limits.UserSetBandwidthLimit = nil
}

func (s *Service) projectUsesExternalS3(ctx context.Context, projectID uuid.UUID) bool {
	if s == nil || s.store == nil {
		return false
	}
	project, err := s.store.Projects().Get(ctx, projectID)
	if err != nil || project == nil {
		return false
	}
	if backends := s.store.ExternalS3Backends(); backends != nil {
		backend, bErr := backends.GetByUserID(ctx, project.OwnerID)
		if bErr == nil && backend != nil && backend.Status == ExternalS3StatusActive {
			return true
		}
	}
	dest, err := s.store.StorageDestinations().GetByUserID(ctx, project.OwnerID)
	if err != nil || dest == nil {
		return false
	}
	return dest.Mode == StorageDestinationExternalS3
}

// quotaLimitForDestination is the cap shown on storage and bandwidth cards.
// External S3 has no capacity this satellite can read, so the cap is omitted.
func quotaLimitForDestination(mode string, limit int64) int64 {
	if mode == StorageDestinationExternalS3 {
		return 0
	}
	return limit
}
