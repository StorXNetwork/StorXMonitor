// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"strings"
	"time"

	"github.com/StorXNetwork/common/pb"
	"github.com/StorXNetwork/common/uuid"
)

// MailExportOrdersDB is the orders DB subset used to record mail-export download charges.
// Uses UpdateBucketBandwidthInline with PieceAction_GET (same pattern as orders.UpdateGetInlineOrder).
type MailExportOrdersDB interface {
	UpdateBucketBandwidthInline(ctx context.Context, projectID uuid.UUID, bucketName []byte, action pb.PieceAction, amount int64, intervalStart time.Time) error
}

// ChargeMailExportDownloadBandwidthRequest is the internal charge API input.
type ChargeMailExportDownloadBandwidthRequest struct {
	AccessGrant string
	Bytes       int64
	JobID       string
	ChargeID    string
}

// ChargeMailExportDownloadBandwidthResult is returned after applying (or replaying) a charge.
type ChargeMailExportDownloadBandwidthResult struct {
	ChargedBytes   int64 `json:"chargedBytes"`
	AlreadyCharged bool  `json:"alreadyCharged"`
}

// SetMailExportOrdersDB wires orders DB for mail-export download bandwidth charges.
func (s *Service) SetMailExportOrdersDB(db MailExportOrdersDB) {
	s.mailExportOrdersDB = db
}

// ChargeMailExportDownloadBandwidth records actual download bytes as settled GET usage.
// Idempotent on (jobId, chargeId) via mail_export_jobs.last_download_charge_id.
// Project is resolved from accessGrant only. Caller must authenticate (Bearer token).
func (s *Service) ChargeMailExportDownloadBandwidth(ctx context.Context, req ChargeMailExportDownloadBandwidthRequest) (result ChargeMailExportDownloadBandwidthResult, err error) {
	defer mon.Task()(&ctx)(&err)

	req.AccessGrant = strings.TrimSpace(req.AccessGrant)
	req.JobID = strings.TrimSpace(req.JobID)
	req.ChargeID = strings.TrimSpace(req.ChargeID)

	if req.AccessGrant == "" {
		return result, ErrValidation.New("accessGrant is required")
	}
	if req.JobID == "" {
		return result, ErrValidation.New("jobId is required")
	}
	if req.ChargeID == "" {
		return result, ErrValidation.New("chargeId is required")
	}
	if req.Bytes <= 0 {
		return result, ErrValidation.New("bytes must be greater than 0")
	}
	if s.mailExportOrdersDB == nil {
		return result, Error.New("mail export orders DB not configured")
	}

	job, err := s.store.MailExportJobs().Get(ctx, req.JobID)
	if err != nil {
		if ErrMailExportJobNotFound.Has(err) {
			return result, err
		}
		return result, Error.Wrap(err)
	}

	if job.LastDownloadChargeID == req.ChargeID {
		result.ChargedBytes = req.Bytes
		if job.LastDownloadChargedBytes != nil {
			result.ChargedBytes = *job.LastDownloadChargedBytes
		}
		result.AlreadyCharged = true
		return result, nil
	}

	project, err := s.resolveProjectForMailExportQuota(ctx, "", req.AccessGrant)
	if err != nil {
		return result, err
	}

	limits, err := s.projectUsage.GetProjectLimits(ctx, project.ID)
	if err != nil {
		return result, Error.Wrap(err)
	}
	if err := s.projectUsage.UpdateProjectBandwidthUsage(ctx, *limits, req.Bytes); err != nil {
		return result, Error.Wrap(err)
	}

	now := time.Now().UTC()
	intervalStart := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	bucketName := []byte(job.Bucket)
	if len(bucketName) == 0 {
		bucketName = []byte("mail-export")
	}
	if err := s.mailExportOrdersDB.UpdateBucketBandwidthInline(ctx, project.ID, bucketName, pb.PieceAction_GET, req.Bytes, intervalStart); err != nil {
		return result, Error.Wrap(err)
	}

	charged := req.Bytes
	chargeID := req.ChargeID
	if _, err := s.store.MailExportJobs().Patch(ctx, req.JobID, PatchMailExportJob{
		LastDownloadChargeID:     &chargeID,
		LastDownloadChargedBytes: &charged,
	}); err != nil {
		return result, Error.Wrap(err)
	}

	result.ChargedBytes = charged
	return result, nil
}
