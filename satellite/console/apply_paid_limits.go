// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"context"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

// ApplyPaidUsageLimits upgrades a user to paid tier and applies storage/bandwidth
// (and optional segment) limits to the user defaults and all owned projects.
// Used after real payment completion and seller plan assignment.
func ApplyPaidUsageLimits(ctx context.Context, users Users, projects Projects, userID uuid.UUID, storage, bandwidth, segment int64) (err error) {
	defer mon.Task()(&ctx)(&err)

	if users == nil || projects == nil {
		return errs.New("users and projects are required")
	}

	limits := UsageLimits{
		Storage:   storage,
		Bandwidth: bandwidth,
		Segment:   segment,
	}

	if err = users.UpdateUserProjectLimits(ctx, userID, limits); err != nil {
		return errs.Wrap(err)
	}
	if err = users.UpdatePaidTiers(ctx, userID, true); err != nil {
		return errs.Wrap(err)
	}

	owned, err := projects.GetOwn(ctx, userID)
	if err != nil {
		return errs.Wrap(err)
	}
	for _, project := range owned {
		projectLimits := limits
		// Preserve existing segment when caller did not specify one (payment gateway path).
		if segment <= 0 && project.SegmentLimit != nil {
			projectLimits.Segment = *project.SegmentLimit
		}
		if err = projects.UpdateUsageLimits(ctx, project.ID, projectLimits); err != nil {
			return errs.Wrap(err)
		}
	}
	return nil
}

// ApplyFreeUsageLimits downgrades a user to free tier and applies free storage/bandwidth
// limits to the user defaults and all owned projects.
// Used when a seller-assigned plan ends with no future plan scheduled.
func ApplyFreeUsageLimits(ctx context.Context, users Users, projects Projects, userID uuid.UUID, storage, bandwidth, segment int64) (err error) {
	defer mon.Task()(&ctx)(&err)

	if users == nil || projects == nil {
		return errs.New("users and projects are required")
	}

	limits := UsageLimits{
		Storage:   storage,
		Bandwidth: bandwidth,
		Segment:   segment,
	}

	if err = users.UpdateUserProjectLimits(ctx, userID, limits); err != nil {
		return errs.Wrap(err)
	}
	if err = users.UpdatePaidTiers(ctx, userID, false); err != nil {
		return errs.Wrap(err)
	}

	owned, err := projects.GetOwn(ctx, userID)
	if err != nil {
		return errs.Wrap(err)
	}
	for _, project := range owned {
		if err = projects.UpdateUsageLimits(ctx, project.ID, limits); err != nil {
			return errs.Wrap(err)
		}
	}
	return nil
}
