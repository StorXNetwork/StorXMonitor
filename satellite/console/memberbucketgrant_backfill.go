// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

// MemberBucketGrantBackfillReport summarizes a Member ACL backfill run.
type MemberBucketGrantBackfillReport struct {
	MembersVisited   int `json:"membersVisited"`
	ACLsCreated      int `json:"aclsCreated"`
	APIKeysRotated   int `json:"apiKeysRotated"`
	SkippedNoBuckets int `json:"skippedNoBuckets"`
	Errors           int `json:"errors"`
}

// BackfillMemberBucketGrants creates default grants for existing Members that have none,
// only when the project already has ACL registry buckets. Does not seed registry names.
// Always invalidates Member project API keys so unrestricted credentials cannot linger.
func (s *Service) BackfillMemberBucketGrants(ctx context.Context, projectID uuid.UUID) (report MemberBucketGrantBackfillReport, err error) {
	defer mon.Task()(&ctx)(&err)

	if !s.config.MemberBucketGrantsEnabled {
		return report, ErrValidation.New("member bucket grants feature is disabled")
	}

	names, err := s.registeredBucketNames(ctx, projectID)
	if err != nil {
		return report, err
	}

	// Page through members via GetPagedWithInvitationsByProjectID until exhausted.
	page := uint(1)
	for {
		pmp, err := s.store.ProjectMembers().GetPagedWithInvitationsByProjectID(ctx, projectID, ProjectMembersCursor{
			Limit:          50,
			Page:           page,
			Order:          Created,
			OrderDirection: Ascending,
		})
		if err != nil {
			return report, Error.Wrap(err)
		}
		if len(pmp.ProjectMembers) == 0 {
			break
		}

		for _, pm := range pmp.ProjectMembers {
			if pm.Role != RoleMember {
				continue
			}
			report.MembersVisited++

			existing, err := s.store.MemberBucketGrants().GetByMember(ctx, projectID, pm.MemberID)
			if err != nil {
				report.Errors++
				s.log.Error("backfill get grants failed", zap.Error(err), zap.String("member", pm.MemberID.String()))
				continue
			}
			if len(existing) > 0 {
				if invErr := s.InvalidateMemberProjectCredentials(ctx, projectID, pm.MemberID); invErr != nil {
					report.Errors++
					s.log.Error("backfill invalidate failed", zap.Error(invErr))
					continue
				}
				report.APIKeysRotated++
				continue
			}

			if len(names) == 0 {
				report.SkippedNoBuckets++
				if invErr := s.InvalidateMemberProjectCredentials(ctx, projectID, pm.MemberID); invErr != nil {
					report.Errors++
					s.log.Error("backfill invalidate failed", zap.Error(invErr))
					continue
				}
				report.APIKeysRotated++
				continue
			}

			memberUser, err := s.store.Users().Get(ctx, pm.MemberID)
			if err != nil {
				report.Errors++
				s.log.Error("backfill get user failed", zap.Error(err))
				continue
			}
			defaults := DefaultInviteGrants(memberUser.Email, names)
			if err := ValidateGrantSet(defaults); err != nil {
				report.Errors++
				s.log.Error("backfill validate failed", zap.Error(err))
				continue
			}
			_, err = s.store.MemberBucketGrants().ReplaceForMember(ctx, projectID, pm.MemberID, memberUser.Email, defaults)
			if err != nil {
				report.Errors++
				s.log.Error("backfill replace grants failed", zap.Error(err))
				continue
			}
			report.ACLsCreated++
			if invErr := s.InvalidateMemberProjectCredentials(ctx, projectID, pm.MemberID); invErr != nil {
				report.Errors++
				s.log.Error("backfill invalidate failed", zap.Error(invErr))
				continue
			}
			report.APIKeysRotated++
		}

		if page >= pmp.PageCount {
			break
		}
		page++
	}

	if report.Errors > 0 {
		return report, errs.New("member bucket grant backfill completed with %d errors", report.Errors)
	}
	return report, nil
}
