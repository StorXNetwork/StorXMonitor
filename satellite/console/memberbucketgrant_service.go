// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/grant"
	"github.com/StorXNetwork/common/uuid"
)

// ListProjectMemberACLBuckets returns the Admin-managed ACL bucket registry for a project.
func (s *Service) ListProjectMemberACLBuckets(ctx context.Context, projectID uuid.UUID) (buckets []ProjectMemberACLBucket, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "list member acl buckets", zap.String("project_id", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}
	member, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if !member.isOwnerOrAdmin(user.ID) {
		return nil, ErrForbidden.New("only project Owner or Admin can manage member ACL buckets")
	}

	return s.store.ProjectMemberACLBuckets().List(ctx, member.project.ID)
}

// AddProjectMemberACLBucket validates and registers a bucket for Member ACL grants.
func (s *Service) AddProjectMemberACLBucket(ctx context.Context, projectID uuid.UUID, bucketName string) (row *ProjectMemberACLBucket, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "add member acl bucket", zap.String("project_id", projectID.String()), zap.String("bucket", bucketName))
	if err != nil {
		return nil, Error.Wrap(err)
	}
	member, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if !member.isOwnerOrAdmin(user.ID) {
		return nil, ErrForbidden.New("only project Owner or Admin can manage member ACL buckets")
	}

	bucketName = strings.TrimSpace(bucketName)
	if err := ValidateBucketNameForMemberACL(bucketName); err != nil {
		return nil, ErrValidation.Wrap(err)
	}

	exists, err := s.buckets.HasBucket(ctx, []byte(bucketName), member.project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !exists {
		return nil, ErrValidation.New("bucket %q does not exist on this project", bucketName)
	}

	row, err = s.store.ProjectMemberACLBuckets().Add(ctx, member.project.ID, bucketName)
	if err != nil {
		if dbxConstraintError(err) {
			return nil, ErrConflict.New("bucket %q is already in the member ACL registry", bucketName)
		}
		return nil, Error.Wrap(err)
	}
	return row, nil
}

// RemoveProjectMemberACLBucket removes a bucket from the Member ACL registry.
func (s *Service) RemoveProjectMemberACLBucket(ctx context.Context, projectID uuid.UUID, bucketName string) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "remove member acl bucket", zap.String("project_id", projectID.String()), zap.String("bucket", bucketName))
	if err != nil {
		return Error.Wrap(err)
	}
	member, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return ErrUnauthorized.Wrap(err)
	}
	if !member.isOwnerOrAdmin(user.ID) {
		return ErrForbidden.New("only project Owner or Admin can manage member ACL buckets")
	}

	return Error.Wrap(s.store.ProjectMemberACLBuckets().Remove(ctx, member.project.ID, strings.TrimSpace(bucketName)))
}

// GetMemberBucketGrants returns ACL grants for a member. Admins can read any; Members only their own.
func (s *Service) GetMemberBucketGrants(ctx context.Context, projectID, memberID uuid.UUID) (grants []MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get member bucket grants", zap.String("project_id", projectID.String()), zap.String("member_id", memberID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}
	caller, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if !caller.isOwnerOrAdmin(user.ID) && user.ID != memberID {
		return nil, ErrForbidden.New("members can only view their own bucket grants")
	}

	return s.store.MemberBucketGrants().GetByMember(ctx, caller.project.ID, memberID)
}

// GetPendingInviteBucketGrants returns pending ACL grants for an invite email. Owner/Admin only.
func (s *Service) GetPendingInviteBucketGrants(ctx context.Context, projectID uuid.UUID, inviteEmail string) (grants []MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get pending invite bucket grants", zap.String("project_id", projectID.String()), zap.String("invite_email", inviteEmail))
	if err != nil {
		return nil, Error.Wrap(err)
	}
	caller, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if !caller.isOwnerOrAdmin(user.ID) {
		return nil, ErrForbidden.New("only project Owner or Admin can view pending invite grants")
	}

	return s.store.MemberBucketGrants().GetByInviteEmail(ctx, caller.project.ID, inviteEmail)
}

// ReplaceMemberBucketGrants full-replaces grants for a Member and invalidates their project credentials.
// vaultExpiration is 24h|3d|7d|30d (empty = vault access does not expire).
func (s *Service) ReplaceMemberBucketGrants(ctx context.Context, projectID, memberID uuid.UUID, grants []MemberBucketGrantInput, vaultExpiration string) (out []MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "replace member bucket grants", zap.String("project_id", projectID.String()), zap.String("member_id", memberID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}
	caller, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if !caller.isOwnerOrAdmin(user.ID) {
		return nil, ErrForbidden.New("only project Owner or Admin can update member bucket grants")
	}

	target, err := s.store.ProjectMembers().GetByMemberIDAndProjectID(ctx, memberID, caller.project.ID)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, ErrNoMembership.Wrap(err)
		}
		return nil, Error.Wrap(err)
	}
	_ = target

	memberUser, err := s.store.Users().Get(ctx, memberID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if err := ValidateGrantSet(grants); err != nil {
		return nil, ErrValidation.Wrap(err)
	}
	if err := s.ensureMemberGrantBucketsExist(ctx, caller.project.ID, grants); err != nil {
		return nil, err
	}

	vaultDur, err := ParseOptionalVaultExpiration(vaultExpiration)
	if err != nil {
		return nil, err
	}
	vaultExpiresAt := VaultExpiresAtPtr(s.nowFn(), vaultDur)

	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) error {
		out, err = tx.MemberBucketGrants().ReplaceForMember(ctx, caller.project.ID, memberID, memberUser.Email, grants, vaultExpiresAt)
		return err
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if err := s.InvalidateMemberProjectCredentials(ctx, caller.project.ID, memberID); err != nil {
		return nil, Error.Wrap(err)
	}
	return out, nil
}

// InvalidateMemberProjectCredentials deletes API keys created by the member for the project.
func (s *Service) InvalidateMemberProjectCredentials(ctx context.Context, projectID, memberID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	return Error.Wrap(s.store.APIKeys().DeleteAllByProjectIDAndOwnerID(ctx, projectID, memberID))
}

func (s *Service) registeredBucketSet(ctx context.Context, projectID uuid.UUID) (map[string]struct{}, error) {
	return registeredBucketSet(ctx, s.store, projectID)
}

func (s *Service) registeredBucketNames(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	return registeredBucketNames(ctx, s.store, projectID)
}

func registeredBucketSet(ctx context.Context, db DB, projectID uuid.UUID) (map[string]struct{}, error) {
	rows, err := db.ProjectMemberACLBuckets().List(ctx, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	out := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		out[row.BucketName] = struct{}{}
	}
	return out, nil
}

func registeredBucketNames(ctx context.Context, db DB, projectID uuid.UUID) ([]string, error) {
	rows, err := db.ProjectMemberACLBuckets().List(ctx, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.BucketName)
	}
	return names, nil
}

func (s *Service) createPendingMemberGrants(ctx context.Context, tx DBTx, projectID uuid.UUID, inviteEmail string, grants []MemberBucketGrantInput, vaultExpiresAt *time.Time) error {
	if !s.config.MemberBucketGrantsEnabled {
		return nil
	}
	existing, err := tx.MemberBucketGrants().GetByInviteEmail(ctx, projectID, inviteEmail)
	if err != nil {
		return err
	}
	// Reinvite must not overwrite Admin-customized pending grants.
	if len(existing) > 0 {
		return nil
	}

	if grants == nil {
		// Optional defaults from ACL registry if Admin configured any; otherwise no folder grants.
		names, err := registeredBucketNames(ctx, tx, projectID)
		if err != nil {
			return err
		}
		grants = DefaultInviteGrants(inviteEmail, names)
	}

	if err := ValidateGrantSet(grants); err != nil {
		return ErrValidation.Wrap(err)
	}
	// Bucket existence must be checked outside the console DB transaction
	// (buckets.HasBucket uses the non-tx DB and panics if called inside WithTx).
	if len(grants) == 0 {
		return nil
	}
	_, err = tx.MemberBucketGrants().CreatePending(ctx, projectID, inviteEmail, grants, vaultExpiresAt)
	return err
}

// ensureMemberGrantBucketsExist requires each grant bucket to exist on the project.
// No separate ACL-registry registration is required.
func (s *Service) ensureMemberGrantBucketsExist(ctx context.Context, projectID uuid.UUID, grants []MemberBucketGrantInput) error {
	seen := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		if _, ok := seen[g.Bucket]; ok {
			continue
		}
		seen[g.Bucket] = struct{}{}
		exists, err := s.buckets.HasBucket(ctx, []byte(g.Bucket), projectID)
		if err != nil {
			return Error.Wrap(err)
		}
		if !exists {
			return ErrValidation.New("bucket %q does not exist on this project", g.Bucket)
		}
	}
	return nil
}

// applyMemberACLToAccessRequest intersects Member AG requests with stored grants.
// Returns updated prefixes/permission. Deny unrestricted or out-of-ACL requests.
func (s *Service) applyMemberACLToAccessRequest(ctx context.Context, projectID, userID uuid.UUID, prefixes []grant.SharePrefix, permission *grant.Permission) ([]grant.SharePrefix, *grant.Permission, error) {
	if !s.config.MemberBucketGrantsEnabled {
		return prefixes, permission, nil
	}

	member, err := s.isProjectMember(ctx, userID, projectID)
	if err != nil {
		if ErrNoMembership.Has(err) {
			// Owner may not have a membership row; treat as unrestricted.
			isOwner, _, ownerErr := s.isProjectOwner(ctx, userID, projectID)
			if ownerErr == nil && isOwner {
				return prefixes, permission, nil
			}
			return nil, nil, ErrUnauthorized.Wrap(err)
		}
		return nil, nil, Error.Wrap(err)
	}
	// Owner (projects.owner_id) or RoleAdmin bypass Member ACL. CreateProject stores owner as RoleMember.
	if member.isOwnerOrAdmin(userID) {
		return prefixes, permission, nil
	}

	acl, err := s.store.MemberBucketGrants().GetByMember(ctx, member.project.ID, userID)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}
	acl = FilterActiveMemberGrants(acl, time.Now())

	// Unrestricted mint (no prefix/permission) is not allowed for Members.
	if len(prefixes) == 0 && permission == nil {
		return nil, nil, ErrForbidden.New("members cannot create unrestricted access grants")
	}

	if len(acl) == 0 {
		return nil, nil, ErrForbidden.New("member has no bucket grants")
	}

	return IntersectMemberAccessRequest(prefixes, permission, acl)
}

// IntersectMemberAccessRequest intersects requested SharePrefix + Permission with stored Member ACL grants.
// Pure helper for enforcement and table-driven tests.
func IntersectMemberAccessRequest(prefixes []grant.SharePrefix, permission *grant.Permission, acl []MemberBucketGrant) ([]grant.SharePrefix, *grant.Permission, error) {
	var outPrefixes []grant.SharePrefix
	var combined *grant.Permission

	for _, p := range prefixes {
		if p.Bucket == "" {
			return nil, nil, ErrForbidden.New("members cannot request all-buckets access")
		}
		match := FindMatchingGrant(p.Bucket, p.Prefix, acl)
		if match == nil {
			return nil, nil, ErrForbidden.New("requested scope outside member bucket grants")
		}
		eff := IntersectPermission(permission, *match)
		if !eff.AllowList && !eff.AllowDownload {
			return nil, nil, ErrForbidden.New("effective permissions are empty after ACL intersection")
		}
		outPrefixes = append(outPrefixes, p)
		if combined == nil {
			c := eff
			combined = &c
		} else {
			combined.AllowList = combined.AllowList && eff.AllowList
			combined.AllowDownload = combined.AllowDownload && eff.AllowDownload
			combined.AllowUpload = false
			combined.AllowDelete = false
		}
	}

	if len(outPrefixes) == 0 {
		return nil, nil, ErrForbidden.New("members must request an explicit bucket prefix within their grants")
	}
	return outPrefixes, combined, nil
}

// dbxConstraintError detects unique/constraint failures without importing dbx here.
func dbxConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") || strings.Contains(msg, "constraint")
}
