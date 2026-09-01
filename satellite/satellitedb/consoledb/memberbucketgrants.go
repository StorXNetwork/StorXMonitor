// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

var _ console.MemberBucketGrants = (*memberBucketGrants)(nil)

type memberBucketGrants struct {
	db dbx.DriverMethods
}

func (r *memberBucketGrants) CreatePending(ctx context.Context, projectID uuid.UUID, inviteEmail string, grants []console.MemberBucketGrantInput, expiresAt *time.Time) (out []console.MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	email := normalizeEmail(inviteEmail)
	out = make([]console.MemberBucketGrant, 0, len(grants))
	for _, g := range grants {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		createFields := dbx.MemberBucketGrant_Create_Fields{
			MemberId: dbx.MemberBucketGrant_MemberId_Null(),
		}
		if expiresAt != nil {
			createFields.ExpiresAt = dbx.MemberBucketGrant_ExpiresAt(*expiresAt)
		}
		row, err := r.db.Create_MemberBucketGrant(ctx,
			dbx.MemberBucketGrant_Id(id[:]),
			dbx.MemberBucketGrant_ProjectId(projectID[:]),
			dbx.MemberBucketGrant_InviteEmail(email),
			dbx.MemberBucketGrant_Bucket(g.Bucket),
			dbx.MemberBucketGrant_Prefix(g.Prefix),
			dbx.MemberBucketGrant_AllowList(g.AllowList),
			dbx.MemberBucketGrant_AllowDownload(g.AllowDownload),
			// Member ACL supports List + Download only.
			dbx.MemberBucketGrant_AllowUpload(false),
			dbx.MemberBucketGrant_AllowDelete(false),
			createFields,
		)
		if err != nil {
			return nil, err
		}
		converted, err := memberBucketGrantFromDBX(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *converted)
	}
	return out, nil
}

func (r *memberBucketGrants) GetByMember(ctx context.Context, projectID, memberID uuid.UUID) (out []console.MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := r.db.All_MemberBucketGrant_By_ProjectId_And_MemberId(ctx,
		dbx.MemberBucketGrant_ProjectId(projectID[:]),
		dbx.MemberBucketGrant_MemberId(memberID[:]),
	)
	if err != nil {
		return nil, err
	}
	return memberBucketGrantSliceFromDBX(rows)
}

func (r *memberBucketGrants) GetByInviteEmail(ctx context.Context, projectID uuid.UUID, inviteEmail string) (out []console.MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := r.db.All_MemberBucketGrant_By_ProjectId_And_InviteEmail(ctx,
		dbx.MemberBucketGrant_ProjectId(projectID[:]),
		dbx.MemberBucketGrant_InviteEmail(normalizeEmail(inviteEmail)),
	)
	if err != nil {
		return nil, err
	}
	return memberBucketGrantSliceFromDBX(rows)
}

func (r *memberBucketGrants) ReplacePendingForInviteEmail(ctx context.Context, projectID uuid.UUID, inviteEmail string, grants []console.MemberBucketGrantInput, expiresAt *time.Time) (out []console.MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	if err = r.DeleteByInviteEmail(ctx, projectID, inviteEmail); err != nil {
		return nil, err
	}
	return r.CreatePending(ctx, projectID, inviteEmail, grants, expiresAt)
}

func (r *memberBucketGrants) ReplaceForMember(ctx context.Context, projectID, memberID uuid.UUID, inviteEmail string, grants []console.MemberBucketGrantInput, expiresAt *time.Time) (out []console.MemberBucketGrant, err error) {
	defer mon.Task()(&ctx)(&err)

	if err = r.DeleteByMember(ctx, projectID, memberID); err != nil {
		return nil, err
	}

	email := normalizeEmail(inviteEmail)
	out = make([]console.MemberBucketGrant, 0, len(grants))
	for _, g := range grants {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		createFields := dbx.MemberBucketGrant_Create_Fields{
			MemberId: dbx.MemberBucketGrant_MemberId(memberID[:]),
		}
		if expiresAt != nil {
			createFields.ExpiresAt = dbx.MemberBucketGrant_ExpiresAt(*expiresAt)
		}
		row, err := r.db.Create_MemberBucketGrant(ctx,
			dbx.MemberBucketGrant_Id(id[:]),
			dbx.MemberBucketGrant_ProjectId(projectID[:]),
			dbx.MemberBucketGrant_InviteEmail(email),
			dbx.MemberBucketGrant_Bucket(g.Bucket),
			dbx.MemberBucketGrant_Prefix(g.Prefix),
			dbx.MemberBucketGrant_AllowList(g.AllowList),
			dbx.MemberBucketGrant_AllowDownload(g.AllowDownload),
			// Member ACL supports List + Download only.
			dbx.MemberBucketGrant_AllowUpload(false),
			dbx.MemberBucketGrant_AllowDelete(false),
			createFields,
		)
		if err != nil {
			return nil, err
		}
		converted, err := memberBucketGrantFromDBX(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *converted)
	}
	return out, nil
}

func (r *memberBucketGrants) BindPendingToMember(ctx context.Context, projectID uuid.UUID, inviteEmail string, memberID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := r.db.All_MemberBucketGrant_By_ProjectId_And_InviteEmail(ctx,
		dbx.MemberBucketGrant_ProjectId(projectID[:]),
		dbx.MemberBucketGrant_InviteEmail(normalizeEmail(inviteEmail)),
	)
	if err != nil {
		return err
	}

	for _, row := range rows {
		_, err = r.db.Update_MemberBucketGrant_By_Id(ctx,
			dbx.MemberBucketGrant_Id(row.Id),
			dbx.MemberBucketGrant_Update_Fields{
				MemberId: dbx.MemberBucketGrant_MemberId(memberID[:]),
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *memberBucketGrants) DeleteByMember(ctx context.Context, projectID, memberID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = r.db.Delete_MemberBucketGrant_By_ProjectId_And_MemberId(ctx,
		dbx.MemberBucketGrant_ProjectId(projectID[:]),
		dbx.MemberBucketGrant_MemberId(memberID[:]),
	)
	return err
}

func (r *memberBucketGrants) DeleteByInviteEmail(ctx context.Context, projectID uuid.UUID, inviteEmail string) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = r.db.Delete_MemberBucketGrant_By_ProjectId_And_InviteEmail(ctx,
		dbx.MemberBucketGrant_ProjectId(projectID[:]),
		dbx.MemberBucketGrant_InviteEmail(normalizeEmail(inviteEmail)),
	)
	return err
}

func memberBucketGrantSliceFromDBX(rows []*dbx.MemberBucketGrant) ([]console.MemberBucketGrant, error) {
	out := make([]console.MemberBucketGrant, 0, len(rows))
	for _, row := range rows {
		converted, err := memberBucketGrantFromDBX(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *converted)
	}
	return out, nil
}

func memberBucketGrantFromDBX(row *dbx.MemberBucketGrant) (*console.MemberBucketGrant, error) {
	if row == nil {
		return nil, Error.New("dbx member bucket grant is nil")
	}
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	projectID, err := uuid.FromBytes(row.ProjectId)
	if err != nil {
		return nil, err
	}
	var memberID *uuid.UUID
	if row.MemberId != nil {
		parsed, err := uuid.FromBytes(row.MemberId)
		if err != nil {
			return nil, err
		}
		memberID = &parsed
	}
	return &console.MemberBucketGrant{
		ID:            id,
		ProjectID:     projectID,
		MemberID:      memberID,
		InviteEmail:   row.InviteEmail,
		Bucket:        row.Bucket,
		Prefix:        row.Prefix,
		AllowList:     row.AllowList,
		AllowDownload: row.AllowDownload,
		AllowUpload:   row.AllowUpload,
		AllowDelete:   row.AllowDelete,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
		ExpiresAt:     row.ExpiresAt,
	}, nil
}
