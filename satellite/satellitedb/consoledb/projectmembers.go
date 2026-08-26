// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/private/slices2"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/StorXMonitor/shared/dbutil"
	"github.com/StorXNetwork/StorXMonitor/shared/tagsql"
)

// ensures that projectMembers implements console.ProjectMembers.
var _ console.ProjectMembers = (*projectMembers)(nil)

// ProjectMembers exposes db to manage ProjectMembers table in database.
type projectMembers struct {
	db   dbx.DriverMethods
	impl dbutil.Implementation
}

// GetByMemberID is a method for querying project member from the database by memberID.
func (pm *projectMembers) GetByMemberID(ctx context.Context, memberID uuid.UUID) (_ []console.ProjectMember, err error) {
	defer mon.Task()(&ctx)(&err)
	projectMembersDbx, err := pm.db.All_ProjectMember_By_MemberId(ctx, dbx.ProjectMember_MemberId(memberID[:]))
	if err != nil {
		return nil, err
	}

	return projectMembersFromDbxSlice(ctx, projectMembersDbx)
}

// GetByMemberIDAndProjectID is a method for querying project member from the database by memberID and projectID.
func (pm *projectMembers) GetByMemberIDAndProjectID(ctx context.Context, memberID, projectID uuid.UUID) (*console.ProjectMember, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	projectMember, err := pm.db.Get_ProjectMember_By_MemberId_And_ProjectId(ctx,
		dbx.ProjectMember_MemberId(memberID[:]),
		dbx.ProjectMember_ProjectId(projectID[:]),
	)
	if err != nil {
		return nil, err
	}

	return projectMemberFromDBX(ctx, projectMember)
}

func (pm *projectMembers) UpdateRole(ctx context.Context, memberID, projectID uuid.UUID, newRole console.ProjectMemberRole) (_ *console.ProjectMember, err error) {
	defer mon.Task()(&ctx)(&err)
	projectMember, err := pm.db.Update_ProjectMember_By_MemberId_And_ProjectId(ctx,
		dbx.ProjectMember_MemberId(memberID[:]),
		dbx.ProjectMember_ProjectId(projectID[:]),
		dbx.ProjectMember_Update_Fields{
			Role: dbx.ProjectMember_Role(int(newRole)),
		},
	)
	if err != nil {
		return nil, err
	}

	return projectMemberFromDBX(ctx, projectMember)
}

// GetTotalCountByProjectID is a method for getting total count of project members by projectID.
func (pm *projectMembers) GetTotalCountByProjectID(ctx context.Context, projectID uuid.UUID) (count uint64, err error) {
	defer mon.Task()(&ctx)(&err)

	countQuery := pm.db.Rebind(`
		SELECT COUNT(*)
		FROM project_members
		WHERE project_id = ?
	`)

	err = pm.db.QueryRowContext(ctx, countQuery, projectID[:]).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

type projectMemberListFilters struct {
	includeMembers bool
	includeInvites bool
	role           *console.ProjectMemberRole
	ownerID        *uuid.UUID
	// ownerMode: "" = ignore owner id; "include" = role OR owner; "exclude" = not owner.
	ownerMode    string
	inviteStatus string // "", "pending", "expired"
	vault        string // bucket name filter; empty = none
	now          time.Time
	inviteTTL    time.Duration
}

func resolveProjectMemberListFilters(cursor console.ProjectMembersCursor) projectMemberListFilters {
	kind := strings.ToLower(strings.TrimSpace(cursor.Kind))
	status := strings.ToLower(strings.TrimSpace(cursor.Status))
	if kind == "" || kind == console.ProjectMemberListKindAll {
		kind = console.ProjectMemberListKindAll
	}
	if status == "" || status == console.ProjectMemberListStatusAll {
		status = console.ProjectMemberListStatusAll
	}

	now := cursor.Now
	if now.IsZero() {
		now = time.Now()
	}
	ttl := cursor.InviteTTL
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}

	f := projectMemberListFilters{
		includeMembers: true,
		includeInvites: true,
		role:           cursor.Role,
		ownerID:        cursor.OwnerID,
		vault:          strings.TrimSpace(cursor.Vault),
		now:            now,
		inviteTTL:      ttl,
	}

	switch kind {
	case console.ProjectMemberListKindMembers:
		f.includeInvites = false
	case console.ProjectMemberListKindPending:
		f.includeMembers = false
		if status == console.ProjectMemberListStatusAll {
			f.inviteStatus = console.ProjectMemberListStatusPending
		}
	case console.ProjectMemberListKindAdmins:
		f.includeInvites = false
		admin := console.RoleAdmin
		f.role = &admin
		if f.ownerID != nil {
			f.ownerMode = "include"
		}
	}

	// Explicit role filter: Admin includes project owner; Member excludes owner.
	if f.role != nil && f.ownerID != nil {
		if *f.role == console.RoleAdmin {
			f.ownerMode = "include"
		} else {
			f.ownerMode = "exclude"
		}
	}
	// Role applies to members only — drop invites when filtering by role.
	if f.role != nil {
		f.includeInvites = false
	}

	switch status {
	case console.ProjectMemberListStatusActive:
		f.includeInvites = false
		f.includeMembers = true
		f.inviteStatus = ""
	case console.ProjectMemberListStatusPending, console.ProjectMemberListStatusExpired:
		f.includeMembers = false
		f.includeInvites = true
		f.inviteStatus = status
		f.role = nil
		f.ownerID = nil
		f.ownerMode = ""
	}

	// Role filter only applies to members; if only invites remain, drop role.
	if !f.includeMembers {
		f.role = nil
		f.ownerID = nil
		f.ownerMode = ""
	}

	return f
}

func inviteExpiredSQLPostgres(createdCol, expiresCol, nowParam, cutoffParam string) string {
	// Expired when expires_at is set and past, or expires_at NULL and created_at past default TTL cutoff.
	return fmt.Sprintf(`((%s IS NOT NULL AND %s <= %s) OR (%s IS NULL AND %s <= %s))`,
		expiresCol, expiresCol, nowParam, expiresCol, createdCol, cutoffParam)
}

func invitePendingSQLPostgres(createdCol, expiresCol, nowParam, cutoffParam string) string {
	return "NOT " + inviteExpiredSQLPostgres(createdCol, expiresCol, nowParam, cutoffParam)
}

// GetPagedWithInvitationsByProjectID is a method for querying project members and invitations from the database by projectID, offset and limit.
func (pm *projectMembers) GetPagedWithInvitationsByProjectID(ctx context.Context, projectID uuid.UUID, cursor console.ProjectMembersCursor) (_ *console.ProjectMembersPage, err error) {
	defer mon.Task()(&ctx)(&err)

	search := "%" + strings.ReplaceAll(cursor.Search, " ", "%") + "%"

	if cursor.Limit == 0 {
		return nil, errs.New("limit cannot be 0")
	}

	if cursor.Page == 0 {
		return nil, errs.New("page cannot be 0")
	}

	filters := resolveProjectMemberListFilters(cursor)
	if !filters.includeMembers && !filters.includeInvites {
		return &console.ProjectMembersPage{
			Search:         cursor.Search,
			Limit:          cursor.Limit,
			Offset:         uint64((cursor.Page - 1) * cursor.Limit),
			Order:          cursor.Order,
			OrderDirection: cursor.OrderDirection,
			CurrentPage:    cursor.Page,
			PageCount:      1,
		}, nil
	}

	page := &console.ProjectMembersPage{
		Search:         cursor.Search,
		Limit:          cursor.Limit,
		Offset:         uint64((cursor.Page - 1) * cursor.Limit),
		Order:          cursor.Order,
		OrderDirection: cursor.OrderDirection,
	}

	expireCutoff := filters.now.Add(-filters.inviteTTL)

	switch pm.impl {
	case dbutil.Cockroach, dbutil.Postgres:
		return pm.getPagedPostgres(ctx, projectID, cursor, page, search, filters, expireCutoff)
	case dbutil.Spanner:
		return pm.getPagedSpanner(ctx, projectID, cursor, page, search, filters, expireCutoff)
	default:
		return nil, Error.New("unsupported database: %v", pm.impl)
	}
}

func (pm *projectMembers) getPagedPostgres(
	ctx context.Context,
	projectID uuid.UUID,
	cursor console.ProjectMembersCursor,
	page *console.ProjectMembersPage,
	search string,
	filters projectMemberListFilters,
	expireCutoff time.Time,
) (*console.ProjectMembersPage, error) {
	var (
		memberCountSQL string
		inviteCountSQL string
		memberSelect   string
		inviteSelect   string
		args           []any
	)

	argN := 1
	nextArg := func() string {
		s := fmt.Sprintf("$%d", argN)
		argN++
		return s
	}

	projectParam := nextArg()
	args = append(args, projectID[:])
	searchParam := nextArg()
	args = append(args, search)

	var roleParam, ownerParam, nowParam, cutoffParam, vaultParam string
	if filters.includeMembers && filters.role != nil {
		roleParam = nextArg()
		args = append(args, int(*filters.role))
	}
	if filters.includeMembers && filters.ownerID != nil && filters.ownerMode != "" {
		ownerParam = nextArg()
		args = append(args, filters.ownerID[:])
	}
	if filters.includeInvites && filters.inviteStatus != "" {
		nowParam = nextArg()
		args = append(args, filters.now)
		cutoffParam = nextArg()
		args = append(args, expireCutoff)
	}
	if filters.vault != "" {
		vaultParam = nextArg()
		args = append(args, filters.vault)
	}

	if filters.includeMembers {
		memberWhere := fmt.Sprintf(`pm.project_id = %s AND (
			u.email ILIKE %s OR
			u.full_name ILIKE %s OR
			u.short_name ILIKE %s
		)`, projectParam, searchParam, searchParam, searchParam)
		if filters.role != nil {
			switch filters.ownerMode {
			case "include":
				memberWhere += fmt.Sprintf(` AND (pm.role = %s OR pm.member_id = %s)`, roleParam, ownerParam)
			case "exclude":
				memberWhere += fmt.Sprintf(` AND pm.role = %s AND pm.member_id <> %s`, roleParam, ownerParam)
			default:
				memberWhere += fmt.Sprintf(` AND pm.role = %s`, roleParam)
			}
		}
		if vaultParam != "" {
			memberWhere += fmt.Sprintf(` AND EXISTS (
				SELECT 1 FROM member_bucket_grants mbg
				WHERE mbg.project_id = pm.project_id
				  AND mbg.member_id = pm.member_id
				  AND mbg.bucket = %s
			)`, vaultParam)
		}
		memberCountSQL = fmt.Sprintf(`
			SELECT COUNT(*)
			FROM project_members pm
			INNER JOIN users u ON pm.member_id = u.id
			WHERE %s
		`, memberWhere)
		memberSelect = fmt.Sprintf(`
			SELECT pm.member_id, pm.project_id, pm.role, pm.created_at, u.email, u.full_name, NULL::bytea as inviter_id, NULL::timestamptz as expires_at
			FROM project_members pm
			INNER JOIN users u ON pm.member_id = u.id
			WHERE %s
		`, memberWhere)
	}

	if filters.includeInvites {
		inviteWhere := fmt.Sprintf(`project_id = %s AND email ILIKE %s`, projectParam, searchParam)
		switch filters.inviteStatus {
		case console.ProjectMemberListStatusPending:
			inviteWhere += " AND " + invitePendingSQLPostgres("created_at", "expires_at", nowParam, cutoffParam)
		case console.ProjectMemberListStatusExpired:
			inviteWhere += " AND " + inviteExpiredSQLPostgres("created_at", "expires_at", nowParam, cutoffParam)
		}
		if vaultParam != "" {
			inviteWhere += fmt.Sprintf(` AND EXISTS (
				SELECT 1 FROM member_bucket_grants mbg
				WHERE mbg.project_id = project_id
				  AND LOWER(mbg.invite_email) = LOWER(email)
				  AND mbg.member_id IS NULL
				  AND mbg.bucket = %s
			)`, vaultParam)
		}
		inviteCountSQL = fmt.Sprintf(`
			SELECT COUNT(*)
			FROM project_invitations
			WHERE %s
		`, inviteWhere)
		inviteSelect = fmt.Sprintf(`
			SELECT NULL::bytea as member_id, project_id, 1 as role, created_at, LOWER(email) as email, LOWER(SPLIT_PART(email, '@', 1)) as full_name, inviter_id, expires_at
			FROM project_invitations pi
			WHERE %s
		`, inviteWhere)
	}

	var countSQL string
	switch {
	case filters.includeMembers && filters.includeInvites:
		countSQL = fmt.Sprintf(`SELECT (%s) + (%s)`, memberCountSQL, inviteCountSQL)
	case filters.includeMembers:
		countSQL = memberCountSQL
	default:
		countSQL = inviteCountSQL
	}

	if err := pm.db.QueryRowContext(ctx, countSQL, args...).Scan(&page.TotalCount); err != nil {
		return nil, err
	}
	if page.TotalCount == 0 {
		return page, nil
	}
	if page.Offset > page.TotalCount-1 {
		return nil, errs.New("page is out of range")
	}

	var unionSQL string
	switch {
	case filters.includeMembers && filters.includeInvites:
		unionSQL = memberSelect + " UNION ALL " + inviteSelect
	case filters.includeMembers:
		unionSQL = memberSelect
	default:
		unionSQL = inviteSelect
	}

	limitParam := nextArg()
	offsetParam := nextArg()
	listArgs := append(append([]any{}, args...), page.Limit, page.Offset)

	membersQuery := fmt.Sprintf(`
		SELECT member_id, project_id, role, created_at, email, inviter_id, expires_at FROM (
			%s
		) results
		%s
		LIMIT %s OFFSET %s
	`, unionSQL, projectMembersSortClause(cursor.Order, page.OrderDirection), limitParam, offsetParam)

	rows, err := pm.db.QueryContext(ctx, membersQuery, listArgs...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	if err := scanProjectMemberListRows(rows, page); err != nil {
		return nil, err
	}

	page.PageCount = uint(page.TotalCount / uint64(cursor.Limit))
	if page.TotalCount%uint64(cursor.Limit) != 0 {
		page.PageCount++
	}
	page.CurrentPage = cursor.Page
	return page, nil
}

func (pm *projectMembers) getPagedSpanner(
	ctx context.Context,
	projectID uuid.UUID,
	cursor console.ProjectMembersCursor,
	page *console.ProjectMembersPage,
	search string,
	filters projectMemberListFilters,
	expireCutoff time.Time,
) (*console.ProjectMembersPage, error) {
	// Spanner uses named args; build compatible filtered UNION similar to Postgres.
	memberWhere := `
		pm.project_id = @project_id
		AND (
			LOWER(u.email) LIKE LOWER(@search) OR
			LOWER(u.full_name) LIKE LOWER(@search) OR
			LOWER(u.short_name) LIKE LOWER(@search)
		)`
	if filters.includeMembers && filters.role != nil {
		switch filters.ownerMode {
		case "include":
			memberWhere += ` AND (pm.role = @role OR pm.member_id = @owner_id)`
		case "exclude":
			memberWhere += ` AND pm.role = @role AND pm.member_id <> @owner_id`
		default:
			memberWhere += ` AND pm.role = @role`
		}
	}

	inviteWhere := `
		project_id = @project_id
		AND LOWER(email) LIKE LOWER(@search)`
	switch filters.inviteStatus {
	case console.ProjectMemberListStatusPending:
		inviteWhere += ` AND NOT ((expires_at IS NOT NULL AND expires_at <= @now) OR (expires_at IS NULL AND created_at <= @expire_cutoff))`
	case console.ProjectMemberListStatusExpired:
		inviteWhere += ` AND ((expires_at IS NOT NULL AND expires_at <= @now) OR (expires_at IS NULL AND created_at <= @expire_cutoff))`
	}
	if filters.vault != "" {
		memberWhere += ` AND EXISTS (
			SELECT 1 FROM member_bucket_grants mbg
			WHERE mbg.project_id = pm.project_id
			  AND mbg.member_id = pm.member_id
			  AND mbg.bucket = @vault
		)`
		inviteWhere += ` AND EXISTS (
			SELECT 1 FROM member_bucket_grants mbg
			WHERE mbg.project_id = project_id
			  AND LOWER(mbg.invite_email) = LOWER(email)
			  AND mbg.member_id IS NULL
			  AND mbg.bucket = @vault
		)`
	}

	named := []any{
		sql.Named("project_id", projectID.Bytes()),
		sql.Named("search", search),
	}
	if filters.includeMembers && filters.role != nil {
		named = append(named, sql.Named("role", int(*filters.role)))
		if filters.ownerID != nil && filters.ownerMode != "" {
			named = append(named, sql.Named("owner_id", filters.ownerID.Bytes()))
		}
	}
	if filters.includeInvites && filters.inviteStatus != "" {
		named = append(named,
			sql.Named("now", filters.now),
			sql.Named("expire_cutoff", expireCutoff),
		)
	}
	if filters.vault != "" {
		named = append(named, sql.Named("vault", filters.vault))
	}

	var countSQL string
	switch {
	case filters.includeMembers && filters.includeInvites:
		countSQL = fmt.Sprintf(`
			WITH pm_cte AS (
				SELECT COUNT(*) AS cnt
				FROM project_members pm
				INNER JOIN users u ON pm.member_id = u.id
				WHERE %s
			),
			pi_cte AS (
				SELECT COUNT(*) AS cnt
				FROM project_invitations
				WHERE %s
			)
			SELECT pi_cte.cnt + pm_cte.cnt FROM pm_cte, pi_cte`, memberWhere, inviteWhere)
	case filters.includeMembers:
		countSQL = fmt.Sprintf(`
			SELECT COUNT(*)
			FROM project_members pm
			INNER JOIN users u ON pm.member_id = u.id
			WHERE %s`, memberWhere)
	default:
		countSQL = fmt.Sprintf(`
			SELECT COUNT(*)
			FROM project_invitations
			WHERE %s`, inviteWhere)
	}

	if err := pm.db.QueryRowContext(ctx, countSQL, named...).Scan(&page.TotalCount); err != nil {
		return nil, err
	}
	if page.TotalCount == 0 {
		return page, nil
	}
	if page.Offset > page.TotalCount-1 {
		return nil, errs.New("page is out of range")
	}

	memberSelect := fmt.Sprintf(`
		SELECT pm.member_id, pm.project_id, pm.role, pm.created_at, u.email, u.full_name, CAST(NULL AS BYTES) as inviter_id, CAST(NULL AS TIMESTAMP) as expires_at
		FROM project_members pm
		INNER JOIN users u ON pm.member_id = u.id
		WHERE %s`, memberWhere)
	inviteSelect := fmt.Sprintf(`
		SELECT CAST(NULL AS BYTES) as member_id, project_id, 1 as role, created_at, LOWER(email) as email, LOWER(SPLIT(email, '@')[OFFSET(0)]) as full_name, inviter_id, expires_at
		FROM project_invitations pi
		WHERE %s`, inviteWhere)

	var unionSQL string
	switch {
	case filters.includeMembers && filters.includeInvites:
		unionSQL = memberSelect + " UNION ALL " + inviteSelect
	case filters.includeMembers:
		unionSQL = memberSelect
	default:
		unionSQL = inviteSelect
	}

	listNamed := append(append([]any{}, named...),
		sql.Named("limit", int64(page.Limit)),
		sql.Named("offset", int64(page.Offset)),
	)

	membersQuery := fmt.Sprintf(`
		SELECT member_id, project_id, role, created_at, email, inviter_id, expires_at FROM (
			%s
		) results
		%s
		LIMIT @limit OFFSET @offset
	`, unionSQL, projectMembersSortClause(cursor.Order, page.OrderDirection))

	rows, err := pm.db.QueryContext(ctx, membersQuery, listNamed...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	if err := scanProjectMemberListRows(rows, page); err != nil {
		return nil, err
	}

	page.PageCount = uint(page.TotalCount / uint64(cursor.Limit))
	if page.TotalCount%uint64(cursor.Limit) != 0 {
		page.PageCount++
	}
	page.CurrentPage = cursor.Page
	return page, nil
}

func scanProjectMemberListRows(rows tagsql.Rows, page *console.ProjectMembersPage) error {
	for rows.Next() {
		var (
			memberID  uuid.NullUUID
			projectID uuid.UUID
			role      console.ProjectMemberRole
			createdAt time.Time
			email     string
			inviterID uuid.NullUUID
			expiresAt sql.NullTime
		)

		err := rows.Scan(
			&memberID,
			&projectID,
			&role,
			&createdAt,
			&email,
			&inviterID,
			&expiresAt,
		)
		if err != nil {
			return err
		}

		if memberID.Valid {
			page.ProjectMembers = append(page.ProjectMembers, console.ProjectMember{
				MemberID:  memberID.UUID,
				ProjectID: projectID,
				Role:      role,
				CreatedAt: createdAt,
			})
			continue
		}

		invite := console.ProjectInvitation{
			ProjectID: projectID,
			Email:     email,
			CreatedAt: createdAt,
		}
		if inviterID.Valid {
			invite.InviterID = &inviterID.UUID
		}
		if expiresAt.Valid {
			t := expiresAt.Time
			invite.ExpiresAt = &t
		}
		page.ProjectInvitations = append(page.ProjectInvitations, invite)
	}
	return rows.Err()
}

// Insert is a method for inserting project member into the database.
func (pm *projectMembers) Insert(ctx context.Context, memberID, projectID uuid.UUID, role console.ProjectMemberRole) (_ *console.ProjectMember, err error) {
	defer mon.Task()(&ctx)(&err)
	createdProjectMember, err := pm.db.Create_ProjectMember(ctx,
		dbx.ProjectMember_MemberId(memberID[:]),
		dbx.ProjectMember_ProjectId(projectID[:]),
		dbx.ProjectMember_Create_Fields{
			Role: dbx.ProjectMember_Role(int(role)),
		},
	)
	if err != nil {
		return nil, err
	}

	return projectMemberFromDBX(ctx, createdProjectMember)
}

// Delete is a method for deleting project member by memberID and projectID from the database.
func (pm *projectMembers) Delete(ctx context.Context, memberID, projectID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = pm.db.Delete_ProjectMember_By_MemberId_And_ProjectId(
		ctx,
		dbx.ProjectMember_MemberId(memberID[:]),
		dbx.ProjectMember_ProjectId(projectID[:]),
	)

	return err
}

// projectMemberFromDBX is used for creating ProjectMember entity from autogenerated dbx.ProjectMember struct.
func projectMemberFromDBX(ctx context.Context, projectMember *dbx.ProjectMember) (_ *console.ProjectMember, err error) {
	defer mon.Task()(&ctx)(&err)
	if projectMember == nil {
		return nil, errs.New("projectMember parameter is nil")
	}

	memberID, err := uuid.FromBytes(projectMember.MemberId)
	if err != nil {
		return nil, err
	}

	projectID, err := uuid.FromBytes(projectMember.ProjectId)
	if err != nil {
		return nil, err
	}

	return &console.ProjectMember{
		MemberID:  memberID,
		ProjectID: projectID,
		Role:      console.ProjectMemberRole(projectMember.Role),
		CreatedAt: projectMember.CreatedAt,
	}, nil
}

// projectMembersSortClause returns what ORDER BY clause should be used when sorting project member results.
func projectMembersSortClause(order console.ProjectMemberOrder, direction console.OrderDirection) string {
	dirStr := "ASC"
	if direction == console.Descending {
		dirStr = "DESC"
	}

	switch order {
	case console.Email:
		return "ORDER BY LOWER(email) " + dirStr
	case console.Created:
		return "ORDER BY created_at " + dirStr + ", LOWER(email)"
	}
	return "ORDER BY LOWER(full_name) " + dirStr + ", LOWER(email)"
}

// projectMembersFromDbxSlice is used for creating []ProjectMember entities from autogenerated []*dbx.ProjectMember struct.
func projectMembersFromDbxSlice(ctx context.Context, projectMembersDbx []*dbx.ProjectMember) (_ []console.ProjectMember, err error) {
	defer mon.Task()(&ctx)(&err)
	rs, errors := slices2.ConvertErrs(projectMembersDbx,
		func(v *dbx.ProjectMember) (r console.ProjectMember, _ error) {
			p, err := projectMemberFromDBX(ctx, v)
			if err != nil {
				return r, err
			}
			return *p, err
		})
	return rs, errs.Combine(errors...)
}
