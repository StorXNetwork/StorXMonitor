// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

var (
	_ console.Organizations = (*organizations)(nil)
	_ console.OrgMembers    = (*orgMembers)(nil)
	_ console.OrgNodes      = (*orgNodes)(nil)
)

type organizations struct {
	db *dbx.DB
}

type orgMembers struct {
	db *dbx.DB
}

type orgNodes struct {
	db *dbx.DB
}

// Create inserts a new organization.
func (o *organizations) Create(ctx context.Context, name string, createdBy uuid.UUID) (org *console.Organization, err error) {
	defer mon.Task()(&ctx)(&err)

	id, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}
	now := time.Now().UTC()
	_, err = o.db.ExecContext(ctx, o.db.Rebind(`
		INSERT INTO organizations (id, name, created_by, created_at) VALUES (?, ?, ?, ?)
	`), id[:], name, createdBy[:], now)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return &console.Organization{
		ID:        id,
		Name:      name,
		CreatedBy: createdBy,
		CreatedAt: now,
	}, nil
}

// Get returns an organization by ID.
func (o *organizations) Get(ctx context.Context, id uuid.UUID) (org *console.Organization, err error) {
	defer mon.Task()(&ctx)(&err)

	row := o.db.QueryRowContext(ctx, o.db.Rebind(`
		SELECT id, name, created_by, created_at FROM organizations WHERE id = ?
	`), id[:])
	orgVal, err := scanOrganization(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrOrgNotFound.New("")
		}
		return nil, Error.Wrap(err)
	}
	return &orgVal, nil
}

// ListByUserID returns organizations the user belongs to.
func (o *organizations) ListByUserID(ctx context.Context, userID uuid.UUID) (orgs []console.Organization, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := o.db.QueryContext(ctx, o.db.Rebind(`
		SELECT o.id, o.name, o.created_by, o.created_at
		FROM organizations o
		INNER JOIN org_members m ON m.org_id = o.id
		WHERE m.user_id = ?
		ORDER BY o.created_at ASC
	`), userID[:])
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errsCombine(err, rows.Close()) }()

	for rows.Next() {
		org, scanErr := scanOrganization(rows)
		if scanErr != nil {
			return nil, Error.Wrap(scanErr)
		}
		orgs = append(orgs, org)
	}
	return orgs, Error.Wrap(rows.Err())
}

// Insert adds a member to an organization.
func (m *orgMembers) Insert(ctx context.Context, orgID, userID uuid.UUID, role string) (member *console.OrgMember, err error) {
	defer mon.Task()(&ctx)(&err)

	now := time.Now().UTC()
	_, err = m.db.ExecContext(ctx, m.db.Rebind(`
		INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)
	`), orgID[:], userID[:], role, now)
	if err != nil {
		if dbx.IsConstraintError(err) {
			return nil, console.ErrOrgInvalid.New("user is already a member of this organization")
		}
		return nil, Error.Wrap(err)
	}
	return &console.OrgMember{
		OrgID:     orgID,
		UserID:    userID,
		Role:      role,
		CreatedAt: now,
	}, nil
}

// Get returns a membership row.
func (m *orgMembers) Get(ctx context.Context, orgID, userID uuid.UUID) (member *console.OrgMember, err error) {
	return m.GetMembership(ctx, orgID, userID)
}

// GetMembership returns a membership row.
func (m *orgMembers) GetMembership(ctx context.Context, orgID, userID uuid.UUID) (member *console.OrgMember, err error) {
	defer mon.Task()(&ctx)(&err)

	row := m.db.QueryRowContext(ctx, m.db.Rebind(`
		SELECT org_id, user_id, role, created_at FROM org_members WHERE org_id = ? AND user_id = ?
	`), orgID[:], userID[:])
	mem, err := scanOrgMember(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrOrgForbidden.New("not a member of this organization")
		}
		return nil, Error.Wrap(err)
	}
	return &mem, nil
}

// ListByOrgID returns all members of an organization.
func (m *orgMembers) ListByOrgID(ctx context.Context, orgID uuid.UUID) (members []console.OrgMember, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := m.db.QueryContext(ctx, m.db.Rebind(`
		SELECT org_id, user_id, role, created_at FROM org_members WHERE org_id = ? ORDER BY created_at ASC
	`), orgID[:])
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errsCombine(err, rows.Close()) }()

	for rows.Next() {
		mem, scanErr := scanOrgMember(rows)
		if scanErr != nil {
			return nil, Error.Wrap(scanErr)
		}
		members = append(members, mem)
	}
	return members, Error.Wrap(rows.Err())
}

// Delete removes a member from an organization.
func (m *orgMembers) Delete(ctx context.Context, orgID, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	res, err := m.db.ExecContext(ctx, m.db.Rebind(`
		DELETE FROM org_members WHERE org_id = ? AND user_id = ?
	`), orgID[:], userID[:])
	if err != nil {
		return Error.Wrap(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Error.Wrap(err)
	}
	if n == 0 {
		return console.ErrOrgNotFound.New("member not found")
	}
	return nil
}

// CountAdmins returns the number of admin members in an organization.
func (m *orgMembers) CountAdmins(ctx context.Context, orgID uuid.UUID) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	err = m.db.QueryRowContext(ctx, m.db.Rebind(`
		SELECT COUNT(*) FROM org_members WHERE org_id = ? AND role = ?
	`), orgID[:], console.OrgRoleAdmin).Scan(&count)
	return count, Error.Wrap(err)
}

// Insert claims a node for an organization.
// Idempotent for check-in: if the node is already claimed (same or other org),
// returns ErrOrgNodeAlreadyClaimed instead of a raw unique-violation error.
// Plain INSERT (no ON CONFLICT) so Postgres, Cockroach, and Spanner all work.
func (n *orgNodes) Insert(ctx context.Context, orgID uuid.UUID, nodeID storxnetwork.NodeID, claimedBy uuid.UUID) (node *console.OrgNode, err error) {
	defer mon.Task()(&ctx)(&err)

	now := time.Now().UTC()
	_, err = n.db.ExecContext(ctx, n.db.Rebind(`
		INSERT INTO org_nodes (org_id, node_id, claimed_by, created_at) VALUES (?, ?, ?, ?)
	`), orgID[:], nodeID.Bytes(), claimedBy[:], now)
	if err != nil {
		if isOrgNodeUniqueViolation(err) {
			return nil, console.ErrOrgNodeAlreadyClaimed.New("node already claimed")
		}
		return nil, Error.Wrap(err)
	}
	return &console.OrgNode{
		OrgID:     orgID,
		NodeID:    nodeID,
		ClaimedBy: claimedBy,
		CreatedAt: now,
	}, nil
}

func isOrgNodeUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if dbx.IsConstraintError(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "23505")
}

// Delete removes an org node claim.
func (n *orgNodes) Delete(ctx context.Context, orgID uuid.UUID, nodeID storxnetwork.NodeID) (err error) {
	defer mon.Task()(&ctx)(&err)

	res, err := n.db.ExecContext(ctx, n.db.Rebind(`
		DELETE FROM org_nodes WHERE org_id = ? AND node_id = ?
	`), orgID[:], nodeID.Bytes())
	if err != nil {
		return Error.Wrap(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Error.Wrap(err)
	}
	if affected == 0 {
		return console.ErrOrgNodeNotFound.New("")
	}
	return nil
}

// ListByOrgID returns all nodes claimed by an organization.
func (n *orgNodes) ListByOrgID(ctx context.Context, orgID uuid.UUID) (nodes []console.OrgNode, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := n.db.QueryContext(ctx, n.db.Rebind(`
		SELECT org_id, node_id, claimed_by, created_at
		FROM org_nodes WHERE org_id = ? ORDER BY created_at ASC
	`), orgID[:])
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errsCombine(err, rows.Close()) }()

	for rows.Next() {
		node, scanErr := scanOrgNode(rows)
		if scanErr != nil {
			return nil, Error.Wrap(scanErr)
		}
		nodes = append(nodes, node)
	}
	return nodes, Error.Wrap(rows.Err())
}

// GetNodeIDsByOrgID returns node IDs claimed by an organization.
func (n *orgNodes) GetNodeIDsByOrgID(ctx context.Context, orgID uuid.UUID) (ids []storxnetwork.NodeID, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := n.db.QueryContext(ctx, n.db.Rebind(`
		SELECT node_id FROM org_nodes WHERE org_id = ? ORDER BY created_at ASC
	`), orgID[:])
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errsCombine(err, rows.Close()) }()

	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, Error.Wrap(err)
		}
		id, err := storxnetwork.NodeIDFromBytes(raw)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		ids = append(ids, id)
	}
	return ids, Error.Wrap(rows.Err())
}

// GetByNodeID returns the org claim for a node, if any.
func (n *orgNodes) GetByNodeID(ctx context.Context, nodeID storxnetwork.NodeID) (node *console.OrgNode, err error) {
	defer mon.Task()(&ctx)(&err)

	row := n.db.QueryRowContext(ctx, n.db.Rebind(`
		SELECT org_id, node_id, claimed_by, created_at FROM org_nodes WHERE node_id = ?
	`), nodeID.Bytes())
	nodeVal, err := scanOrgNode(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrOrgNodeNotFound.New("")
		}
		return nil, Error.Wrap(err)
	}
	return &nodeVal, nil
}

// CountByOrgID returns how many nodes an organization has claimed.
func (n *orgNodes) CountByOrgID(ctx context.Context, orgID uuid.UUID) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	err = n.db.QueryRowContext(ctx, n.db.Rebind(`
		SELECT COUNT(*) FROM org_nodes WHERE org_id = ?
	`), orgID[:]).Scan(&count)
	return count, Error.Wrap(err)
}

// AllNodeIDs returns every org-claimed node ID.
func (n *orgNodes) AllNodeIDs(ctx context.Context) (ids []storxnetwork.NodeID, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := n.db.QueryContext(ctx, `SELECT DISTINCT node_id FROM org_nodes`)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errsCombine(err, rows.Close()) }()

	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, Error.Wrap(err)
		}
		id, err := storxnetwork.NodeIDFromBytes(raw)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		ids = append(ids, id)
	}
	return ids, Error.Wrap(rows.Err())
}

// NodeExists reports whether the node is present in the overlay nodes table.
func (n *orgNodes) NodeExists(ctx context.Context, nodeID storxnetwork.NodeID) (exists bool, operatorEmail string, err error) {
	defer mon.Task()(&ctx)(&err)

	err = n.db.QueryRowContext(ctx, n.db.Rebind(`
		SELECT email FROM nodes WHERE id = ?
	`), nodeID.Bytes()).Scan(&operatorEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil
		}
		return false, "", Error.Wrap(err)
	}
	return true, strings.TrimSpace(operatorEmail), nil
}

// CountOnlineByOrgID counts org nodes with recent last_contact_success.
func (n *orgNodes) CountOnlineByOrgID(ctx context.Context, orgID uuid.UUID, onlineWindow time.Duration) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	if onlineWindow <= 0 {
		onlineWindow = 4 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-onlineWindow)
	err = n.db.QueryRowContext(ctx, n.db.Rebind(`
		SELECT COUNT(*)
		FROM org_nodes o
		INNER JOIN nodes n ON n.id = o.node_id
		WHERE o.org_id = ?
		  AND n.last_contact_success > ?
		  AND n.disqualified IS NULL
		  AND n.exit_finished_at IS NULL
	`), orgID[:], cutoff).Scan(&count)
	return count, Error.Wrap(err)
}

func scanOrganization(row scannable) (console.Organization, error) {
	var (
		idRaw, createdByRaw []byte
		name                string
		createdAt           time.Time
	)
	if err := row.Scan(&idRaw, &name, &createdByRaw, &createdAt); err != nil {
		return console.Organization{}, err
	}
	id, err := uuid.FromBytes(idRaw)
	if err != nil {
		return console.Organization{}, err
	}
	createdBy, err := uuid.FromBytes(createdByRaw)
	if err != nil {
		return console.Organization{}, err
	}
	return console.Organization{
		ID:        id,
		Name:      name,
		CreatedBy: createdBy,
		CreatedAt: createdAt,
	}, nil
}

func scanOrgMember(row scannable) (console.OrgMember, error) {
	var (
		orgIDRaw, userIDRaw []byte
		role                string
		createdAt           time.Time
	)
	if err := row.Scan(&orgIDRaw, &userIDRaw, &role, &createdAt); err != nil {
		return console.OrgMember{}, err
	}
	orgID, err := uuid.FromBytes(orgIDRaw)
	if err != nil {
		return console.OrgMember{}, err
	}
	userID, err := uuid.FromBytes(userIDRaw)
	if err != nil {
		return console.OrgMember{}, err
	}
	return console.OrgMember{
		OrgID:     orgID,
		UserID:    userID,
		Role:      role,
		CreatedAt: createdAt,
	}, nil
}

func scanOrgNode(row scannable) (console.OrgNode, error) {
	var (
		orgIDRaw, claimedByRaw, nodeIDRaw []byte
		createdAt                         time.Time
	)
	if err := row.Scan(&orgIDRaw, &nodeIDRaw, &claimedByRaw, &createdAt); err != nil {
		return console.OrgNode{}, err
	}
	orgID, err := uuid.FromBytes(orgIDRaw)
	if err != nil {
		return console.OrgNode{}, err
	}
	claimedBy, err := uuid.FromBytes(claimedByRaw)
	if err != nil {
		return console.OrgNode{}, err
	}
	nodeID, err := storxnetwork.NodeIDFromBytes(nodeIDRaw)
	if err != nil {
		return console.OrgNode{}, err
	}
	return console.OrgNode{
		OrgID:     orgID,
		NodeID:    nodeID,
		ClaimedBy: claimedBy,
		CreatedAt: createdAt,
	}, nil
}
