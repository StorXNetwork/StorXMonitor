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

var _ console.UserNodes = (*userNodes)(nil)

type userNodes struct {
	db *dbx.DB
}

// GetByUserID returns all nodes claimed by the user.
func (u *userNodes) GetByUserID(ctx context.Context, userID uuid.UUID) (nodes []console.UserNode, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := u.db.QueryContext(ctx, u.db.Rebind(`
		SELECT user_id, node_id, created_at
		FROM user_nodes
		WHERE user_id = ?
		ORDER BY created_at ASC
	`), userID[:])
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errsCombine(err, rows.Close()) }()

	for rows.Next() {
		node, scanErr := scanUserNode(rows)
		if scanErr != nil {
			return nil, Error.Wrap(scanErr)
		}
		nodes = append(nodes, node)
	}
	return nodes, Error.Wrap(rows.Err())
}

// GetNodeIDsByUserID returns only the node IDs claimed by the user.
func (u *userNodes) GetNodeIDsByUserID(ctx context.Context, userID uuid.UUID) (ids []storxnetwork.NodeID, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := u.db.QueryContext(ctx, u.db.Rebind(`
		SELECT node_id FROM user_nodes WHERE user_id = ? ORDER BY created_at ASC
	`), userID[:])
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

// GetByNodeID returns the claim for a node, if any.
func (u *userNodes) GetByNodeID(ctx context.Context, nodeID storxnetwork.NodeID) (node *console.UserNode, err error) {
	defer mon.Task()(&ctx)(&err)

	row := u.db.QueryRowContext(ctx, u.db.Rebind(`
		SELECT user_id, node_id, created_at
		FROM user_nodes
		WHERE node_id = ?
	`), nodeID.Bytes())

	n, err := scanUserNode(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrUserNodeNotFound.New("")
		}
		return nil, Error.Wrap(err)
	}
	return &n, nil
}

// Insert creates a claim.
func (u *userNodes) Insert(ctx context.Context, userID uuid.UUID, nodeID storxnetwork.NodeID) (node *console.UserNode, err error) {
	defer mon.Task()(&ctx)(&err)

	now := time.Now().UTC()
	_, err = u.db.ExecContext(ctx, u.db.Rebind(`
		INSERT INTO user_nodes (user_id, node_id, created_at) VALUES (?, ?, ?)
	`), userID[:], nodeID.Bytes(), now)
	if err != nil {
		if dbx.IsConstraintError(err) {
			return nil, console.ErrUserNodeAlreadyClaimed.New("node already claimed")
		}
		return nil, Error.Wrap(err)
	}
	return &console.UserNode{
		UserID:    userID,
		NodeID:    nodeID,
		CreatedAt: now,
	}, nil
}

// Delete removes a claim for the given user and node.
func (u *userNodes) Delete(ctx context.Context, userID uuid.UUID, nodeID storxnetwork.NodeID) (err error) {
	defer mon.Task()(&ctx)(&err)

	res, err := u.db.ExecContext(ctx, u.db.Rebind(`
		DELETE FROM user_nodes WHERE user_id = ? AND node_id = ?
	`), userID[:], nodeID.Bytes())
	if err != nil {
		return Error.Wrap(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Error.Wrap(err)
	}
	if n == 0 {
		return console.ErrUserNodeNotFound.New("")
	}
	return nil
}

// AllNodeIDs returns every claimed node ID.
func (u *userNodes) AllNodeIDs(ctx context.Context) (ids []storxnetwork.NodeID, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := u.db.QueryContext(ctx, `SELECT DISTINCT node_id FROM user_nodes`)
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
func (u *userNodes) NodeExists(ctx context.Context, nodeID storxnetwork.NodeID) (exists bool, operatorEmail string, err error) {
	defer mon.Task()(&ctx)(&err)

	err = u.db.QueryRowContext(ctx, u.db.Rebind(`
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

type scannable interface {
	Scan(dest ...any) error
}

func scanUserNode(row scannable) (console.UserNode, error) {
	var (
		userIDRaw []byte
		nodeIDRaw []byte
		createdAt time.Time
	)
	if err := row.Scan(&userIDRaw, &nodeIDRaw, &createdAt); err != nil {
		return console.UserNode{}, err
	}
	userID, err := uuid.FromBytes(userIDRaw)
	if err != nil {
		return console.UserNode{}, err
	}
	nodeID, err := storxnetwork.NodeIDFromBytes(nodeIDRaw)
	if err != nil {
		return console.UserNode{}, err
	}
	return console.UserNode{
		UserID:    userID,
		NodeID:    nodeID,
		CreatedAt: createdAt,
	}, nil
}

func errsCombine(err error, closeErr error) error {
	if err != nil {
		return err
	}
	return closeErr
}
