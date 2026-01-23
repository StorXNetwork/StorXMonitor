// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"fmt"

	"storj.io/common/storj"
	"storj.io/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

const (
// VerifyRetryInterval defines a limit on how frequently we retry
// verification audits. At least this long should elapse between
// attempts.
// VerifyRetryInterval = 4 * time.Hour
)

// nodeReputation implements github.com/StorXNetwork/StorXMonitor/satellite/audit.NodeReputation.
type nodeReputation struct {
	db *satelliteDB
}

var _ audit.NodeReputation = (*nodeReputation)(nil)

func (nr *nodeReputation) GetAll(ctx context.Context) (reputations []audit.NodeReputationEntry, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := nr.db.Query(ctx, `SELECT n.id, n.wallet, n.disqualified, n.exit_initiated_at, n.exit_finished_at,
										n.exit_success, n.under_review, n.inactive, r.audit_reputation_alpha, r.disqualified,
										n.piece_count, n.last_contact_success
                                    FROM reputations r
                                    INNER JOIN nodes n on n.id = r.id;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var reputation audit.NodeReputationEntry
		err = rows.Scan(&reputation.NodeID, &reputation.Wallet, &reputation.Disqualified,
			&reputation.ExitInitiatedAt, &reputation.ExitFinishedAt, &reputation.ExitSuccess,
			&reputation.UnderReview, &reputation.Inactive, &reputation.AuditReputationAlpha,
			&reputation.Disqualified, &reputation.PieceCount, &reputation.LastContactSuccess)
		if err != nil {
			return nil, err
		}
		reputations = append(reputations, reputation)
	}

	return reputations, nil
}

func (nr *nodeReputation) NodeSmartContractStatus(ctx context.Context, wallet, msgType, msg string) (err error) {
	defer mon.Task()(&ctx)(&err)

	id, err := uuid.New()
	if err != nil {
		return fmt.Errorf("failed to generate uuid: %v", err)
	}

	err = nr.db.CreateNoReturn_NodeSmartContractUpdates(ctx,
		dbx.NodeSmartContractUpdates_Id(id[:]),
		dbx.NodeSmartContractUpdates_Wallet(wallet),
		dbx.NodeSmartContractUpdates_Message(msg),
		dbx.NodeSmartContractUpdates_MessageType(msgType),
	)
	if err != nil {
		return fmt.Errorf("failed to create node smart contract update: %v", err)
	}

	return nil
}

// ActivateNode activates a node in the database.
func (nr *nodeReputation) ActivateNode(ctx context.Context, nodeID storj.NodeID) error {
	_, err := nr.db.Update_Node_By_Id(ctx, dbx.Node_Id(nodeID[:]), dbx.Node_Update_Fields{
		Inactive: dbx.Node_Inactive(false),
	})

	return err
}
