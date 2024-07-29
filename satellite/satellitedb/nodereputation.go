// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"fmt"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/audit"
	"storj.io/storj/satellite/satellitedb/dbx"
)

const (
// VerifyRetryInterval defines a limit on how frequently we retry
// verification audits. At least this long should elapse between
// attempts.
// VerifyRetryInterval = 4 * time.Hour
)

// nodeReputation implements storj.io/storj/satellite/audit.NodeReputation.
type nodeReputation struct {
	db *satelliteDB
}

var _ audit.NodeReputation = (*nodeReputation)(nil)

func (nr *nodeReputation) GetAll(ctx context.Context) (reputations []audit.NodeReputationEntry, err error) {

	rows, err := nr.db.Query(ctx, `SELECT n.id, n.wallet, n.disqualified, n.exit_initiated_at, n.exit_finished_at, n.exit_success, n.under_review, r.audit_reputation_alpha, r.disqualified
					FROM "satellite/0".reputations r
					INNER JOIN "satellite/0".nodes n on n.id = r.id;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var reputation audit.NodeReputationEntry
		err = rows.Scan(&reputation.NodeID, &reputation.Wallet, &reputation.Disqualified,
			&reputation.ExitInitiatedAt, &reputation.ExitFinishedAt, &reputation.ExitSuccess,
			&reputation.UnderReview, &reputation.AuditReputationAlpha, &reputation.Disqualified)
		if err != nil {
			return nil, err
		}
		reputations = append(reputations, reputation)
	}

	return reputations, nil
}

func (nr *nodeReputation) NodeStmartContractStatus(ctx context.Context, wallet, msgType, msg string) (err error) {
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
