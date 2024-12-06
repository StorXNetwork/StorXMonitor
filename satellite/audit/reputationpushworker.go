package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/go-stack/stack"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"storj.io/common/storj"
	"storj.io/common/sync2"
)

type NodeReputation interface {
	GetAll(ctx context.Context) (reputations []NodeReputationEntry, err error)
	NodeStmartContractStatus(ctx context.Context, wallet, msgType, msg string) (err error)
	ActivateNode(ctx context.Context, nodeID storj.NodeID) error
}

type NodeReputationEntry struct {
	// NodeID is the unique identifier of the node.
	NodeID storj.NodeID
	// && reputation.NodeID, &reputation.Wallet, &reputation.Disqualified,
	// &reputation.ExitInitiatedAt, &reputation.ExitFinishedAt, &reputation.ExitSuccess,
	// &reputation.UnderReview, &reputation.AuditReputationAlpha
	Wallet               string
	Disqualified         *time.Time
	ExitInitiatedAt      *time.Time
	ExitFinishedAt       *time.Time
	ExitSuccess          *bool
	UnderReview          *time.Time
	AuditReputationAlpha float64
	Inactive             bool
}

// ReputationPushWorker fetch reputation from node database and push that in smart contract.
type ReputationPushWorker struct {
	log *zap.Logger
	db  NodeReputation

	Loop *sync2.Cycle

	connector ReputationConnector
}

type ReputationConnector interface {
	IsStaker(ctx context.Context, wallet string) (bool, error)
	PushReputation(ctx context.Context, wallet string, reputation int64) error
	AddStaker(ctx context.Context, wallet string, reputation int64) error
	GetReputation(ctx context.Context, wallet string) (int64, error)
}

func NewReputationPushWorker(log *zap.Logger, db NodeReputation, connector ReputationConnector) *ReputationPushWorker {
	return &ReputationPushWorker{
		log:       log,
		db:        db,
		Loop:      sync2.NewCycle(time.Hour * 4),
		connector: connector,
	}
}

func (worker *ReputationPushWorker) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	worker.log.Info("ReputationPushWorker started")

	return worker.Loop.Run(ctx, func(ctx context.Context) (err error) {
		err = worker.process(ctx)
		if err == nil {
			return nil
		}

		worker.log.Error("failure processing reputation push", zap.Error(err))

		return nil
	})
}

func (worker *ReputationPushWorker) process(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	defer func() {
		if err := recover(); err != nil {
			worker.log.Error("panic in reputation push worker", zap.Any("error", err))
			worker.log.Error("stack", zap.String("stack", stack.Trace().String()))
		}
	}()

	worker.log.Info("fetch list of nodes with reputation")
	reputations, err := worker.db.GetAll(ctx)
	if err != nil {
		worker.log.Error("failed to get all reputations", zap.Error(err))
		return err
	}

	var smartContractErr errs.Group
	for _, reputation := range reputations {
		func() {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()

			var isStaker bool

			worker.log.Info("processing reputation", zap.String("wallet", reputation.Wallet), zap.Float64("reputation", reputation.AuditReputationAlpha))
			reputationVal := int64(reputation.AuditReputationAlpha) * 5
			if (reputation.Disqualified != nil && !(*reputation.Disqualified).IsZero()) ||
				(reputation.ExitInitiatedAt != nil && reputation.ExitInitiatedAt.IsZero()) ||
				(reputation.ExitFinishedAt != nil && reputation.ExitFinishedAt.IsZero()) ||
				(reputation.ExitSuccess != nil && *reputation.ExitSuccess) ||
				(reputation.UnderReview != nil && !(*reputation.UnderReview).IsZero()) {
				worker.log.Info("disqualified node", zap.String("wallet", reputation.Wallet), zap.Time("disqualified", *reputation.Disqualified))
				reputationVal = 0
			}

			worker.log.Info("checking if wallet is staker", zap.String("wallet", reputation.Wallet))
			isStaker, err = worker.connector.IsStaker(ctx, reputation.Wallet)
			if err != nil {
				worker.log.Error("failed to check if wallet is staker", zap.Error(err))
				worker.db.NodeStmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to check if wallet is staker: %v", err))
				return
			}

			if isStaker {

				worker.log.Info("pushing reputation", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
				err = worker.connector.PushReputation(ctx, reputation.Wallet, reputationVal)
				if err != nil {
					worker.log.Error("failed to push reputation", zap.Error(err))
					err = worker.db.NodeStmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to push reputation: %v", err))
					smartContractErr.Add(err)
					return
				}
				worker.log.Info("pushed reputation", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
				err = worker.db.NodeStmartContractStatus(ctx, reputation.Wallet, "info", fmt.Sprintf("pushed reputation: %v", reputationVal))
				smartContractErr.Add(err)
			} else {
				worker.log.Info("adding staker", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
				err = worker.connector.AddStaker(ctx, reputation.Wallet, reputationVal)
				if err != nil {
					worker.log.Error("failed to add staker", zap.Error(err))
					err = worker.db.NodeStmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to add staker: %v", err))
					smartContractErr.Add(err)
					return
				}
				worker.log.Info("added staker", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
				err = worker.db.NodeStmartContractStatus(ctx, reputation.Wallet, "info", fmt.Sprintf("added staker: %v", reputationVal))
				smartContractErr.Add(err)
			}

			if reputation.Inactive {
				// make this node active
				err = worker.db.ActivateNode(ctx, reputation.NodeID)
				if err != nil {
					worker.log.Error("failed to activate node", zap.Error(err))
					err = worker.db.NodeStmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to activate node: %v", err))
					smartContractErr.Add(err)
					return
				}
			}

			worker.log.Info("processed reputation", zap.String("wallet", reputation.Wallet), zap.Float64("reputation", reputation.AuditReputationAlpha))
		}()
	}

	worker.log.Info("ReputationPushWorker processed reputations", zap.Int("count", len(reputations)))

	return smartContractErr.Err()
}

// Close halts the worker.
func (worker *ReputationPushWorker) Close() error {
	worker.Loop.Close()
	return nil
}
