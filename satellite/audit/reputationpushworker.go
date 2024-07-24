package audit

import (
	"context"
	"time"

	"github.com/go-stack/stack"
	"go.uber.org/zap"
	"storj.io/common/storj"
	"storj.io/common/sync2"
)

type NodeReputation interface {
	GetAll(ctx context.Context) (reputations []NodeReputationEntry, err error)
}

type NodeReputationEntry struct {
	// NodeID is the unique identifier of the node.
	NodeID storj.NodeID
	// && reputation.NodeID, &reputation.Wallet, &reputation.Disqualified,
	// &reputation.ExitInitiatedAt, &reputation.ExitFinishedAt, &reputation.ExitSuccess,
	// &reputation.UnderReview, &reputation.AuditReputationAlpha
	Wallet               string
	Disqualified         *bool
	ExitInitiatedAt      *time.Time
	ExitFinishedAt       *time.Time
	ExitSuccess          *bool
	UnderReview          *bool
	AuditReputationAlpha float64
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
		if err != nil {
			worker.log.Error("failure processing reputation push", zap.Error(err))
		}
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

	reputations, err := worker.db.GetAll(ctx)
	if err != nil {
		return err
	}

	for _, reputation := range reputations {
		var isStaker bool

		reputationVal := int64(reputation.AuditReputationAlpha) * 5
		if reputation.Disqualified != nil && *reputation.Disqualified {
			reputationVal = 0
		}

		isStaker, err = worker.connector.IsStaker(ctx, reputation.Wallet)
		if err != nil {
			worker.log.Error("failed to check if wallet is staker", zap.Error(err))
			continue
		}

		if isStaker {
			err = worker.connector.PushReputation(ctx, reputation.Wallet, reputationVal)
			if err != nil {
				worker.log.Error("failed to push reputation", zap.Error(err))
				continue
			}
		} else {
			err = worker.connector.AddStaker(ctx, reputation.Wallet, reputationVal)
			if err != nil {
				worker.log.Error("failed to add staker", zap.Error(err))
				continue
			}
		}
	}

	worker.log.Info("ReputationPushWorker processed reputations", zap.Int("count", len(reputations)))

	return nil
}

// Close halts the worker.
func (worker *ReputationPushWorker) Close() error {
	worker.Loop.Close()
	return nil
}
