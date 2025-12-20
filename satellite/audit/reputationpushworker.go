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
	NodeSmartContractStatus(ctx context.Context, wallet, msgType, msg string) (err error)
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
	LastContactSuccess   *time.Time
	ExitInitiatedAt      *time.Time
	ExitFinishedAt       *time.Time
	ExitSuccess          *bool
	UnderReview          *time.Time
	AuditReputationAlpha float64
	PieceCount           int64
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
		Loop:      sync2.NewCycle(time.Hour * 24),
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
		mon.Counter("reputation_push_worker_get_all_failures").Inc(1) //mon:locked
		return err
	}

	mon.IntVal("reputation_push_worker_total_nodes").Observe(int64(len(reputations))) //mon:locked
	mon.Counter("reputation_push_worker_get_all_successes").Inc(1)                    //mon:locked

	var smartContractErr errs.Group
	for _, reputation := range reputations {
		if ctx.Err() != nil {
			worker.log.Error("context cancelled", zap.Error(ctx.Err()))
			return ctx.Err()
		}

		err = worker.processReputation(ctx, reputation)
		smartContractErr.Add(err)

	}

	worker.log.Info("ReputationPushWorker processed reputations", zap.Int("count", len(reputations)))
	mon.IntVal("reputation_push_worker_processed_reputations").Observe(int64(len(reputations))) //mon:locked

	if smartContractErr.Err() != nil {
		mon.Counter("reputation_push_worker_processing_errors").Inc(1) //mon:locked
	} else {
		mon.Counter("reputation_push_worker_processing_successes").Inc(1) //mon:locked
	}

	return smartContractErr.Err()
}

// processReputation processes a single reputation entry and pushes it to the smart contract.
func (worker *ReputationPushWorker) processReputation(ctx context.Context, reputation NodeReputationEntry) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	worker.log.Info("processing reputation", zap.String("wallet", reputation.Wallet), zap.Float64("reputation", reputation.AuditReputationAlpha))

	reputationVal := worker.calculateReputationValue(reputation)

	// Handle inactive nodes: add as staker if needed and activate the node
	if reputation.Inactive {
		shouldContinue, err := worker.handleInactiveNode(ctx, reputation, reputationVal)
		if err != nil {
			return err
		}
		if !shouldContinue {
			return nil
		}
	}

	// Push reputation to contract if needed
	if err := worker.pushReputationIfNeeded(ctx, reputation, reputationVal); err != nil {
		return err
	}

	time.Sleep(time.Minute) // if we are calling smart contract, we need to wait for some time. just for safety

	worker.log.Info("processed reputation", zap.String("wallet", reputation.Wallet), zap.Float64("reputation", reputation.AuditReputationAlpha))
	return nil
}

// calculateReputationValue calculates the reputation value based on audit reputation and node status.
func (worker *ReputationPushWorker) calculateReputationValue(reputation NodeReputationEntry) int64 {
	reputationVal := int64(reputation.AuditReputationAlpha) * 5
	mon.IntVal("reputation_push_worker_processing_nodes").Observe(1)             //mon:locked
	mon.IntVal("reputation_push_worker_reputation_value").Observe(reputationVal) //mon:locked

	// Check if node is disqualified
	if worker.isNodeDisqualified(reputation) {
		worker.log.Info("disqualified node", zap.String("wallet", reputation.Wallet))
		mon.Counter("reputation_push_worker_disqualified_nodes").Inc(1) //mon:locked
		return 0
	}

	// Check if node is inactive (no recent contact or no pieces)
	if worker.isNodeInactive(reputation) {
		worker.log.Info("node is inactive", zap.String("wallet", reputation.Wallet))
		mon.Counter("reputation_push_worker_inactive_nodes").Inc(1) //mon:locked
		return 5                                                    // default reputation value
	}

	return reputationVal
}

// isNodeDisqualified checks if a node is disqualified based on various status flags.
func (worker *ReputationPushWorker) isNodeDisqualified(reputation NodeReputationEntry) bool {
	return (reputation.Disqualified != nil && !(*reputation.Disqualified).IsZero()) ||
		(reputation.ExitInitiatedAt != nil && reputation.ExitInitiatedAt.IsZero()) ||
		(reputation.ExitFinishedAt != nil && reputation.ExitFinishedAt.IsZero()) ||
		(reputation.ExitSuccess != nil && *reputation.ExitSuccess) ||
		(reputation.UnderReview != nil && !(*reputation.UnderReview).IsZero())
}

// isNodeInactive checks if a node is considered inactive.
func (worker *ReputationPushWorker) isNodeInactive(reputation NodeReputationEntry) bool {
	return reputation.LastContactSuccess == nil ||
		reputation.PieceCount == 0 ||
		reputation.LastContactSuccess.Before(time.Now().Add(-time.Hour*24*30))
}

// handleInactiveNode handles inactive nodes by checking if they're stakers, adding them if needed, and activating them.
// Returns true if processing should continue, false if it should stop.
func (worker *ReputationPushWorker) handleInactiveNode(ctx context.Context, reputation NodeReputationEntry, reputationVal int64) (shouldContinue bool, err error) {
	worker.log.Info("checking if wallet is staker", zap.String("wallet", reputation.Wallet))
	isStaker, err := worker.connector.IsStaker(ctx, reputation.Wallet)
	if err != nil {
		worker.log.Error("failed to check if wallet is staker", zap.Error(err))
		worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to check if wallet is staker: %v", err))
		return false, err
	}

	// Add staker if not already a staker
	if !isStaker {
		if err := worker.addStaker(ctx, reputation, reputationVal); err != nil {
			return false, err
		}
	}

	// Activate the node
	if err := worker.activateNode(ctx, reputation); err != nil {
		return false, err
	}

	// If we just added a new staker, we're done processing this node
	return isStaker, nil
}

// addStaker adds a wallet as a staker with the given reputation value.
func (worker *ReputationPushWorker) addStaker(ctx context.Context, reputation NodeReputationEntry, reputationVal int64) error {
	worker.log.Info("adding staker", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
	err := worker.connector.AddStaker(ctx, reputation.Wallet, reputationVal)
	if err != nil {
		worker.log.Error("failed to add staker", zap.Error(err))
		mon.Counter("reputation_push_worker_add_staker_failures").Inc(1) //mon:locked
		err = worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to add staker: %v", err))
		return err
	}
	worker.log.Info("added staker", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
	mon.Counter("reputation_push_worker_add_staker_successes").Inc(1) //mon:locked
	err = worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "info", fmt.Sprintf("added staker: %v", reputationVal))
	return err
}

// activateNode activates a node in the database.
func (worker *ReputationPushWorker) activateNode(ctx context.Context, reputation NodeReputationEntry) error {
	err := worker.db.ActivateNode(ctx, reputation.NodeID)
	if err != nil {
		worker.log.Error("failed to activate node", zap.Error(err))
		mon.Counter("reputation_push_worker_activate_node_failures").Inc(1) //mon:locked
		err = worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to activate node: %v", err))
		return err
	}
	mon.Counter("reputation_push_worker_activate_node_successes").Inc(1) //mon:locked
	return nil
}

// pushReputationIfNeeded checks if reputation is already pushed to the contract, and pushes it if needed.
func (worker *ReputationPushWorker) pushReputationIfNeeded(ctx context.Context, reputation NodeReputationEntry, reputationVal int64) error {
	reputationFromContract, err := worker.connector.GetReputation(ctx, reputation.Wallet)
	if err != nil {
		worker.log.Error("failed to get reputation from contract", zap.Error(err))
		return err
	}

	// Skip if reputation is already up to date
	if reputationFromContract == reputationVal {
		worker.log.Info("reputation already pushed", zap.String("wallet", reputation.Wallet), zap.Int64("reputationFromContract", reputationFromContract), zap.Int64("reputation", reputationVal))
		mon.Counter("reputation_push_worker_already_pushed").Inc(1) //mon:locked
		err = worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "info", fmt.Sprintf("reputation already pushed: %v", reputationVal))
		return err
	}

	// Push reputation to contract
	return worker.pushReputation(ctx, reputation, reputationVal)
}

// pushReputation pushes the reputation value to the smart contract.
func (worker *ReputationPushWorker) pushReputation(ctx context.Context, reputation NodeReputationEntry, reputationVal int64) error {
	worker.log.Info("pushing reputation", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
	err := worker.connector.PushReputation(ctx, reputation.Wallet, reputationVal)
	if err != nil {
		worker.log.Error("failed to push reputation", zap.Error(err))
		mon.Counter("reputation_push_worker_push_reputation_failures").Inc(1) //mon:locked
		err = worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "error", fmt.Sprintf("failed to push reputation: %v", err))
		return err
	}
	worker.log.Info("pushed reputation", zap.String("wallet", reputation.Wallet), zap.Int64("reputation", reputationVal))
	mon.Counter("reputation_push_worker_push_reputation_successes").Inc(1) //mon:locked
	err = worker.db.NodeSmartContractStatus(ctx, reputation.Wallet, "info", fmt.Sprintf("pushed reputation: %v", reputationVal))
	return err
}

// Close halts the worker.
func (worker *ReputationPushWorker) Close() error {
	worker.Loop.Close()
	return nil
}
