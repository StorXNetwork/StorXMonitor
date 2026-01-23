package smartcontract

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
)

// Ensure that web3Helper implements audit.ReputationConnector.
var _ audit.ReputationConnector = (*reputationWeb3Helper)(nil)

//go:embed contract.abi
var reputationABI []byte

type reputationWeb3Helper struct {
	web3Helper *web3Helper
}

func NewReputationWeb3Helper(web3Config Web3Config, privateKey string) (*reputationWeb3Helper, error) {
	web3Helper, err := NewWeb3Helper(web3Config, privateKey)
	if err != nil {
		return nil, err
	}

	parsedABI, err := abi.JSON(bytes.NewReader(reputationABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	web3Helper.abi = parsedABI

	return &reputationWeb3Helper{web3Helper: web3Helper}, nil
}

func (w *reputationWeb3Helper) AddStaker(ctx context.Context, address string, reputation int64) error {
	// Track attempts
	mon.Counter("smartcontract_add_staker_attempts").Inc(1)

	address = updateAddress(address)
	err := w.web3Helper.SubmitTransaction(ctx, "addStaker", common.HexToAddress(address), big.NewInt(reputation))
	if err != nil {
		// Track failures with error type
		mon.Counter("smartcontract_add_staker_failures").Inc(1)

		mon.IntVal("smartcontract_add_staker_reputation_on_error").Observe(reputation)
		return fmt.Errorf("error in GeneralContractMethod with addStaker: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_add_staker_successes").Inc(1)
	mon.IntVal("smartcontract_add_staker_reputation").Observe(reputation)
	return nil
}

func (w *reputationWeb3Helper) PushReputation(ctx context.Context, address string, reputation int64) error {
	// Track attempts
	mon.Counter("smartcontract_push_reputation_attempts").Inc(1)

	address = updateAddress(address)
	err := w.web3Helper.SubmitTransaction(ctx, "setReputation", common.HexToAddress(address), big.NewInt(reputation))
	if err != nil {
		// Track failures with error type
		mon.Counter("smartcontract_push_reputation_failures").Inc(1)

		mon.IntVal("smartcontract_push_reputation_value_on_error").Observe(reputation)
		return fmt.Errorf("error in GeneralContractMethod with setReputation: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_push_reputation_successes").Inc(1)
	mon.IntVal("smartcontract_push_reputation_value").Observe(reputation)
	return nil
}

func (w *reputationWeb3Helper) IsStaker(ctx context.Context, address string) (bool, error) {
	// Track attempts
	mon.Counter("smartcontract_is_staker_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_is_staker_failures").Inc(1)

		return false, fmt.Errorf("web3Helper is nil")
	}

	address = updateAddress(address)

	var isStaker bool
	err := w.web3Helper.GetMethodCallData(ctx, "isStaker", &isStaker, common.HexToAddress(address))
	if err != nil {
		mon.Counter("smartcontract_is_staker_failures").Inc(1)

		return false, fmt.Errorf("error in GetMethodCallData with isStaker: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_is_staker_successes").Inc(1)
	return isStaker, nil
}

func (w *reputationWeb3Helper) GetReputation(ctx context.Context, address string) (int64, error) {
	// Track attempts
	mon.Counter("smartcontract_get_reputation_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_get_reputation_failures").Inc(1)

		return 0, fmt.Errorf("web3Helper is nil")
	}

	address = updateAddress(address)

	var r *big.Int
	err := w.web3Helper.GetMethodCallData(ctx, "getReputation", &r, common.HexToAddress(address))
	if err != nil {
		mon.Counter("smartcontract_get_reputation_failures").Inc(1)

		return 0, fmt.Errorf("error in GetMethodCallData with getReputation: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_get_reputation_successes").Inc(1)
	reputation := r.Int64()
	mon.IntVal("smartcontract_get_reputation_value").Observe(reputation)
	return reputation, nil
}

func updateAddress(address string) string {
	if strings.HasPrefix(address, "0x") {
		return address
	}

	if strings.HasPrefix(address, "xdc") {
		return "0x" + address[3:]
	}

	return "0x" + address
}
