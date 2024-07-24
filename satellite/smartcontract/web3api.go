package smartcontract

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"storj.io/storj/satellite/audit"
)

type Web3Config struct {
	NetworkRPC             string
	ReputationContractAddr string
	NounceAddr             string
	PrivateKey             string
}

type web3Helper struct {
	client                 *ethclient.Client
	abi                    abi.ABI
	nounceAddr             common.Address
	reputationContractAddr common.Address
	stakeContractAddr      common.Address
	privateKey             *ecdsa.PrivateKey
}

// Ensure that web3Helper implements audit.ReputationConnector.
var _ audit.ReputationConnector = (*web3Helper)(nil)

func NewWeb3Helper(cnf Web3Config) (*web3Helper, error) {
	client, err := ethclient.Dial(cnf.NetworkRPC)
	if err != nil {
		return nil, fmt.Errorf("error connecting to the network: %v", err)
	}

	privateKeyECDSA, err := crypto.HexToECDSA(cnf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	return &web3Helper{
		client:                 client,
		nounceAddr:             common.HexToAddress(cnf.NounceAddr),
		reputationContractAddr: common.HexToAddress(cnf.ReputationContractAddr),
		privateKey:             privateKeyECDSA,
	}, nil
}

func (w *web3Helper) SetABI(abiFile io.Reader) error {
	abi, err := getContractABI(abiFile)
	if err != nil {
		return fmt.Errorf("error getting contract ABI: %v", err)
	}

	w.abi = abi
	return nil
}

func (w *web3Helper) getNonce(ctx context.Context) (uint64, error) {
	nonce, err := w.client.PendingNonceAt(ctx, w.nounceAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to get nonce: %v", err)
	}
	return nonce, nil
}

func (w *web3Helper) GeneralContractMethod(ctx context.Context, addr common.Address, method string, params ...interface{}) error {

	data, err := w.abi.Pack(method, params...)
	if err != nil {
		return fmt.Errorf("error packing method call: %v", err)
	}

	gasPrice, err := w.client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("error suggesting gas price: %v", err)
	}

	nonceCount, err := w.getNonce(ctx)
	if err != nil {
		return fmt.Errorf("error getting nonce: %v", err)
	}

	tx := types.NewTransaction(nonceCount, addr, big.NewInt(0), uint64(300000), gasPrice, data)

	chainID, err := w.client.NetworkID(ctx)
	if err != nil {
		return fmt.Errorf("error getting network ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), w.privateKey)
	if err != nil {
		return fmt.Errorf("error signing transaction: %v", err)
	}

	err = w.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("error sending transaction: %v", err)
	}

	receipt, err := bind.WaitMined(ctx, w.client, signedTx)
	if err != nil {
		return fmt.Errorf("error waiting for transaction to be mined: %v", err)
	}

	if receipt.Status == types.ReceiptStatusFailed {
		return fmt.Errorf("transaction failed with status %v", receipt.Status)
	}

	return nil
}

func (w *web3Helper) AddStaker(ctx context.Context, address string, reputation int64) error {

	err := w.GeneralContractMethod(ctx, w.reputationContractAddr, "addStaker", common.HexToAddress(address), big.NewInt(reputation))
	if err != nil {
		return fmt.Errorf("error in GeneralContractMethod with addStaker: %v", err)
	}

	return nil
}

func (w *web3Helper) PushReputation(ctx context.Context, address string, reputation int64) error {
	err := w.GeneralContractMethod(ctx, w.reputationContractAddr, "setReputation", common.HexToAddress(address), big.NewInt(reputation))
	if err != nil {
		return fmt.Errorf("error in GeneralContractMethod with setReputation: %v", err)
	}

	return nil
}

func (w *web3Helper) IsStaker(ctx context.Context, address string) (bool, error) {
	if w == nil {
		return false, fmt.Errorf("web3Helper is nil")
	}

	callData, err := w.abi.Pack("isStaker", common.HexToAddress(address))
	if err != nil {
		return false, fmt.Errorf("error packing method call: %v", err)
	}

	callMsg := ethereum.CallMsg{
		To:   &w.reputationContractAddr,
		Data: callData,
	}

	gasLimit, err := w.client.EstimateGas(ctx, callMsg)
	if err != nil {
		return false, fmt.Errorf("error estimating gas: %v", err)
	}
	callMsg.Gas = gasLimit

	// b, _ := json.Marshal(callMsg)
	// fmt.Println(string(b))

	result, err := w.client.CallContract(ctx, callMsg, nil)
	if err != nil {
		return false, fmt.Errorf("error calling contract: %v and result (%s)", err, string(result))
	}

	var isStaker bool
	err = w.abi.UnpackIntoInterface(&isStaker, "isStaker", result)
	if err != nil {
		return false, fmt.Errorf("failed to unpack result: %v", err)
	}

	return isStaker, nil

}

func getContractABI(abiFile io.Reader) (abi.ABI, error) {
	// Normally, we would fetch the ABI from a URL or a file.
	// For now, we'll use a placeholder string representing the ABI.
	parsedABI, err := abi.JSON(abiFile)
	if err != nil {
		return abi.ABI{}, fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	return parsedABI, nil
}
