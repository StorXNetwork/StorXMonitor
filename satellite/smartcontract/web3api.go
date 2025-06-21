package smartcontract

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Web3Config struct {
	NetworkRPC   string
	ContractAddr string
	Address      string
}

type web3Helper struct {
	client       *ethclient.Client
	abi          abi.ABI
	address      common.Address
	contractAddr common.Address
	privateKey   *ecdsa.PrivateKey
}

func NewWeb3Helper(cnf Web3Config, privateKey string) (*web3Helper, error) {
	client, err := ethclient.Dial(cnf.NetworkRPC)
	if err != nil {
		return nil, fmt.Errorf("error connecting to the network: %v", err)
	}

	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	return &web3Helper{
		client:       client,
		address:      common.HexToAddress(cnf.Address),
		contractAddr: common.HexToAddress(cnf.ContractAddr),
		privateKey:   privateKeyECDSA,
	}, nil
}

func (w *web3Helper) getNonce(ctx context.Context) (uint64, error) {
	nonce, err := w.client.PendingNonceAt(ctx, w.address)
	if err != nil {
		return 0, fmt.Errorf("failed to get nonce: %v", err)
	}
	return nonce, nil
}

func (w *web3Helper) SubmitTransaction(ctx context.Context, method string, params ...interface{}) error {

	data, err := w.abi.Pack(method, params...)
	if err != nil {
		return fmt.Errorf("error packing method call: %v", err)
	}

	gasPrice, err := w.client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("error suggesting gas price: %v", err)
	}

	if gasPrice.Cmp(big.NewInt(15000000000)) > 0 {
		gasPrice = big.NewInt(15000000000)
	}

	nonceCount, err := w.getNonce(ctx)
	if err != nil {
		return fmt.Errorf("error getting nonce: %v", err)
	}

	fmt.Println("SMART CONTRACT DEBUG nonceCount", nonceCount)
	fmt.Println("SMART CONTRACT DEBUG gasPrice", gasPrice)
	fmt.Println("SMART CONTRACT DEBUG data", data)
	fmt.Println("SMART CONTRACT DEBUG contractAddr", w.contractAddr)
	fmt.Println("SMART CONTRACT DEBUG address", w.address)

	tx := types.NewTransaction(nonceCount, w.contractAddr, big.NewInt(0), uint64(5000000), gasPrice, data)

	fmt.Println("SMART CONTRACT DEBUG tx", tx)

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

	// b, _ := json.Marshal(receipt)
	// fmt.Println(string(b))

	if receipt.Status == types.ReceiptStatusFailed {
		return fmt.Errorf("transaction failed with status %v", receipt.Status)
	}

	return nil
}

func (w *web3Helper) GetMethodCallData(ctx context.Context, method string, output interface{}, params ...interface{}) error {
	callData, err := w.abi.Pack(method, params...)
	if err != nil {
		return fmt.Errorf("error packing method call: %v", err)
	}

	callMsg := ethereum.CallMsg{
		To:   &w.contractAddr,
		Data: callData,
		From: w.address,
	}

	gasLimit, err := w.client.EstimateGas(ctx, callMsg)
	if err != nil {
		return fmt.Errorf("error estimating gas: %v", err)
	}
	callMsg.Gas = gasLimit

	// b, _ := json.Marshal(callMsg)
	// fmt.Println(string(b))

	result, err := w.client.CallContract(ctx, callMsg, nil)
	if err != nil {
		return fmt.Errorf("error calling contract: %v and result (%s)", err, string(result))
	}

	err = w.abi.UnpackIntoInterface(output, method, result)
	if err != nil {
		return fmt.Errorf("failed to unpack result in get reputation: %v", err)
	}

	return nil
}
