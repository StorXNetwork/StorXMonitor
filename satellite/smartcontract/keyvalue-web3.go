package smartcontract

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

//go:embed keystorevalue.abi
var keystoreValueABI []byte

type SocialShareHelper interface {
	UploadSocialShare(ctx context.Context, id string, share string) error
	UpdateSocialShare(ctx context.Context, id string, share string) error
	GetSocialShare(ctx context.Context, id string) ([]byte, error)
}

var _ SocialShareHelper = (*keyValueWeb3Helper)(nil)

type keyValueWeb3Helper struct {
	web3Helper *web3Helper
}

func NewKeyValueWeb3Helper(web3Config Web3Config) (*keyValueWeb3Helper, error) {
	web3Helper, err := NewWeb3Helper(web3Config)
	if err != nil {
		return nil, err
	}

	parsedABI, err := abi.JSON(bytes.NewReader(keystoreValueABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	web3Helper.abi = parsedABI

	return &keyValueWeb3Helper{web3Helper: web3Helper}, nil
}

// UploadSocialShare stores the social share data in the smart contract
func (w *keyValueWeb3Helper) UploadSocialShare(ctx context.Context, id string, share string) error {
	if w == nil {
		return fmt.Errorf("web3Helper is nil")
	}

	err := w.web3Helper.SubmitTransaction(ctx, "createKeyValue", id, share)
	if err != nil {
		return w.web3Helper.SubmitTransaction(ctx, "createKeyValue", id, share)
	}

	return nil
}

func (w *keyValueWeb3Helper) UpdateSocialShare(ctx context.Context, id string, share string) error {
	if w == nil {
		return fmt.Errorf("web3Helper is nil")
	}

	// If key already exists, try updating it
	err := w.web3Helper.SubmitTransaction(ctx, "editKeyValue", id, share)
	if err != nil {
		return fmt.Errorf("error storing social share: %v", err)
	}

	return nil
}

// GetSocialShare retrieves the social share data from the smart contract
func (w *keyValueWeb3Helper) GetSocialShare(ctx context.Context, id string) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("web3Helper is nil")
	}

	var value string
	err := w.web3Helper.GetMethodCallData(ctx, "getValue", &value, id)
	if err != nil {
		return nil, fmt.Errorf("error getting social share: %v", err)
	}

	return []byte(value), nil
}

// Ensure keyValueWeb3Helper implements SocialShareHelper interface
var _ SocialShareHelper = (*keyValueWeb3Helper)(nil)
