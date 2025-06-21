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
	UploadSocialShare(ctx context.Context, id string, share string, versionId string) error
	UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error
	GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error)
	GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error)
	GetTotalKeys(ctx context.Context) (uint64, error)
}

var _ SocialShareHelper = (*keyValueWeb3Helper)(nil)

type keyValueWeb3Helper struct {
	web3Helper *web3Helper
}

func NewKeyValueWeb3Helper(web3Config Web3Config, privateKey string) (*keyValueWeb3Helper, error) {
	web3Helper, err := NewWeb3Helper(web3Config, privateKey)
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
func (w *keyValueWeb3Helper) UploadSocialShare(ctx context.Context, id string, share string, versionId string) error {
	if w == nil {
		return fmt.Errorf("web3Helper is nil")
	}

	err := w.web3Helper.SubmitTransaction(ctx, "createKeyValue", id, share, versionId)
	if err != nil {
		return w.UpdateSocialShare(ctx, id, share, versionId)
	}

	return nil
}

func (w *keyValueWeb3Helper) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	if w == nil {
		return fmt.Errorf("web3Helper is nil")
	}

	// If key already exists, try updating it
	err := w.web3Helper.SubmitTransaction(ctx, "editKeyValue", id, share, versionId)
	if err != nil {
		return fmt.Errorf("error storing social share: %v", err)
	}

	return nil
}

// GetSocialShare retrieves the social share data from the smart contract
func (w *keyValueWeb3Helper) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("web3Helper is nil")
	}

	var value string
	var exists bool
	err := w.web3Helper.GetMethodCallData(ctx, "getKeyValueByVersion", &value, &exists, id, versionId)
	if err != nil {
		return nil, fmt.Errorf("error getting social share: %v", err)
	}
	if !exists {
		return nil, fmt.Errorf("key or version not found")
	}

	return []byte(value), nil
}

func (w *keyValueWeb3Helper) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	if w == nil {
		return nil, nil, nil, fmt.Errorf("web3Helper is nil")
	}
	type output struct {
		Keys       []string
		Values     []string
		VersionIds []string
	}
	var out output
	err = w.web3Helper.GetMethodCallData(ctx, "getPaginatedKeyValues", &out.Keys, &out.Values, &out.VersionIds, startIndex, count)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error getting paginated key values: %v", err)
	}
	return out.Keys, out.Values, out.VersionIds, nil
}

func (w *keyValueWeb3Helper) GetTotalKeys(ctx context.Context) (uint64, error) {
	if w == nil {
		return 0, fmt.Errorf("web3Helper is nil")
	}
	var total uint64
	err := w.web3Helper.GetMethodCallData(ctx, "getTotalKeys", &total)
	if err != nil {
		return 0, fmt.Errorf("error getting total keys: %v", err)
	}
	return total, nil
}

// Ensure keyValueWeb3Helper implements SocialShareHelper interface
var _ SocialShareHelper = (*keyValueWeb3Helper)(nil)
