package smartcontract

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/spacemonkeygo/monkit/v3"
)

var mon = monkit.Package()

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
	// Track attempts
	mon.Counter("smartcontract_upload_social_share_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_upload_social_share_failures").Inc(1)

		return fmt.Errorf("web3Helper is nil")
	}

	err := w.web3Helper.SubmitTransaction(ctx, "createKeyValue", id, share, versionId)
	if err != nil {
		mon.Counter("smartcontract_upload_social_share_create_failed").Inc(1)

		// Try to update instead
		updateErr := w.UpdateSocialShare(ctx, id, share, versionId)
		if updateErr != nil {
			mon.Counter("smartcontract_upload_social_share_failures").Inc(1)

			return updateErr
		}
		// Update succeeded
		mon.Counter("smartcontract_upload_social_share_successes").Inc(1)
		mon.IntVal("smartcontract_upload_social_share_size").Observe(int64(len(share)))
		return nil
	}

	// Create succeeded
	mon.Counter("smartcontract_upload_social_share_successes").Inc(1)
	mon.IntVal("smartcontract_upload_social_share_size").Observe(int64(len(share)))
	return nil
}

func (w *keyValueWeb3Helper) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	// Track attempts
	mon.Counter("smartcontract_update_social_share_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_update_social_share_failures").Inc(1)

		return fmt.Errorf("web3Helper is nil")
	}

	// If key already exists, try updating it
	err := w.web3Helper.SubmitTransaction(ctx, "editKeyValue", id, share, versionId)
	if err != nil {
		mon.Counter("smartcontract_update_social_share_failures").Inc(1)

		return fmt.Errorf("error storing social share: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_update_social_share_successes").Inc(1)
	mon.IntVal("smartcontract_update_social_share_size").Observe(int64(len(share)))
	return nil
}

// GetSocialShare retrieves the social share data from the smart contract
func (w *keyValueWeb3Helper) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	// Track attempts
	mon.Counter("smartcontract_get_social_share_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_get_social_share_failures").Inc(1)

		return nil, fmt.Errorf("web3Helper is nil")
	}

	// Create a struct to hold the return values
	type returnValues struct {
		Value  string
		Exists bool
	}

	var result returnValues
	err := w.web3Helper.GetMethodCallData(ctx, "getKeyValueByVersion", &result, id, versionId)
	if err != nil {
		mon.Counter("smartcontract_get_social_share_failures").Inc(1)

		return nil, fmt.Errorf("error getting social share: %v", err)
	}
	if !result.Exists {
		mon.Counter("smartcontract_get_social_share_failures").Inc(1)

		return nil, fmt.Errorf("key or version not found")
	}

	// Track success
	mon.Counter("smartcontract_get_social_share_successes").Inc(1)
	mon.IntVal("smartcontract_get_social_share_size").Observe(int64(len(result.Value)))
	return []byte(result.Value), nil
}

func (w *keyValueWeb3Helper) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	// Track attempts
	mon.Counter("smartcontract_get_paginated_keyvalues_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_get_paginated_keyvalues_failures").Inc(1)

		return nil, nil, nil, fmt.Errorf("web3Helper is nil")
	}

	// Create a struct to hold the return values
	type output struct {
		Keys       []string
		Values     []string
		VersionIds []string
	}
	var out output

	// Convert uint64 to *big.Int for ABI compatibility
	startIndexBig := new(big.Int).SetUint64(startIndex)
	countBig := new(big.Int).SetUint64(count)

	err = w.web3Helper.GetMethodCallData(ctx, "getPaginatedKeyValues", &out, startIndexBig, countBig)
	if err != nil {
		mon.Counter("smartcontract_get_paginated_keyvalues_failures").Inc(1)

		return nil, nil, nil, fmt.Errorf("error getting paginated key values: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_get_paginated_keyvalues_successes").Inc(1)
	mon.IntVal("smartcontract_get_paginated_keyvalues_count").Observe(int64(len(out.Keys)))
	return out.Keys, out.Values, out.VersionIds, nil
}

func (w *keyValueWeb3Helper) GetTotalKeys(ctx context.Context) (uint64, error) {
	// Track attempts
	mon.Counter("smartcontract_get_total_keys_attempts").Inc(1)

	if w == nil {
		mon.Counter("smartcontract_get_total_keys_failures").Inc(1)

		return 0, fmt.Errorf("web3Helper is nil")
	}

	var total *big.Int
	err := w.web3Helper.GetMethodCallData(ctx, "getTotalKeys", &total)
	if err != nil {
		mon.Counter("smartcontract_get_total_keys_failures").Inc(1)

		return 0, fmt.Errorf("error getting total keys: %v", err)
	}

	// Track success
	mon.Counter("smartcontract_get_total_keys_successes").Inc(1)
	totalKeys := total.Uint64()
	mon.IntVal("smartcontract_get_total_keys_value").Observe(int64(totalKeys))
	return totalKeys, nil
}

// Ensure keyValueWeb3Helper implements SocialShareHelper interface
var _ SocialShareHelper = (*keyValueWeb3Helper)(nil)
