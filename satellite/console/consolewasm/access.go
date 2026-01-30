// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package consolewasm

import (
	"context"
	"encoding/base64"

	"github.com/StorXNetwork/common/encryption"
	"github.com/StorXNetwork/common/grant"
	"github.com/StorXNetwork/common/macaroon"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/spacemonkeygo/monkit/v3"
)

var mon = monkit.Package()

// GenAccessGrant creates a new access grant and returns it serialized form.
func GenAccessGrant(satelliteNodeURL, apiKey, encryptionPassphrase, base64EncodedSalt string) (string, error) {
	ctx := context.Background()
	var err error
	defer mon.Task()(&ctx)(&err)

	parsedAPIKey, err := macaroon.ParseAPIKey(apiKey)
	if err != nil {
		return "", err
	}

	key, err := DeriveRootKey(encryptionPassphrase, base64EncodedSalt)
	if err != nil {
		return "", err
	}

	encAccess := grant.NewEncryptionAccessWithDefaultKey(key)
	encAccess.SetDefaultPathCipher(storxnetwork.EncAESGCM)
	encAccess.LimitTo(parsedAPIKey)

	accessString, err := (&grant.Access{
		SatelliteAddress: satelliteNodeURL,
		APIKey:           parsedAPIKey,
		EncAccess:        encAccess,
	}).Serialize()
	if err != nil {
		return "", err
	}
	return accessString, nil
}

// DeriveRootKey derives the root key portion of the access grant.
func DeriveRootKey(encryptionPassphrase, base64EncodedSalt string) (*storxnetwork.Key, error) {
	ctx := context.Background()
	var err error
	defer mon.Task()(&ctx)(&err)

	const concurrency = 8
	saltBytes, err := base64.StdEncoding.DecodeString(base64EncodedSalt)
	if err != nil {
		return nil, err
	}
	return encryption.DeriveRootKey([]byte(encryptionPassphrase), saltBytes, "", concurrency)
}
