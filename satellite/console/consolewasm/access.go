// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package consolewasm

import (
	"context"
	"encoding/base64"

	"github.com/spacemonkeygo/monkit/v3"
	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/storj"
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
	encAccess.SetDefaultPathCipher(storj.EncAESGCM)
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
func DeriveRootKey(encryptionPassphrase, base64EncodedSalt string) (*storj.Key, error) {
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
