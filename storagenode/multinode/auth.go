// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package multinode

import (
	"context"

	"github.com/StorXNetwork/StorXMonitor/private/multinodeauth"
	"github.com/StorXNetwork/StorXMonitor/private/multinodepb"
	"github.com/StorXNetwork/StorXMonitor/storagenode/apikeys"
)

// authenticate checks if request header contains valid api key.
func authenticate(ctx context.Context, apiKeys *apikeys.Service, header *multinodepb.RequestHeader) error {
	secret, err := multinodeauth.SecretFromBytes(header.GetApiKey())
	if err != nil {
		return err
	}

	if err = apiKeys.Check(ctx, secret); err != nil {
		return err
	}

	return nil
}
