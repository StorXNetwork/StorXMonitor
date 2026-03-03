// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package contact

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/shared/nodetag"
	"github.com/StorXNetwork/common/identity/testidentity"
	"github.com/StorXNetwork/common/signing"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testcontext"
)

func TestGetTags(t *testing.T) {
	ctx := testcontext.New(t)
	cfg := Config{
		Tags: SignedTags{},
		SelfSignedTags: []string{
			"foo=bar",
		},
	}
	id := testidentity.MustPregeneratedIdentity(0, storxnetwork.LatestIDVersion())
	tags, err := GetTags(ctx, cfg, id)
	require.NoError(t, err)
	require.Len(t, tags.Tags, 1)
	_, err = nodetag.Verify(ctx, tags.Tags[0], signing.SigneeFromPeerIdentity(id.PeerIdentity()))
	require.NoError(t, err)

}
