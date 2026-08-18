// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package socialmedia

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLooksLikeJWT(t *testing.T) {
	require.True(t, looksLikeJWT("aaa.bbb.ccc"))
	require.False(t, looksLikeJWT("not-a-jwt"))
	require.False(t, looksLikeJWT("only.two"))
	require.False(t, looksLikeJWT(""))
}

func TestAudienceContains(t *testing.T) {
	require.True(t, audienceContains("client-id", "client-id"))
	require.False(t, audienceContains("other", "client-id"))
	require.True(t, audienceContains([]interface{}{"a", "client-id"}, "client-id"))
	require.False(t, audienceContains([]interface{}{"a"}, "client-id"))
	require.False(t, audienceContains(nil, "client-id"))
}
