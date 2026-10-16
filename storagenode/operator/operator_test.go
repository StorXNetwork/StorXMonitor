// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package operator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckInEmail(t *testing.T) {
	t.Parallel()

	require.Equal(t, "a@b.com", Config{Email: "a@b.com"}.CheckInEmail())

	require.Equal(t, "ownnodes:user-1|a@b.com", Config{
		Email:  "a@b.com",
		UserID: "user-1",
	}.CheckInEmail())

	require.Equal(t, "ownnodes:user-1", Config{
		UserID: "user-1",
	}.CheckInEmail())
}
