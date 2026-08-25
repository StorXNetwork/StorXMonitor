// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInferMicrosoftAccountTypeFromEmail(t *testing.T) {
	require.Equal(t, "personal", InferMicrosoftAccountTypeFromEmail("user@outlook.com"))
	require.Equal(t, "", InferMicrosoftAccountTypeFromEmail("admin@contoso.com"))
}

func TestIsMicrosoftConsumerEmail(t *testing.T) {
	require.True(t, IsMicrosoftConsumerEmail("user@outlook.com"))
	require.True(t, IsMicrosoftConsumerEmail("user@hotmail.com"))
	require.False(t, IsMicrosoftConsumerEmail("admin@contoso.com"))
}
