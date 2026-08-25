// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateBackupAutoSyncJobRequest_Validate(t *testing.T) {
	require.Error(t, UpdateBackupAutoSyncJobRequest{}.Validate())
	require.NoError(t, UpdateBackupAutoSyncJobRequest{Active: boolPtr(false)}.Validate())
	require.NoError(t, UpdateBackupAutoSyncJobRequest{RefreshToken: "rt"}.Validate())
}
