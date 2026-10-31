// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreferredBackupProviderForServicesQuota(t *testing.T) {
	require.Equal(t, BackupProviderMicrosoft, preferredBackupProviderForServicesQuota([]string{
		"outlook", "calendar", "contacts", "onedrive", "sharepoint", "teams", "groups",
	}))
	require.Equal(t, BackupProviderGoogle, preferredBackupProviderForServicesQuota([]string{
		"drive", "gmail", "photos",
	}))
	require.Equal(t, "", preferredBackupProviderForServicesQuota([]string{"calendar", "contacts"}))
	require.Equal(t, BackupProviderGoogle, preferredBackupProviderForServicesQuota([]string{"google_drive", "gmail"}))
}

func TestMicrosoftQuotaCheckDisabledResponse(t *testing.T) {
	got := microsoftQuotaCheckDisabledResponse(" ann@outlook.com ")
	require.Equal(t, true, got["allowed"])
	require.Equal(t, true, got["estimate_skipped"])
	require.Equal(t, "", got["failure_code"])
	require.Equal(t, "ann@outlook.com", got["oauth_holder"])
	require.NotContains(t, got, "estimate_bytes")
}

func TestServicesFromQuotaRequest(t *testing.T) {
	require.Empty(t, servicesFromQuotaRequest(map[string]interface{}{}))
	got := servicesFromQuotaRequest(map[string]interface{}{
		"project_id": "p",
		"services":   []interface{}{"outlook", "onedrive"},
	})
	require.Equal(t, []string{"outlook", "onedrive"}, got)
}
