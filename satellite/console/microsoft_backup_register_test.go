// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMicrosoftBackupRegistrationPayloadKeepsDetectionSummary(t *testing.T) {
	detection := map[string]interface{}{
		"account":           "ann@outlook.com",
		"email":             "ann@outlook.com",
		"account_type":      "personal",
		"workspace_kind":    "personal",
		"tenant_id":         "9188040d-6c67-4c5b-b112-36a304b66dad",
		"tenant_name":       "",
		"is_admin":          false,
		"admin_roles":       []interface{}{},
		"consent":           map[string]interface{}{"status": "not_requested"},
		"capabilities":      map[string]interface{}{"mail_backup": false},
		"capability_errors": map[string]interface{}{},
		"entities":          []interface{}{},
		"access_state": map[string]interface{}{
			"can_personal_backup":     true,
			"can_organization_backup": false,
			"capabilities":            map[string]interface{}{"mail_backup": false},
		},
	}

	got := MicrosoftBackupRegistrationPayload(RegisterMicrosoftBackupResult{
		CredentialID:    "7ee3ec7f-6f23-4c09-bb32-07cd94480052",
		MicrosoftEmail:  "ann@outlook.com",
		AccountType:     MicrosoftAccountTypePersonal,
		HasRefreshToken: true,
		Detection:       detection,
	})

	require.Equal(t, map[string]interface{}{
		"credential_id":       "7ee3ec7f-6f23-4c09-bb32-07cd94480052",
		"email":               "ann@outlook.com",
		"account_type":        MicrosoftAccountTypePersonal,
		"workspace_kind":      "personal",
		"tenant_id":           "9188040d-6c67-4c5b-b112-36a304b66dad",
		"tenant_name":         "",
		"is_admin":            false,
		"admin_roles":         []interface{}{},
		"can_personal_backup": true,
		"has_refresh_token":   true,
	}, got)
}

func TestMicrosoftBackupRegistrationPayloadWorkAccountKeepsAdminRoles(t *testing.T) {
	got := MicrosoftBackupRegistrationPayload(RegisterMicrosoftBackupResult{
		MicrosoftEmail: "admin@contoso.com",
		AccountType:    MicrosoftAccountTypeWorkAccount,
		TenantID:       "contoso-tid",
		TenantName:     "Contoso",
		Detection: map[string]interface{}{
			"account_type": MicrosoftAccountTypeWorkAccount,
			"tenant_id":    "contoso-tid",
			"is_admin":     true,
			"admin_roles":  []interface{}{"Global Administrator"},
			"consent":      map[string]interface{}{"status": "granted"},
		},
	})

	require.Equal(t, true, got["is_admin"])
	require.Equal(t, []interface{}{"Global Administrator"}, got["admin_roles"])
	require.Equal(t, "organization", got["workspace_kind"])
	require.Equal(t, "Contoso", got["tenant_name"])
	require.NotContains(t, got, "consent")
}

func TestMicrosoftBackupRegistrationPayloadWithoutDetection(t *testing.T) {
	got := MicrosoftBackupRegistrationPayload(RegisterMicrosoftBackupResult{
		MicrosoftEmail: "ann@outlook.com",
		DetectionError: "timeout",
	})

	require.Equal(t, map[string]interface{}{
		"email":             "ann@outlook.com",
		"detection_error":   "timeout",
		"has_refresh_token": false,
	}, got)
}
