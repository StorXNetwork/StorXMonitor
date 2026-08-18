// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoogleBackupDomainUsersPayloadPassesThroughOUFields(t *testing.T) {
	src := GmailCorporateDomainUsersResponse{
		"account":        "sales@salestalker.com",
		"account_type":   "admin_workspace",
		"count":          2,
		"mailbox_count":  3,
		"ou_count":       2,
		"grouped_emails": map[string]interface{}{"connected_emails": []string{"billing@salestalker.com"}},
		"organizational_units": []interface{}{
			map[string]interface{}{
				"org_unit_path": "/",
				"name":          "/",
				"user_count":    1,
			},
			map[string]interface{}{
				"org_unit_path": "/SAles",
				"name":          "SAles",
				"user_count":    2,
			},
		},
	}

	out := googleBackupDomainUsersPayload(src, "")
	require.Equal(t, src["organizational_units"], out["organizational_units"])
	require.Equal(t, src["mailbox_count"], out["mailbox_count"])
	require.Equal(t, src["ou_count"], out["ou_count"])
	require.Equal(t, src["grouped_emails"], out["grouped_emails"])
	require.Equal(t, "admin_workspace", out["account_type"])
	require.NotContains(t, out, "domain_users_error")
}
