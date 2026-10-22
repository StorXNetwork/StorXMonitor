// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
)

func TestParseOwnNodesOperatorEmail(t *testing.T) {
	userID := testrand.UUID()
	orgID := testrand.UUID()

	// Preferred: user id only.
	email := console.FormatOwnNodesOperatorEmail(userID)
	parsedUser, parsedOrg, ok := console.ParseOwnNodesOperatorEmail(email)
	require.True(t, ok)
	require.Equal(t, userID, parsedUser)
	require.True(t, parsedOrg.IsZero())

	// With contact email suffix.
	withContact := email + "|ops@example.com"
	parsedUser, parsedOrg, ok = console.ParseOwnNodesOperatorEmail(withContact)
	require.True(t, ok)
	require.Equal(t, userID, parsedUser)
	require.True(t, parsedOrg.IsZero())
	bind, contact := console.SplitOwnNodesCheckInEmail(withContact)
	require.Equal(t, email, bind)
	require.Equal(t, "ops@example.com", contact)

	// Legacy: user + org.
	legacy := console.FormatOwnNodesOperatorEmailWithOrg(userID, orgID)
	parsedUser, parsedOrg, ok = console.ParseOwnNodesOperatorEmail(legacy)
	require.True(t, ok)
	require.Equal(t, userID, parsedUser)
	require.Equal(t, orgID, parsedOrg)

	legacyContact := legacy + "|ops@example.com"
	parsedUser, parsedOrg, ok = console.ParseOwnNodesOperatorEmail(legacyContact)
	require.True(t, ok)
	require.Equal(t, userID, parsedUser)
	require.Equal(t, orgID, parsedOrg)

	_, _, ok = console.ParseOwnNodesOperatorEmail("user@example.com")
	require.False(t, ok)

	_, _, ok = console.ParseOwnNodesOperatorEmail("ownnodes:not-a-uuid")
	require.False(t, ok)

	_, _, ok = console.ParseOwnNodesOperatorEmail("ownnodes:not-a-uuid:" + orgID.String())
	require.False(t, ok)

	bind, contact = console.SplitOwnNodesCheckInEmail("user@example.com")
	require.Empty(t, bind)
	require.Equal(t, "user@example.com", contact)
}

func TestOrgRoleConstants(t *testing.T) {
	require.Equal(t, "admin", console.OrgRoleAdmin)
	require.Equal(t, "member", console.OrgRoleMember)
}

func TestFormatOwnNodesOperatorEmailRoundTrip(t *testing.T) {
	userID, err := uuid.FromString("11111111-1111-1111-1111-111111111111")
	require.NoError(t, err)

	email := console.FormatOwnNodesOperatorEmail(userID)
	require.Equal(t, "ownnodes:11111111-1111-1111-1111-111111111111", email)
}
