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

func TestMicrosoftBackupScopeSummary(t *testing.T) {
	granted, ungranted := MicrosoftBackupScopeSummary([]string{
		"openid", "email", "offline_access", "User.Read", "Mail.Read",
		"https://graph.microsoft.com/Calendars.Read",
	}, false)
	require.Contains(t, granted, "openid")
	require.Contains(t, granted, "offline_access")
	require.Contains(t, granted, "Mail.Read")
	require.Contains(t, granted, "Calendars.Read")
	require.Contains(t, ungranted, "Contacts.Read")
	require.Contains(t, ungranted, "Mail.Read.Shared")
	require.Contains(t, ungranted, "Files.Read.All")
	require.Contains(t, ungranted, "Sites.Read.All")
	require.Contains(t, ungranted, "User.Read.All")

	grantedWithDrive, ungrantedWithDrive := MicrosoftBackupScopeSummary([]string{
		"openid", "email", "offline_access", "User.Read", "Mail.Read", "Mail.Read.Shared",
		"Calendars.Read", "Contacts.Read", "Files.Read.All", "Sites.Read.All",
		"User.Read.All", "Directory.Read.All", "profile",
	}, false)
	require.Contains(t, grantedWithDrive, "Files.Read.All")
	require.Contains(t, grantedWithDrive, "Sites.Read.All")
	require.Empty(t, ungrantedWithDrive)

	grantedRefresh, ungrantedRefresh := MicrosoftBackupScopeSummary([]string{
		"openid", "profile", "email", "User.Read", "Mail.Read",
	}, true)
	require.Contains(t, grantedRefresh, "offline_access")
	require.NotContains(t, ungrantedRefresh, "offline_access")
}

func TestBuildMicrosoftBackupOAuthURL(t *testing.T) {
	SetOutlookSocialMediaConfig("test-client-id", "secret")
	SetMicrosoftBackupOAuthRedirectURL("https://app.example.com/microsoft-backup")
	t.Cleanup(func() {
		SetOutlookSocialMediaConfig("", "")
		SetMicrosoftBackupOAuthRedirectURL("")
	})

	authURL, err := BuildMicrosoftBackupOAuthURL("state-1", "")
	require.NoError(t, err)
	require.Contains(t, authURL, "client_id=test-client-id")
	require.Contains(t, authURL, "Mail.Read")
	require.Contains(t, authURL, "Mail.Read.Shared")
	require.Contains(t, authURL, "Files.Read.All")
	require.Contains(t, authURL, "Sites.Read.All")
	require.Contains(t, authURL, "prompt=consent")
	require.Contains(t, authURL, "response_type=code")
	require.Contains(t, authURL, "state=state-1")
}
