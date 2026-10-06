// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package socialmedia

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLooksLikeJWT(t *testing.T) {
	require.True(t, looksLikeJWT("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln"))
	require.False(t, looksLikeJWT("aaa.bbb.ccc"))
	require.False(t, looksLikeJWT("1.AcYAf8QgeJ0L-UGJd5VjCizaAIRR2ZnpW71LvrUJUwKxwrQAAFfGAA.BQABBAIAAAADAOz_BQD0_0V2b1N0c0FydGlmYWN0cwIAAAAAAESwEdrWt"))
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
	require.Contains(t, authURL, "Files.Read")
	require.Contains(t, authURL, "offline_access")
	// Organization scopes come from admin consent (app permissions), never the user sign-in.
	require.NotContains(t, authURL, "Mail.Read.Shared")
	require.NotContains(t, authURL, "Files.Read.All")
	require.NotContains(t, authURL, "Sites.Read.All")
	require.NotContains(t, authURL, "User.Read.All")
	require.Contains(t, authURL, "prompt=consent")
	require.Contains(t, authURL, "response_type=code")
	require.Contains(t, authURL, "state=state-1")
}
