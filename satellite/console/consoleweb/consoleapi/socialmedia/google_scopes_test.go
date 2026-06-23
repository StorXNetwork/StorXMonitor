// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package socialmedia

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseGoogleScopeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			name:  "single",
			input: "openid",
			want:  []string{"openid"},
		},
		{
			name:  "multiple deduped",
			input: "openid email openid https://www.googleapis.com/auth/gmail.readonly",
			want:  []string{"openid", "email", "https://www.googleapis.com/auth/gmail.readonly"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ParseGoogleScopeString(tt.input))
		})
	}
}

func TestGoogleBackupScopeSummary(t *testing.T) {
	tests := []struct {
		name      string
		grantedIn []string
		granted   []string
		ungranted []string
	}{
		{
			name:      "all backup scopes granted",
			grantedIn: append([]string(nil), GoogleRegisterBackupScopes...),
			granted:   append([]string(nil), GoogleRegisterBackupScopes...),
			ungranted: nil,
		},
		{
			name: "google aliases satisfy backup scopes",
			grantedIn: []string{
				"openid",
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/gmail.readonly",
				"https://www.googleapis.com/auth/gmail.insert",
				"https://www.googleapis.com/auth/admin.directory.user.readonly",
				"https://www.googleapis.com/auth/drive.readonly",
				"https://www.googleapis.com/auth/drive.photos.readonly",
				"https://www.googleapis.com/auth/photoslibrary.readonly",
				"https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata",
				"https://www.googleapis.com/auth/calendar.readonly",
				"https://www.googleapis.com/auth/contacts.readonly",
			},
			granted:   append([]string(nil), GoogleRegisterBackupScopes...),
			ungranted: nil,
		},
		{
			name:      "partial",
			grantedIn: []string{"openid", "email", "profile"},
			granted:   []string{"openid", "email", "profile"},
			ungranted: []string{
				"https://www.googleapis.com/auth/gmail.readonly",
				"https://www.googleapis.com/auth/gmail.insert",
				"https://www.googleapis.com/auth/admin.directory.user.readonly",
				"https://www.googleapis.com/auth/drive.readonly",
				"https://www.googleapis.com/auth/photoslibrary.readonly",
				"https://www.googleapis.com/auth/calendar.readonly",
				"https://www.googleapis.com/auth/contacts.readonly",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			granted, ungranted := GoogleBackupScopeSummary(tt.grantedIn)
			require.Equal(t, tt.granted, granted)
			require.Equal(t, tt.ungranted, ungranted)
		})
	}
}
