// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
)

func TestBackupProjectUpdateRedirectURI_table(t *testing.T) {
	socialmedia.SetConfig(&socialmedia.Config{
		GoogleOAuthRedirectUrl_googlebackup:          "https://google-app.example",
		OutlookOAuthRedirectUrl_microsoftbackup:      "https://ms-app.example",
		ClientOrigin:                                 "https://fallback.example",
	})

	tests := []struct {
		name string
		req  console.UpdateBackupAutoSyncJobsByProjectRequest
		host string
		want string
	}{
		{
			name: "microsoft email uses microsoft origin on loopback",
			req: console.UpdateBackupAutoSyncJobsByProjectRequest{
				MicrosoftEmail: "user@contoso.com",
				Code:           "code",
			},
			host: "127.0.0.1:10000",
			want: "https://ms-app.example",
		},
		{
			name: "google email uses google origin on loopback",
			req: console.UpdateBackupAutoSyncJobsByProjectRequest{
				GoogleEmail: "user@gmail.com",
				Code:        "code",
			},
			host: "127.0.0.1:10000",
			want: "https://google-app.example",
		},
		{
			name: "microsoft email uses request host in prod",
			req: console.UpdateBackupAutoSyncJobsByProjectRequest{
				MicrosoftEmail: "user@contoso.com",
			},
			host: "portal.acme.com",
			want: "https://portal.acme.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPut, "https://"+tt.host+"/api/v0/backup/auto-sync/jobs/project", nil)
			require.NoError(t, err)
			r.Host = tt.host
			r.Header.Set("X-Forwarded-Proto", "https")
			got := backupProjectUpdateRedirectURI(r, tt.req)
			require.Equal(t, tt.want, got)
		})
	}
}
