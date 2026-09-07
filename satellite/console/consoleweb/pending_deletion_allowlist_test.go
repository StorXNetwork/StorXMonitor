// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestEnforcePendingDeletionAPIAllowlist(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name    string
		status  console.UserStatus
		method  string
		path    string
		wantErr bool
	}{
		{name: "active user any path", status: console.Active, method: http.MethodGet, path: "/api/v0/projects", wantErr: false},
		{name: "pending cancel allowed", status: console.PendingDeletion, method: http.MethodPost, path: "/api/v0/auth/account/cancel-delete-request", wantErr: false},
		{name: "pending logout allowed", status: console.PendingDeletion, method: http.MethodPost, path: "/api/v0/auth/logout", wantErr: false},
		{name: "pending get account allowed", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/auth/account", wantErr: false},
		{name: "pending get settings allowed", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/auth/account/settings", wantErr: false},
		{name: "pending options allowed", status: console.PendingDeletion, method: http.MethodOptions, path: "/api/v0/projects", wantErr: false},
		{name: "pending trailing slash normalized", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/auth/account/", wantErr: false},

		// Postman / direct API abuse — must be forbidden for pending deletion.
		{name: "pending projects blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/projects", wantErr: true},
		{name: "pending buckets blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/buckets", wantErr: true},
		{name: "pending payments blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/payments/account", wantErr: true},
		{name: "pending google backup blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/google-backup/auto-sync/jobs", wantErr: true},
		{name: "pending dashboard blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/dashboard/stats", wantErr: true},
		{name: "pending api keys blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/api-keys", wantErr: true},
		{name: "pending update account blocked", status: console.PendingDeletion, method: http.MethodPatch, path: "/api/v0/auth/account", wantErr: true},
		{name: "pending set settings blocked", status: console.PendingDeletion, method: http.MethodPatch, path: "/api/v0/auth/account/settings", wantErr: true},
		{name: "pending delete-request blocked", status: console.PendingDeletion, method: http.MethodPost, path: "/api/v0/auth/account/delete-request", wantErr: true},
		{name: "pending refresh-session blocked", status: console.PendingDeletion, method: http.MethodPost, path: "/api/v0/auth/refresh-session", wantErr: true},
		{name: "pending cancel wrong method blocked", status: console.PendingDeletion, method: http.MethodGet, path: "/api/v0/auth/account/cancel-delete-request", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := console.WithUser(t.Context(), &console.User{Status: tt.status})
			req, err := http.NewRequestWithContext(ctx, tt.method, tt.path, nil)
			require.NoError(t, err)
			err = server.enforcePendingDeletionAPIAllowlist(ctx, req)
			if tt.wantErr {
				require.Error(t, err)
				require.True(t, console.ErrForbidden.Has(err))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestIsPendingDeletionAllowedRoute(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/api/v0/auth/account/cancel-delete-request", true},
		{http.MethodGet, "/api/v0/auth/account/cancel-delete-request", false},
		{http.MethodPost, "/api/v0/auth/logout", true},
		{http.MethodGet, "/api/v0/auth/account", true},
		{http.MethodPatch, "/api/v0/auth/account", false},
		{http.MethodGet, "/api/v0/projects", false},
		{http.MethodGet, "/api/v0/google-backup/auto-sync/jobs", false},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, isPendingDeletionAllowedRoute(tt.method, tt.path))
		})
	}
}
