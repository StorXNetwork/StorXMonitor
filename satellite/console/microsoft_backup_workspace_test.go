// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestBackupToolsJSON(t *testing.T) {
	var gotMethod, gotPath, gotTokenKey string
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotTokenKey = r.Method, r.URL.RequestURI(), r.Header.Get("token_key")
		gotBody = nil
		if body, _ := io.ReadAll(r.Body); len(body) > 0 {
			_ = json.Unmarshal(body, &gotBody)
		}
		switch r.URL.Path {
		case "/microsoft/tenants/tenant-1/consent":
			_, _ = w.Write([]byte(`{"account_type":"admin_workspace","consent":{"status":"granted"}}`))
		case "/microsoft/tenants/tenant-1/capabilities/refresh":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"consent not granted"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	s := &Service{log: zaptest.NewLogger(t), backupToolsURL: server.URL}
	ctx := context.Background()

	t.Run("success shapes request and decodes body", func(t *testing.T) {
		out, err := s.backupToolsJSON(ctx, http.MethodPost, microsoftTenantPath("tenant-1", "/consent"), "session", map[string]interface{}{"consented_by": "admin@contoso.com"})
		require.NoError(t, err)
		require.Equal(t, http.MethodPost, gotMethod)
		require.Equal(t, "/microsoft/tenants/tenant-1/consent", gotPath)
		require.Equal(t, "session", gotTokenKey)
		require.Equal(t, "admin@contoso.com", gotBody["consented_by"])
		require.Equal(t, MicrosoftAccountTypeAdminWorkspace, out["account_type"])
	})

	t.Run("4xx is returned as status error with body", func(t *testing.T) {
		_, err := s.backupToolsJSON(ctx, http.MethodPost, microsoftTenantPath("tenant-1", "/capabilities/refresh"), "session", nil)
		var statusErr *BackupToolsStatusError
		require.True(t, errors.As(err, &statusErr))
		require.Equal(t, http.StatusForbidden, statusErr.Status)
		require.JSONEq(t, `{"error":"consent not granted"}`, string(statusErr.Body))
	})

	t.Run("tenant id is path escaped", func(t *testing.T) {
		require.Equal(t, "/microsoft/tenants/a%2Fb/consent", microsoftTenantPath("a/b", "/consent"))
	})
}

func TestBackupToolsTenantJSONRefreshToken(t *testing.T) {
	var gotRefresh string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRefresh = r.Header.Get("REFRESH_TOKEN")
		_, _ = w.Write([]byte(`{"account_type":"work_account"}`))
	}))
	defer server.Close()

	s := &Service{log: zaptest.NewLogger(t), backupToolsURL: server.URL}
	ctx := context.Background()

	t.Run("sends stored refresh token", func(t *testing.T) {
		_, err := s.backupToolsTenantJSON(ctx, http.MethodGet, "/microsoft/workspace", "session", &BackupCredential{RefreshToken: "1.refresh-token"}, nil)
		require.NoError(t, err)
		require.Equal(t, "1.refresh-token", gotRefresh)
	})

	t.Run("never sends a JWT as refresh token", func(t *testing.T) {
		jwtLike := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
		_, err := s.backupToolsTenantJSON(ctx, http.MethodGet, "/microsoft/workspace", "session", &BackupCredential{RefreshToken: jwtLike}, nil)
		require.NoError(t, err)
		require.Empty(t, gotRefresh)
	})
}
