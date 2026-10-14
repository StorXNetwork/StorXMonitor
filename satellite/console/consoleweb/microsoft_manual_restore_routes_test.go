// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

const testSessionCookie = "_tokenKey"

var microsoftManualRestorePaths = []string{
	"/office365/satellite-to-outlook",
	"/office365/satellite-to-outlook-calendar",
	"/office365/satellite-to-outlook-contacts",
	"/office365/satellite-to-onedrive",
	"/office365/satellite-to-sharepoint",
	"/office365/satellite-to-teams",
	"/office365/satellite-to-teams-chats",
	"/office365/satellite-to-groups",
}

func newMicrosoftManualRestoreRouter(t *testing.T) (*mux.Router, *int) {
	cookieAuth := consolewebauth.NewCookieAuth(
		consolewebauth.CookieSettings{Name: testSessionCookie, Path: "/"},
		consolewebauth.CookieSettings{Name: "sso_state", Path: "/"},
		consolewebauth.CookieSettings{Name: "sso_email_token", Path: "/"},
		"",
	)
	controller := consoleapi.NewMicrosoftBackup(zaptest.NewLogger(t), &console.Service{}, cookieAuth)

	limited := 0
	limit := func(next http.Handler) http.Handler {
		limited++
		return next
	}
	router := mux.NewRouter()
	registerMicrosoftManualRestoreRoutes(router.PathPrefix("/api/v0/microsoft-backup").Subrouter(), limit, controller)
	return router, &limited
}

func serveManualRestore(router http.Handler, method, path, body string, withSession bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v0/microsoft-backup"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if withSession {
		token := consoleauth.Token{Payload: []byte("payload"), Signature: []byte("signature")}
		req.AddCookie(&http.Cookie{Name: testSessionCookie, Value: token.String()})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func requireJSONError(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	require.NotEmpty(t, body["error"], rec.Body.String())
}

func TestMicrosoftManualRestoreRoutes(t *testing.T) {
	router, limited := newMicrosoftManualRestoreRouter(t)
	require.Equal(t, len(microsoftManualRestorePaths), *limited, "every manual restore route is rate limited")

	const validBody = `{"keys":["a2V5"],"microsoft_auth":"jwt"}`

	t.Run("every route is mounted and requires a session", func(t *testing.T) {
		for _, path := range microsoftManualRestorePaths {
			rec := serveManualRestore(router, http.MethodPost, path, validBody, false)
			require.Equal(t, http.StatusUnauthorized, rec.Code, path)
			requireJSONError(t, rec)
		}
	})

	t.Run("teams chats rejects a missing microsoft_auth", func(t *testing.T) {
		rec := serveManualRestore(router, http.MethodPost, "/office365/satellite-to-teams-chats", `{"keys":["a2V5"]}`, true)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireJSONError(t, rec)
	})

	t.Run("teams chats rejects more than ten keys", func(t *testing.T) {
		keys := strings.TrimSuffix(strings.Repeat(`"a2V5",`, 11), ",")
		rec := serveManualRestore(router, http.MethodPost, "/office365/satellite-to-teams-chats", `{"keys":[`+keys+`],"microsoft_auth":"jwt"}`, true)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireJSONError(t, rec)
	})

	t.Run("teams chats rejects a malformed body", func(t *testing.T) {
		rec := serveManualRestore(router, http.MethodPost, "/office365/satellite-to-teams-chats", `{"keys":`, true)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireJSONError(t, rec)
	})

	t.Run("teams chats is POST only", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := serveManualRestore(router, method, "/office365/satellite-to-teams-chats", validBody, true)
			require.Equal(t, http.StatusMethodNotAllowed, rec.Code, method)
		}
	})

	t.Run("unknown restore paths are not routed", func(t *testing.T) {
		for _, path := range []string{"/office365/satellite-to-teams-chat", "/office365/satellite-to-chats"} {
			rec := serveManualRestore(router, http.MethodPost, path, validBody, true)
			require.Equal(t, http.StatusNotFound, rec.Code, path)
		}
	})
}
