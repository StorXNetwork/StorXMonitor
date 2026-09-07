// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestMemberBucketGrantsInvalidJSON(t *testing.T) {
	t.Parallel()

	log := zaptest.NewLogger(t)
	h := NewMemberBucketGrants(log, nil)

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		vars    map[string]string
		body    string
	}{
		{
			name:    "add acl bucket",
			handler: h.AddACLBucket,
			path:    "/projects/{id}/member-acl-buckets",
			vars:    map[string]string{"id": "00000000-0000-0000-0000-000000000001"},
			body:    "{",
		},
		{
			name:    "put member grants",
			handler: h.PutMemberGrants,
			path:    "/projects/{id}/members/{memberID}/bucket-grants",
			vars: map[string]string{
				"id":       "00000000-0000-0000-0000-000000000001",
				"memberID": "00000000-0000-0000-0000-000000000002",
			},
			body: "not-json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewBufferString(tt.body))
			req = mux.SetURLVars(req, tt.vars)
			rec := httptest.NewRecorder()
			tt.handler(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

func TestMemberBucketGrantInputJSON(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(struct {
		Grants []console.MemberBucketGrantInput `json:"grants"`
	}{Grants: []console.MemberBucketGrantInput{}})
	require.NoError(t, err)
	require.JSONEq(t, `{"grants":[]}`, string(body))
}
