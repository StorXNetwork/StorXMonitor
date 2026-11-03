// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
)

const teamsChatsRestorePath = "/office365/satellite-to-teams-chats"

// manualRestoreStub is a Backup-Tools stub that answers every request with a fixed status and body.
type manualRestoreStub struct {
	status int
	body   string
	drop   bool

	mu    sync.Mutex
	calls []backupToolsCall
}

func newManualRestoreStub(t *testing.T, status int, body string) (*manualRestoreStub, *Service) {
	stub := &manualRestoreStub{status: status, body: body}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		stub.mu.Lock()
		stub.calls = append(stub.calls, backupToolsCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), RawBody: string(raw)})
		drop := stub.drop
		stub.mu.Unlock()
		if drop {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stub.status)
		_, _ = w.Write([]byte(stub.body))
	}))
	t.Cleanup(server.Close)
	return stub, &Service{log: zaptest.NewLogger(t), backupToolsURL: server.URL}
}

func (s *manualRestoreStub) callsSnapshot() []backupToolsCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]backupToolsCall(nil), s.calls...)
}

func TestMicrosoftManualRestoreTeamsChatsForwarding(t *testing.T) {
	const payload = `["a2V5LTE=","a2V5LTI="]`

	t.Run("success is forwarded byte for byte", func(t *testing.T) {
		const respBody = `{"items":[{"key":"a2V5LTE=","status":"restored","ref":"msg-1"}],"skipped_ids":["a2V5LTI="],"outcome_unknown":[]}`
		stub, service := newManualRestoreStub(t, http.StatusOK, respBody)

		body, status, err := service.backupToolsMicrosoftManualRestoreRequest(context.Background(), http.MethodPost, teamsChatsRestorePath, "session-key", " grant ", "Bearer ms-jwt", []byte(payload))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, respBody, string(body))

		calls := stub.callsSnapshot()
		require.Len(t, calls, 1)
		call := calls[0]
		require.Equal(t, http.MethodPost, call.Method)
		require.Equal(t, teamsChatsRestorePath, call.Path)
		require.Equal(t, payload, call.RawBody)
		require.Equal(t, "session-key", call.Header.Get("token_key"))
		require.Equal(t, "grant", call.Header.Get("ACCESS_TOKEN"))
		require.Equal(t, "ms-jwt", call.Header.Get("Authorization"))
		require.Equal(t, "application/json", call.Header.Get("Content-Type"))
		require.Empty(t, call.Header.Get("X-Restore-As-User"))
	})

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"refused by Backup-Tools", http.StatusForbidden, `{"error":"teams restore is not available for organization connections"}`},
		{"bad request", http.StatusBadRequest, `{"error":"invalid key"}`},
		{"internal error", http.StatusInternalServerError, `{"error":"restore failed"}`},
		{"gateway timeout", http.StatusGatewayTimeout, `{"error":"timeout","outcome":"unknown"}`},
	} {
		t.Run(tc.name+" keeps status and body and is not retried", func(t *testing.T) {
			stub, service := newManualRestoreStub(t, tc.status, tc.body)

			body, status, err := service.backupToolsMicrosoftManualRestoreRequest(context.Background(), http.MethodPost, teamsChatsRestorePath, "session-key", "grant", "ms-jwt", []byte(payload))
			require.NoError(t, err)
			require.Equal(t, tc.status, status)
			require.Equal(t, tc.body, string(body))
			require.Len(t, stub.callsSnapshot(), 1)
		})
	}

	t.Run("dropped connection is an error and is not retried", func(t *testing.T) {
		stub, service := newManualRestoreStub(t, http.StatusOK, `{}`)
		stub.drop = true

		body, status, err := service.backupToolsMicrosoftManualRestoreRequest(context.Background(), http.MethodPost, teamsChatsRestorePath, "session-key", "grant", "ms-jwt", []byte(payload))
		require.Error(t, err)
		require.Zero(t, status)
		require.Nil(t, body)
		require.Len(t, stub.callsSnapshot(), 1)
	})

	t.Run("missing Backup-Tools URL never sends", func(t *testing.T) {
		_, _, err := (&Service{}).backupToolsMicrosoftManualRestoreRequest(context.Background(), http.MethodPost, teamsChatsRestorePath, "session-key", "grant", "ms-jwt", []byte(payload))
		require.Error(t, err)
	})
}

func TestMicrosoftManualRestoreValidationBeforeBackupTools(t *testing.T) {
	keys := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "a2V5"
		}
		return out
	}

	for _, tc := range []struct {
		name string
		req  MicrosoftBackupManualRestoreRequest
	}{
		{"missing microsoft_auth", MicrosoftBackupManualRestoreRequest{Keys: keys(1)}},
		{"blank microsoft_auth", MicrosoftBackupManualRestoreRequest{Keys: keys(1), MicrosoftAuth: "  "}},
		{"no keys", MicrosoftBackupManualRestoreRequest{MicrosoftAuth: "jwt"}},
		{"more than ten keys", MicrosoftBackupManualRestoreRequest{Keys: keys(11), MicrosoftAuth: "jwt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub, service := newManualRestoreStub(t, http.StatusOK, `{}`)
			ctx := WithUser(context.Background(), &User{ID: testrand.UUID()})

			_, _, err := service.MicrosoftBackupManualRestore(ctx, "session-key", teamsChatsRestorePath, tc.req)
			require.True(t, ErrValidation.Has(err), "%v", err)
			require.Empty(t, stub.callsSnapshot())
		})
	}

	t.Run("missing session token is unauthorized", func(t *testing.T) {
		stub, service := newManualRestoreStub(t, http.StatusOK, `{}`)
		_, _, err := service.MicrosoftBackupManualRestore(context.Background(), " ", teamsChatsRestorePath, MicrosoftBackupManualRestoreRequest{Keys: keys(10), MicrosoftAuth: "jwt"})
		require.True(t, ErrUnauthorized.Has(err), "%v", err)
		require.Empty(t, stub.callsSnapshot())
	})
}

type fakeSharedProjects struct {
	Projects
	byID map[uuid.UUID]*Project
}

func (f fakeSharedProjects) Get(ctx context.Context, id uuid.UUID) (*Project, error) {
	return f.GetByPublicOrPrivateID(ctx, id)
}

func (f fakeSharedProjects) GetByPublicOrPrivateID(_ context.Context, id uuid.UUID) (*Project, error) {
	if p, ok := f.byID[id]; ok {
		c := *p
		return &c, nil
	}
	return nil, sql.ErrNoRows
}

type fakeSharedMembers struct {
	ProjectMembers
	byMember map[uuid.UUID][]ProjectMember
}

func (f fakeSharedMembers) GetByMemberID(_ context.Context, memberID uuid.UUID) ([]ProjectMember, error) {
	return f.byMember[memberID], nil
}

// fakeSharedRestoreDB adds the project and membership lookups used by shared restore.
type fakeSharedRestoreDB struct {
	*fakeConsoleDB
	projects fakeSharedProjects
	members  fakeSharedMembers
}

func (db *fakeSharedRestoreDB) Projects() Projects             { return db.projects }
func (db *fakeSharedRestoreDB) ProjectMembers() ProjectMembers { return db.members }

func TestMicrosoftRestoreAllSharedProjectOwner(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	owner := h.user
	ownerCredential := h.addCredential(owner.ID, BackupProviderMicrosoft, "owner@contoso.com", "oid-owner", "tenant-home")

	project := &Project{ID: testrand.UUID(), PublicID: testrand.UUID(), OwnerID: owner.ID}
	invitee := &User{ID: testrand.UUID(), Email: "invitee@storx.test"}
	admin := &User{ID: testrand.UUID(), Email: "admin@storx.test"}
	outsider := &User{ID: testrand.UUID(), Email: "outsider@storx.test"}

	h.service.store = &fakeSharedRestoreDB{
		fakeConsoleDB: h.service.store.(*fakeConsoleDB),
		projects:      fakeSharedProjects{byID: map[uuid.UUID]*Project{project.ID: project, project.PublicID: project}},
		members: fakeSharedMembers{byMember: map[uuid.UUID][]ProjectMember{
			owner.ID:   {{MemberID: owner.ID, ProjectID: project.ID, Role: RoleAdmin}},
			invitee.ID: {{MemberID: invitee.ID, ProjectID: project.ID, Role: RoleMember}},
			admin.ID:   {{MemberID: admin.ID, ProjectID: project.ID, Role: RoleAdmin}},
		}},
	}

	restoreAll := func(user *User, credentialID string) (backupToolsCall, error) {
		before := h.callCount()
		_, _, err := h.service.StartMicrosoftBackupRestoreAll(WithUser(context.Background(), user), "session", MicrosoftBackupRestoreAllRequest{
			Service:      "teams",
			ProjectID:    project.PublicID.String(),
			LoginID:      "owner@contoso.com",
			TenantID:     "tenant-home",
			CredentialID: credentialID,
		})
		if err != nil || h.callCount() == before {
			return backupToolsCall{}, err
		}
		return h.lastCall(), nil
	}

	t.Run("invited member restores with the owner's connection", func(t *testing.T) {
		call, err := restoreAll(invitee, "")
		require.NoError(t, err)
		require.Equal(t, "/restore/all", call.Path)
		require.Equal(t, owner.ID.String(), call.Header.Get("X-Restore-As-User"))
		require.Equal(t, "1.refresh-owner@contoso.com", call.Header.Get("REFRESH_TOKEN"))
		requireMicrosoftHeaders(t, call, "oid-owner", "tenant-home", "tenant-home")
	})

	t.Run("invited member may pick the owner's credential", func(t *testing.T) {
		call, err := restoreAll(invitee, ownerCredential.ID.String())
		require.NoError(t, err)
		require.Equal(t, owner.ID.String(), call.Header.Get("X-Restore-As-User"))
	})

	t.Run("invited member cannot use another user's credential", func(t *testing.T) {
		foreign := h.addCredential(testrand.UUID(), BackupProviderMicrosoft, "mallory@contoso.com", "oid-m", "tenant-home")
		before := h.callCount()
		_, err := restoreAll(invitee, foreign.ID.String())
		require.True(t, ErrMicrosoftCredentialNotFound.Has(err), "%v", err)
		require.Equal(t, before, h.callCount())
	})

	t.Run("owner restores as themself", func(t *testing.T) {
		call, err := restoreAll(owner, "")
		require.NoError(t, err)
		require.Empty(t, call.Header.Get("X-Restore-As-User"))
		requireMicrosoftHeaders(t, call, "oid-owner", "tenant-home", "tenant-home")
	})

	t.Run("admin keeps their own connection", func(t *testing.T) {
		before := h.callCount()
		_, err := restoreAll(admin, "")
		require.True(t, ErrNotFound.Has(err), "%v", err)
		require.Equal(t, before, h.callCount())
	})

	t.Run("non-member gets no access to the owner's connection", func(t *testing.T) {
		before := h.callCount()
		_, err := restoreAll(outsider, "")
		require.True(t, ErrNotFound.Has(err), "%v", err)
		require.Equal(t, before, h.callCount())
	})

	t.Run("prepare for an invited member uses the owner", func(t *testing.T) {
		_, _, err := h.service.PrepareMicrosoftBackupRestore(WithUser(context.Background(), invitee), "session", MicrosoftBackupRestorePrepareParams{
			ProjectID: project.PublicID.String(),
			LoginID:   "owner@contoso.com",
			Service:   "teams",
			TenantID:  "tenant-home",
		})
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/restore/prepare", call.Path)
		require.Equal(t, owner.ID.String(), call.Header.Get("X-Restore-As-User"))
		require.True(t, strings.HasPrefix(call.Header.Get("REFRESH_TOKEN"), "1.refresh-owner"))
	})
}
