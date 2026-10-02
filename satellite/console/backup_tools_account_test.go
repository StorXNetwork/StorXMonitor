// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

func TestBackupToolsAccountLifecycleClients(t *testing.T) {
	userID := uuid.UUID{9}
	projectID := uuid.UUID{8}
	deleteAt := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		call       func(s *Service) error
		wantPath   string
		wantStatus int
		wantErr    bool
		checkBody  bool
	}{
		{
			name: "pending-delete",
			call: func(s *Service) error {
				return s.NotifyBackupToolsAccountPendingDelete(t.Context(), userID, []uuid.UUID{projectID}, deleteAt)
			},
			wantPath:   "/internal/account/pending-delete",
			wantStatus: http.StatusOK,
			checkBody:  true,
		},
		{
			name: "resume",
			call: func(s *Service) error {
				return s.NotifyBackupToolsAccountResume(t.Context(), userID, []uuid.UUID{projectID})
			},
			wantPath:   "/internal/account/resume",
			wantStatus: http.StatusOK,
		},
		{
			name: "purge",
			call: func(s *Service) error {
				return s.PurgeBackupToolsAccount(t.Context(), userID, []uuid.UUID{projectID})
			},
			wantPath:   "/internal/account/purge",
			wantStatus: http.StatusOK,
		},
		{
			name: "purge failure",
			call: func(s *Service) error {
				return s.PurgeBackupToolsAccount(t.Context(), userID, nil)
			},
			wantPath:   "/internal/account/purge",
			wantStatus: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotAPIKey, gotBody string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAPIKey = r.Header.Get("X-API-Key")
				body, _ := io.ReadAll(r.Body)
				gotBody = string(body)
				w.WriteHeader(tt.wantStatus)
			}))
			defer srv.Close()

			s := &Service{
				log:               zap.NewNop(),
				backupToolsURL:    srv.URL,
				backupToolsAPIKey: "test-key",
			}

			err := tt.call(s)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantPath, gotPath)
			require.Equal(t, "test-key", gotAPIKey)
			if tt.checkBody {
				var req BackupToolsAccountRequest
				require.NoError(t, json.Unmarshal([]byte(gotBody), &req))
				require.Equal(t, userID.String(), req.SatelliteUserID)
				require.Equal(t, []string{projectID.String()}, req.ProjectIDs)
				require.Equal(t, deleteAt.Format(time.RFC3339), req.DeleteAt)
			}
		})
	}
}

func TestPurgeBackupToolsAccountRequiresURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "empty url fails closed",
			url:     "",
			wantErr: "Backup-Tools URL not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{log: zap.NewNop(), backupToolsURL: tt.url}
			err := s.PurgeBackupToolsAccount(t.Context(), uuid.UUID{1}, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestEnsurePendingDeletionLoginAllowed(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		user    *User
		req     *UserDeleteRequest
		wantErr string
	}{
		{
			name: "active user allowed",
			user: &User{Status: Active},
		},
		{
			name: "pending with future delete_at allowed",
			user: &User{ID: uuid.UUID{1}, Status: PendingDeletion},
			req:  &UserDeleteRequest{DeleteAt: now.Add(24 * time.Hour)},
		},
		{
			name: "pending without active request allowed for recovery",
			user: &User{ID: uuid.UUID{1}, Status: PendingDeletion},
			req:  nil,
		},
		{
			name:    "pending with past delete_at rejected",
			user:    &User{ID: uuid.UUID{1}, Status: PendingDeletion},
			req:     &UserDeleteRequest{DeleteAt: now.Add(-time.Hour)},
			wantErr: "account deleted / deletion in progress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &memoryDeleteUsers{req: tt.req}
			s := &Service{
				store: &memoryDB{users: store},
				nowFn: func() time.Time { return now },
			}
			err := s.ensurePendingDeletionLoginAllowed(t.Context(), tt.user)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

type memoryDeleteUsers struct {
	Users
	req *UserDeleteRequest
}

func (m *memoryDeleteUsers) GetActiveDeleteRequest(ctx context.Context, userID uuid.UUID) (*UserDeleteRequest, error) {
	return m.req, nil
}

type memoryDB struct {
	DB
	users *memoryDeleteUsers
}

func (m *memoryDB) Users() Users { return m.users }
