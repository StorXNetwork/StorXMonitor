// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package userworker

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/common/macaroon"
	"github.com/StorXNetwork/common/uuid"
)

type stubPurger struct {
	err   error
	calls int
}

func (s *stubPurger) PurgeBackupToolsAccount(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID) error {
	s.calls++
	return s.err
}

type stubProjects struct {
	projects []console.Project
	deleted  []uuid.UUID
}

func (s *stubProjects) GetByUserID(ctx context.Context, userID uuid.UUID) ([]console.Project, error) {
	return s.projects, nil
}
func (s *stubProjects) Delete(ctx context.Context, projectID uuid.UUID) error {
	s.deleted = append(s.deleted, projectID)
	return nil
}

type stubUsers struct {
	deleted []uuid.UUID
}

func (s *stubUsers) Delete(ctx context.Context, userID uuid.UUID) error {
	s.deleted = append(s.deleted, userID)
	return nil
}

type stubCreds struct {
	deleted []uuid.UUID
}

func (s *stubCreds) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	s.deleted = append(s.deleted, userID)
	return nil
}

type stubBuckets struct{}

func (s *stubBuckets) ListBuckets(ctx context.Context, projectID uuid.UUID, listOpts buckets.ListOptions, allowedBuckets macaroon.AllowedBuckets) (buckets.List, error) {
	return buckets.List{}, nil
}
func (s *stubBuckets) DeleteBucket(ctx context.Context, bucketName []byte, projectID uuid.UUID) error {
	return nil
}

type stubAPIKeys struct{}

func (s *stubAPIKeys) GetPagedByProjectID(ctx context.Context, projectID uuid.UUID, cursor console.APIKeyCursor) (*console.APIKeyPage, error) {
	return &console.APIKeyPage{}, nil
}
func (s *stubAPIKeys) Delete(ctx context.Context, id uuid.UUID) error { return nil }

func TestDeleteUserWorker_BTPurgeFailureBlocksSatelliteWipe(t *testing.T) {
	userID := uuid.UUID{1}
	projectID := uuid.UUID{2}

	tests := []struct {
		name           string
		purgeErr       error
		wantPurgeCalls int
		wantUserDelete bool
		wantErr        bool
	}{
		{
			name:           "purge success deletes user",
			purgeErr:       nil,
			wantPurgeCalls: 1,
			wantUserDelete: true,
			wantErr:        false,
		},
		{
			name:           "purge failure blocks satellite wipe",
			purgeErr:       errors.New("bt purge failed"),
			wantPurgeCalls: 1,
			wantUserDelete: false,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purger := &stubPurger{err: tt.purgeErr}
			users := &stubUsers{}
			creds := &stubCreds{}
			projects := &stubProjects{projects: []console.Project{{ID: projectID}}}

			worker := &DeleteUserWorker{
				log:               zap.NewNop(),
				projects:          projects,
				apiKeys:           &stubAPIKeys{},
				buckets:           &stubBuckets{},
				users:             users,
				backupCredentials: creds,
				btPurger:          purger,
			}

			err := worker.deleteAllData(context.Background(), userID)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantPurgeCalls, purger.calls)
			if tt.wantUserDelete {
				require.Equal(t, []uuid.UUID{userID}, users.deleted)
				require.Equal(t, []uuid.UUID{userID}, creds.deleted)
				require.Equal(t, []uuid.UUID{projectID}, projects.deleted)
			} else {
				require.Empty(t, users.deleted)
				require.Empty(t, creds.deleted)
				require.Empty(t, projects.deleted)
			}
		})
	}
}
