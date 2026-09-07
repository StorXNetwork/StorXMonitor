// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

// BackupToolsAccountRequest is the body for Backup-Tools account lifecycle APIs.
//
//	POST /internal/account/pending-delete  — soft delete: pause/cancel jobs, set tombstone
//	POST /internal/account/resume         — cancel deletion: clear tombstone (do not auto-resume jobs)
//	POST /internal/account/purge          — hard delete: idempotent wipe of BT data for the user
type BackupToolsAccountRequest struct {
	SatelliteUserID string   `json:"satellite_user_id"`
	ProjectIDs      []string `json:"project_ids,omitempty"`
	DeleteAt        string   `json:"delete_at,omitempty"`
}

var backupToolsHTTPClient = &http.Client{Timeout: 60 * time.Second}

// NotifyBackupToolsAccountPendingDelete tells Backup-Tools to stop backup/restore activity for the user.
func (s *Service) NotifyBackupToolsAccountPendingDelete(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID, deleteAt time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)
	return s.backupToolsAccountRequest(ctx, http.MethodPost, "/internal/account/pending-delete", userID, projectIDs, &deleteAt, false)
}

// NotifyBackupToolsAccountResume tells Backup-Tools to clear the pending-delete tombstone.
func (s *Service) NotifyBackupToolsAccountResume(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	return s.backupToolsAccountRequest(ctx, http.MethodPost, "/internal/account/resume", userID, projectIDs, nil, false)
}

// PurgeBackupToolsAccount tells Backup-Tools to permanently wipe account data (must succeed before Satellite user delete).
func (s *Service) PurgeBackupToolsAccount(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	// Fail closed: hard delete must not proceed without a successful BT purge when BT is expected.
	return s.backupToolsAccountRequest(ctx, http.MethodPost, "/internal/account/purge", userID, projectIDs, nil, true)
}

// requireConfigured: when true, missing BackupToolsURL is an error (purge). Soft/cancel may skip in local/dev.
func (s *Service) backupToolsAccountRequest(ctx context.Context, method, path string, userID uuid.UUID, projectIDs []uuid.UUID, deleteAt *time.Time, requireConfigured bool) error {
	if s.backupToolsURL == "" {
		if requireConfigured {
			return Error.New("Backup-Tools URL not configured")
		}
		s.log.Warn("Backup-Tools URL not configured; skipping account lifecycle call",
			zap.String("path", path),
			zap.String("user_id", userID.String()),
		)
		return nil
	}

	body := BackupToolsAccountRequest{
		SatelliteUserID: userID.String(),
		ProjectIDs:      make([]string, 0, len(projectIDs)),
	}
	for _, id := range projectIDs {
		body.ProjectIDs = append(body.ProjectIDs, id.String())
	}
	if deleteAt != nil {
		body.DeleteAt = deleteAt.UTC().Format(time.RFC3339)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Error.Wrap(err)
	}

	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.backupToolsURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return Error.Wrap(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(s.backupToolsAPIKey); key != "" {
		req.Header.Set("X-API-Key", key)
	}

	resp, err := backupToolsHTTPClient.Do(req)
	if err != nil {
		return Error.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Error.New("Backup-Tools %s returned status %d: %s", path, resp.StatusCode, string(respBody))
	}
	return nil
}
