// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// MicrosoftBackupUsersGroupsJobsActiveRequest is the UI body for PUT /microsoft/users-groups/jobs/active.
type MicrosoftBackupUsersGroupsJobsActiveRequest struct {
	JobIDs []int `json:"job_ids"`
	Active bool  `json:"active"`
}

func (r *MicrosoftBackupUsersGroupsJobsActiveRequest) Validate() error {
	if len(r.JobIDs) == 0 {
		return ErrValidation.New("job_ids is required")
	}
	return nil
}

func (r MicrosoftBackupUsersGroupsJobsActiveRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"job_ids": r.JobIDs,
		"active":  r.Active,
	})
}

func (s *Service) getMicrosoftBackupUsersGroups(ctx context.Context, tokenKey, path, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if query != "" {
		path += "?" + query
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func microsoftBackupUsersGroupsMailboxQuery(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", ErrValidation.New("email is required")
	}
	return url.Values{"email": {email}}.Encode(), nil
}

// GetMicrosoftBackupUsersGroupsDomains proxies Backup-Tools GET /microsoft/users-groups/domains.
func (s *Service) GetMicrosoftBackupUsersGroupsDomains(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupUsersGroups(ctx, tokenKey, "/microsoft/users-groups/domains", "")
}

// ListMicrosoftBackupUsersGroups proxies Backup-Tools GET /microsoft/users-groups.
func (s *Service) ListMicrosoftBackupUsersGroups(ctx context.Context, tokenKey, query string) (body []byte, status int, err error) {
	return s.getMicrosoftBackupUsersGroups(ctx, tokenKey, "/microsoft/users-groups", query)
}

// GetMicrosoftBackupUsersGroupsMailboxOverview proxies Backup-Tools GET /microsoft/users-groups/mailbox/overview.
func (s *Service) GetMicrosoftBackupUsersGroupsMailboxOverview(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := microsoftBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getMicrosoftBackupUsersGroups(ctx, tokenKey, "/microsoft/users-groups/mailbox/overview", query)
}

// GetMicrosoftBackupUsersGroupsMailboxServices proxies Backup-Tools GET /microsoft/users-groups/mailbox/services.
func (s *Service) GetMicrosoftBackupUsersGroupsMailboxServices(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := microsoftBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getMicrosoftBackupUsersGroups(ctx, tokenKey, "/microsoft/users-groups/mailbox/services", query)
}

// GetMicrosoftBackupUsersGroupsMailboxSchedule proxies Backup-Tools GET /microsoft/users-groups/mailbox/schedule.
func (s *Service) GetMicrosoftBackupUsersGroupsMailboxSchedule(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := microsoftBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getMicrosoftBackupUsersGroups(ctx, tokenKey, "/microsoft/users-groups/mailbox/schedule", query)
}

// GetMicrosoftBackupUsersGroupsMailboxCredentials proxies Backup-Tools GET /microsoft/users-groups/mailbox/credentials.
func (s *Service) GetMicrosoftBackupUsersGroupsMailboxCredentials(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := microsoftBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getMicrosoftBackupUsersGroups(ctx, tokenKey, "/microsoft/users-groups/mailbox/credentials", query)
}

// UpdateMicrosoftBackupUsersGroupsJobsActive proxies Backup-Tools PUT /microsoft/users-groups/jobs/active.
func (s *Service) UpdateMicrosoftBackupUsersGroupsJobsActive(ctx context.Context, tokenKey string, req MicrosoftBackupUsersGroupsJobsActiveRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := (&req).Validate(); err != nil {
		return nil, 0, err
	}

	payload, err := (&req).backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPut, "/microsoft/users-groups/jobs/active", tokenKey, "", payload)
}
