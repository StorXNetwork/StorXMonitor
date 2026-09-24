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

// GoogleBackupUsersGroupsJobsActiveRequest is the UI body for Backup-Tools PUT /users-groups/jobs/active.
type GoogleBackupUsersGroupsJobsActiveRequest struct {
	JobIDs []int `json:"job_ids"`
	Active bool  `json:"active"`
}

func (r *GoogleBackupUsersGroupsJobsActiveRequest) Validate() error {
	if len(r.JobIDs) == 0 {
		return ErrValidation.New("job_ids is required")
	}
	return nil
}

func (r GoogleBackupUsersGroupsJobsActiveRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"job_ids": r.JobIDs,
		"active":  r.Active,
	})
}

func (s *Service) getGoogleBackupUsersGroups(ctx context.Context, tokenKey, path, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if query != "" {
		path += "?" + query
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func googleBackupUsersGroupsMailboxQuery(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", ErrValidation.New("email is required")
	}
	return url.Values{"email": {email}}.Encode(), nil
}

// GetGoogleBackupUsersGroupsDomains proxies Backup-Tools GET /users-groups/domains.
func (s *Service) GetGoogleBackupUsersGroupsDomains(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.getGoogleBackupUsersGroups(ctx, tokenKey, "/users-groups/domains", "")
}

// ListGoogleBackupUsersGroups proxies Backup-Tools GET /users-groups.
func (s *Service) ListGoogleBackupUsersGroups(ctx context.Context, tokenKey, query string) (body []byte, status int, err error) {
	return s.getGoogleBackupUsersGroups(ctx, tokenKey, "/users-groups", query)
}

// GetGoogleBackupUsersGroupsMailboxOverview proxies Backup-Tools GET /users-groups/mailbox/overview.
func (s *Service) GetGoogleBackupUsersGroupsMailboxOverview(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := googleBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getGoogleBackupUsersGroups(ctx, tokenKey, "/users-groups/mailbox/overview", query)
}

// GetGoogleBackupUsersGroupsMailboxServices proxies Backup-Tools GET /users-groups/mailbox/services.
func (s *Service) GetGoogleBackupUsersGroupsMailboxServices(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := googleBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getGoogleBackupUsersGroups(ctx, tokenKey, "/users-groups/mailbox/services", query)
}

// GetGoogleBackupUsersGroupsMailboxSchedule proxies Backup-Tools GET /users-groups/mailbox/schedule.
func (s *Service) GetGoogleBackupUsersGroupsMailboxSchedule(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := googleBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getGoogleBackupUsersGroups(ctx, tokenKey, "/users-groups/mailbox/schedule", query)
}

// GetGoogleBackupUsersGroupsMailboxCredentials proxies Backup-Tools GET /users-groups/mailbox/credentials.
func (s *Service) GetGoogleBackupUsersGroupsMailboxCredentials(ctx context.Context, tokenKey, email string) (body []byte, status int, err error) {
	query, err := googleBackupUsersGroupsMailboxQuery(email)
	if err != nil {
		return nil, 0, err
	}
	return s.getGoogleBackupUsersGroups(ctx, tokenKey, "/users-groups/mailbox/credentials", query)
}

// GetGoogleBackupDashboardAlerts proxies Backup-Tools GET /autosync/dashboard-alerts
// and attaches own_nodes readiness for sidebar / onboarding warnings.
// When own_nodes is under MinOwnNodesRequired, forces Backup-Tools jobs inactive
// so cron cannot keep "push to queue".
func (s *Service) GetGoogleBackupDashboardAlerts(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	body, status, err = s.getGoogleBackupUsersGroups(ctx, tokenKey, "/autosync/dashboard-alerts", "")
	if err != nil || status != http.StatusOK {
		return body, status, err
	}
	user, userErr := GetUser(ctx)
	if userErr != nil {
		return body, status, nil
	}
	ownStatus, stErr := s.ownNodesCapacityForUser(ctx, user.ID)
	if stErr != nil || ownStatus == nil {
		return body, status, nil
	}
	s.enforceOwnNodesInactiveJobs(ctx, tokenKey, ownStatus)
	return mergeOwnNodesIntoJSONObject(body, "own_nodes", ownStatus), status, nil
}

// UpdateGoogleBackupUsersGroupsJobsActive proxies Backup-Tools PUT /users-groups/jobs/active.
func (s *Service) UpdateGoogleBackupUsersGroupsJobsActive(ctx context.Context, tokenKey string, req GoogleBackupUsersGroupsJobsActiveRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := (&req).Validate(); err != nil {
		return nil, 0, err
	}
	if req.Active {
		user, userErr := GetUser(ctx)
		if userErr != nil {
			return nil, 0, Error.Wrap(userErr)
		}
		if gateErr := s.requireOwnNodesReadyForActivation(ctx, user.ID); gateErr != nil {
			return nil, 0, gateErr
		}
	}

	payload, err := (&req).backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPut, "/users-groups/jobs/active", tokenKey, "", payload)
}
