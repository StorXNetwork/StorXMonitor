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

// microsoftAccessVerifyProxyMeta is the credential/tenant selection carried on access-verify POSTs.
type microsoftAccessVerifyProxyMeta struct {
	CredentialID   string `json:"credential_id"`
	TenantID       string `json:"tenant_id"`
	MicrosoftEmail string `json:"microsoft_email"`
}

// StartMicrosoftAccessVerify proxies Backup-Tools POST /microsoft/users-groups/access-verify/start.
func (s *Service) StartMicrosoftAccessVerify(ctx context.Context, tokenKey string, rawBody []byte) (body []byte, status int, err error) {
	return s.proxyMicrosoftAccessVerifyPOST(ctx, tokenKey, "/microsoft/users-groups/access-verify/start", rawBody, true)
}

// StatusMicrosoftAccessVerify proxies Backup-Tools GET /microsoft/users-groups/access-verify/status/:id.
func (s *Service) StatusMicrosoftAccessVerify(ctx context.Context, tokenKey, systemJobID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)
	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	id := strings.TrimSpace(systemJobID)
	if id == "" {
		return nil, 0, ErrValidation.New("system_job_id is required")
	}
	return s.backupToolsRequest(ctx, http.MethodGet, "/microsoft/users-groups/access-verify/status/"+id, tokenKey, "", nil)
}

// RecheckMicrosoftAccessVerify proxies Backup-Tools POST /microsoft/users-groups/access-verify/recheck.
func (s *Service) RecheckMicrosoftAccessVerify(ctx context.Context, tokenKey string, rawBody []byte) (body []byte, status int, err error) {
	return s.proxyMicrosoftAccessVerifyPOST(ctx, tokenKey, "/microsoft/users-groups/access-verify/recheck", rawBody, false)
}

func (s *Service) proxyMicrosoftAccessVerifyPOST(ctx context.Context, tokenKey, path string, rawBody []byte, requireTenant bool) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	user, err := GetUser(ctx)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	var meta microsoftAccessVerifyProxyMeta
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &meta); err != nil {
			return nil, 0, ErrValidation.New("invalid JSON body")
		}
	}
	tenantID := strings.ToLower(strings.TrimSpace(meta.TenantID))
	if requireTenant && tenantID == "" {
		return nil, 0, ErrMicrosoftTenantRequired.New("tenant_id is required")
	}

	credential, err := s.resolveMicrosoftJobCredential(ctx, user.ID, meta.CredentialID, meta.MicrosoftEmail)
	if err != nil {
		return nil, 0, err
	}

	payload := rawBody
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	return s.backupToolsRequestWithExtraHeaders(
		ctx,
		http.MethodPost,
		path,
		tokenKey,
		"",
		microsoftCredentialRefreshToken(credential),
		microsoftBackupToolsHeaders(credential, tenantID),
		payload,
	)
}
