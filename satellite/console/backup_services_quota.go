// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/StorXNetwork/common/uuid"
)

// TriggerBackupServicesQuotaCheck proxies Backup-Tools POST /auto-sync/job/services-quota-check
// for Google or Microsoft backup credentials (same route as storx-google: POST /buckets/quota-check).
// Microsoft-only or Google-only services use that provider's credential; calendar/contacts alone
// use whichever provider is connected (Google first).
func (s *Service) TriggerBackupServicesQuotaCheck(ctx context.Context, tokenKey string, payload []byte) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	req := map[string]interface{}{}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil || req == nil {
			return nil, 0, ErrValidation.New("invalid request body")
		}
	}

	tryOrder := []string{BackupProviderGoogle, BackupProviderMicrosoft}
	if preferred := preferredBackupProviderForServicesQuota(servicesFromQuotaRequest(req)); preferred != "" {
		tryOrder = []string{preferred}
	}

	for _, provider := range tryOrder {
		body, status, err = s.triggerBackupServicesQuotaCheckWithProvider(ctx, tokenKey, req, provider)
		if err == nil || !ErrNotFound.Has(err) {
			return body, status, err
		}
	}
	return nil, 0, err
}

func (s *Service) triggerBackupServicesQuotaCheckWithProvider(ctx context.Context, tokenKey string, req map[string]interface{}, provider string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	if provider == BackupProviderMicrosoft {
		return s.triggerMicrosoftServicesQuotaCheck(ctx, tokenKey, user.ID, req)
	}

	credential, err := s.store.BackupCredentials().GetByUserIDAndProvider(ctx, user.ID, provider)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrNotFound.New("%s backup credentials not found", provider)
		}
		return nil, 0, Error.Wrap(err)
	}
	if err := credential.ValidateForBackup(); err != nil {
		return nil, 0, err
	}

	req["refresh_token"] = credential.RefreshToken
	if accountType := strings.TrimSpace(credential.AccountType); accountType != "" {
		req["account_type"] = accountType
	}
	req["google_email"] = strings.TrimSpace(credential.Email)

	btPayload, err := json.Marshal(req)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPost, "/auto-sync/job/services-quota-check", tokenKey, "", btPayload)
}

// triggerMicrosoftServicesQuotaCheck runs the quota check for the Microsoft account selected by
// credential_id and the tenant selected by tenant_id; the home tenant is never assumed.
func (s *Service) triggerMicrosoftServicesQuotaCheck(ctx context.Context, tokenKey string, userID uuid.UUID, req map[string]interface{}) (body []byte, status int, err error) {
	credentialID, _ := req["credential_id"].(string)
	// credential_id is a Satellite ID; Backup-Tools identifies the account by the headers instead.
	delete(req, "credential_id")

	credential, err := s.resolveMicrosoftCredential(ctx, userID, credentialID)
	if err != nil {
		return nil, 0, err
	}
	if err := credential.ValidateForMicrosoftBackup(); err != nil {
		return nil, 0, err
	}

	tenantID, _ := req["tenant_id"].(string)
	tenantID = strings.ToLower(strings.TrimSpace(tenantID))
	if tenantID == "" {
		return nil, 0, ErrMicrosoftTenantRequired.New("tenant_id is required")
	}
	req["tenant_id"] = tenantID

	req["refresh_token"] = credential.RefreshToken
	if accountType := strings.TrimSpace(credential.AccountType); accountType != "" {
		req["account_type"] = accountType
	}
	req["microsoft_email"] = strings.TrimSpace(credential.Email)

	btPayload, err := json.Marshal(req)
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequestWithExtraHeaders(ctx, http.MethodPost, "/auto-sync/job/services-quota-check", tokenKey, "", microsoftCredentialRefreshToken(credential), microsoftBackupToolsHeaders(credential, tenantID), btPayload)
}

func servicesFromQuotaRequest(req map[string]interface{}) []string {
	raw, _ := req["services"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// preferredBackupProviderForServicesQuota picks credential provider from service names when unambiguous.
func preferredBackupProviderForServicesQuota(services []string) string {
	hasGoogle, hasMicrosoft := false, false
	for _, svc := range services {
		switch strings.ToLower(strings.TrimSpace(svc)) {
		case "drive", "google_drive", "gmail", "photos", "google_photos":
			hasGoogle = true
		case "outlook", "onedrive", "sharepoint", "teams", "groups":
			hasMicrosoft = true
		}
	}
	switch {
	case hasMicrosoft && !hasGoogle:
		return BackupProviderMicrosoft
	case hasGoogle && !hasMicrosoft:
		return BackupProviderGoogle
	default:
		return ""
	}
}
