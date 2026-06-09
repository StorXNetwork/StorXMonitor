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

// UpdateGoogleBackupAutoSyncPolicyRequest is the UI body for Backup-Tools PUT /auto-sync/policy/{policy_id}.
type UpdateGoogleBackupAutoSyncPolicyRequest struct {
	Interval       string `json:"interval"`
	On             string `json:"on"`
	RetentionType  string `json:"retention_type,omitempty"`
	ApplyAll       *bool  `json:"apply_all,omitempty"`
	SelectedJobIDs []int  `json:"selected_job_ids,omitempty"`
}

// MergeGoogleBackupAutoSyncPoliciesRequest is the UI body for Backup-Tools POST /auto-sync/policy/merge.
type MergeGoogleBackupAutoSyncPoliciesRequest struct {
	PolicyIDs []int `json:"policy_ids"`
}

var (
	allowedGoogleBackupPolicyIntervals = map[string]struct{}{
		"3h": {}, "12h": {}, "daily": {}, "weekly": {}, "monthly": {},
	}
	allowedGoogleBackupPolicyRetentionTypes = map[string]struct{}{
		"never": {}, "30_days": {}, "1_year": {}, "7_years": {},
	}
)

func (r UpdateGoogleBackupAutoSyncPolicyRequest) Validate() error {
	if strings.TrimSpace(r.Interval) == "" {
		return ErrValidation.New("interval is required")
	}
	interval := normalizeGoogleBackupPolicyInterval(r.Interval)
	if _, ok := allowedGoogleBackupPolicyIntervals[interval]; !ok {
		return ErrValidation.New("unsupported interval: %s", interval)
	}
	if retention := strings.TrimSpace(r.RetentionType); retention != "" {
		if _, ok := allowedGoogleBackupPolicyRetentionTypes[retention]; !ok {
			return ErrValidation.New("unsupported retention_type: %s", retention)
		}
	}
	return nil
}

func (r UpdateGoogleBackupAutoSyncPolicyRequest) backupToolsPayload() ([]byte, error) {
	out := map[string]interface{}{
		"interval": normalizeGoogleBackupPolicyInterval(r.Interval),
		"on":       strings.TrimSpace(r.On),
	}
	if v := strings.TrimSpace(r.RetentionType); v != "" {
		out["retention_type"] = v
	}
	if r.ApplyAll != nil {
		out["apply_all"] = *r.ApplyAll
	}
	if len(r.SelectedJobIDs) > 0 {
		out["selected_job_ids"] = r.SelectedJobIDs
	}
	return json.Marshal(out)
}

func (r MergeGoogleBackupAutoSyncPoliciesRequest) Validate() error {
	if len(r.PolicyIDs) < 2 {
		return ErrValidation.New("at least two policy_ids are required")
	}
	return nil
}

func (r MergeGoogleBackupAutoSyncPoliciesRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"policy_ids": r.PolicyIDs,
	})
}

func normalizeGoogleBackupPolicyInterval(interval string) string {
	interval = strings.ToLower(strings.TrimSpace(interval))
	switch interval {
	case "24h", "nightly", "7d":
		return "daily"
	default:
		return interval
	}
}

func (s *Service) ListGoogleBackupAutoSyncPolicies(ctx context.Context, tokenKey, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	path := "/auto-sync/policy"
	if query != "" {
		path += "?" + query
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func (s *Service) GetGoogleBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, 0, ErrValidation.New("policy_id is required")
	}

	path := "/auto-sync/policy/" + url.PathEscape(policyID)
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func (s *Service) GetGoogleBackupAutoSyncPolicyByJob(ctx context.Context, tokenKey, jobID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, 0, ErrValidation.New("job_id is required")
	}

	path := "/auto-sync/policy/by-job/" + url.PathEscape(jobID)
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func (s *Service) UpdateGoogleBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID string, req UpdateGoogleBackupAutoSyncPolicyRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, 0, ErrValidation.New("policy_id is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	path := "/auto-sync/policy/" + url.PathEscape(policyID)
	return s.backupToolsRequest(ctx, http.MethodPut, path, tokenKey, "", btPayload)
}

func (s *Service) PreviewMergeGoogleBackupAutoSyncPolicies(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}

	return s.backupToolsRequest(ctx, http.MethodGet, "/auto-sync/policy/merge/preview", tokenKey, "", nil)
}

func (s *Service) MergeGoogleBackupAutoSyncPolicies(ctx context.Context, tokenKey string, req MergeGoogleBackupAutoSyncPoliciesRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	btPayload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}

	return s.backupToolsRequest(ctx, http.MethodPost, "/auto-sync/policy/merge", tokenKey, "", btPayload)
}
