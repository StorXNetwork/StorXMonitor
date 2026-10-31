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

// UpdateBackupAutoSyncPolicyRequest is the UI body for Backup-Tools PUT /auto-sync/policy/{policy_id}.
type UpdateBackupAutoSyncPolicyRequest struct {
	Interval      string `json:"interval"`
	On            string `json:"on"`
	RetentionType string `json:"retention_type"`
}

// CreateBackupAutoSyncPolicyRequest is the UI body for Backup-Tools POST /auto-sync/policy.
type CreateBackupAutoSyncPolicyRequest struct {
	Name          string `json:"name"`
	Interval      string `json:"interval"`
	On            string `json:"on"`
	RetentionType string `json:"retention_type"`
	JobIDs        []int  `json:"job_ids,omitempty"`
}

// MoveBackupAutoSyncPolicyAssignmentsRequest is the UI body for Backup-Tools POST /auto-sync/policy/move.
type MoveBackupAutoSyncPolicyAssignmentsRequest struct {
	TargetPolicyID int   `json:"target_policy_id"`
	JobIDs         []int `json:"job_ids"`
}

// MergeBackupAutoSyncPoliciesRequest is the UI body for Backup-Tools POST /auto-sync/policy/merge.
type MergeBackupAutoSyncPoliciesRequest struct {
	PolicyIDs []int  `json:"policy_ids"`
	Name      string `json:"name"`
}

var (
	allowedBackupAutoSyncPolicyIntervals = map[string]struct{}{
		"3h": {}, "12h": {}, "daily": {}, "weekly": {}, "monthly": {},
	}
	allowedBackupAutoSyncPolicyRetentionTypes = map[string]struct{}{
		"never": {}, "30_days": {}, "1_year": {}, "7_years": {},
	}
)

func validateBackupAutoSyncPolicySchedule(interval, retentionType string) error {
	interval = normalizeBackupAutoSyncPolicyInterval(interval)
	if interval == "" {
		return ErrValidation.New("interval is required")
	}
	if _, ok := allowedBackupAutoSyncPolicyIntervals[interval]; !ok {
		return ErrValidation.New("unsupported interval: %s", interval)
	}
	retentionType = strings.TrimSpace(retentionType)
	if retentionType == "" {
		return ErrValidation.New("retention_type is required")
	}
	if _, ok := allowedBackupAutoSyncPolicyRetentionTypes[retentionType]; !ok {
		return ErrValidation.New("unsupported retention_type: %s", retentionType)
	}
	return nil
}

func (r UpdateBackupAutoSyncPolicyRequest) Validate() error {
	return validateBackupAutoSyncPolicySchedule(r.Interval, r.RetentionType)
}

func (r UpdateBackupAutoSyncPolicyRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"interval":       normalizeBackupAutoSyncPolicyInterval(r.Interval),
		"on":             strings.TrimSpace(r.On),
		"retention_type": strings.TrimSpace(r.RetentionType),
	})
}

func (r CreateBackupAutoSyncPolicyRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return ErrValidation.New("name is required")
	}
	return validateBackupAutoSyncPolicySchedule(r.Interval, r.RetentionType)
}

func (r CreateBackupAutoSyncPolicyRequest) backupToolsPayload() ([]byte, error) {
	out := map[string]interface{}{
		"name":           strings.TrimSpace(r.Name),
		"interval":       normalizeBackupAutoSyncPolicyInterval(r.Interval),
		"on":             strings.TrimSpace(r.On),
		"retention_type": strings.TrimSpace(r.RetentionType),
	}
	if len(r.JobIDs) > 0 {
		out["job_ids"] = r.JobIDs
	}
	return json.Marshal(out)
}

func (r MoveBackupAutoSyncPolicyAssignmentsRequest) Validate() error {
	if r.TargetPolicyID <= 0 {
		return ErrValidation.New("target_policy_id is required")
	}
	if len(r.JobIDs) == 0 {
		return ErrValidation.New("job_ids is required")
	}
	seen := make(map[int]struct{}, len(r.JobIDs))
	for _, id := range r.JobIDs {
		if id <= 0 {
			return ErrValidation.New("job_ids must be positive integers")
		}
		if _, dup := seen[id]; dup {
			return ErrValidation.New("job_ids must not contain duplicates")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (r MoveBackupAutoSyncPolicyAssignmentsRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"target_policy_id": r.TargetPolicyID,
		"job_ids":          r.JobIDs,
	})
}

func (r MergeBackupAutoSyncPoliciesRequest) Validate() error {
	if len(r.PolicyIDs) < 2 {
		return ErrValidation.New("at least two policy_ids are required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return ErrValidation.New("name is required")
	}
	return nil
}

func (r MergeBackupAutoSyncPoliciesRequest) backupToolsPayload() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"policy_ids": r.PolicyIDs,
		"name":       strings.TrimSpace(r.Name),
	})
}

func normalizeBackupAutoSyncPolicyInterval(interval string) string {
	interval = strings.ToLower(strings.TrimSpace(interval))
	switch interval {
	case "24h", "nightly", "7d":
		return "daily"
	default:
		return interval
	}
}

func (s *Service) getBackupAutoSyncPolicy(ctx context.Context, tokenKey, path, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if query != "" {
		path += "?" + query
	}
	return s.backupToolsRequest(ctx, http.MethodGet, path, tokenKey, "", nil)
}

func backupAutoSyncPolicyAvailableAssignmentsQuery(policyID, search, email string) (string, error) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return "", ErrValidation.New("policy_id is required")
	}
	values := url.Values{}
	values.Set("policy_id", policyID)
	if v := strings.TrimSpace(search); v != "" {
		values.Set("search", v)
	}
	if v := strings.TrimSpace(email); v != "" {
		values.Set("email", v)
	}
	return values.Encode(), nil
}

// ListBackupAutoSyncPolicies proxies Backup-Tools GET /auto-sync/policy.
func (s *Service) ListBackupAutoSyncPolicies(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.getBackupAutoSyncPolicy(ctx, tokenKey, "/auto-sync/policy", "")
}

// GetBackupAutoSyncPolicy proxies Backup-Tools GET /auto-sync/policy/{policy_id}.
func (s *Service) GetBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID, query string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, 0, ErrValidation.New("policy_id is required")
	}
	return s.getBackupAutoSyncPolicy(ctx, tokenKey, "/auto-sync/policy/"+url.PathEscape(policyID), query)
}

// CreateBackupAutoSyncPolicy proxies Backup-Tools POST /auto-sync/policy.
func (s *Service) CreateBackupAutoSyncPolicy(ctx context.Context, tokenKey string, req CreateBackupAutoSyncPolicyRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	payload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPost, "/auto-sync/policy", tokenKey, "", payload)
}

// UpdateBackupAutoSyncPolicy proxies Backup-Tools PUT /auto-sync/policy/{policy_id}.
func (s *Service) UpdateBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID string, req UpdateBackupAutoSyncPolicyRequest) (body []byte, status int, err error) {
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

	payload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	path := "/auto-sync/policy/" + url.PathEscape(policyID)
	return s.backupToolsRequest(ctx, http.MethodPut, path, tokenKey, "", payload)
}

// MoveBackupAutoSyncPolicyAssignments proxies Backup-Tools POST /auto-sync/policy/move.
func (s *Service) MoveBackupAutoSyncPolicyAssignments(ctx context.Context, tokenKey string, req MoveBackupAutoSyncPolicyAssignmentsRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	payload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPost, "/auto-sync/policy/move", tokenKey, "", payload)
}

// GetBackupAutoSyncPolicyOptions proxies Backup-Tools GET /auto-sync/policy/options.
func (s *Service) GetBackupAutoSyncPolicyOptions(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.getBackupAutoSyncPolicy(ctx, tokenKey, "/auto-sync/policy/options", "")
}

// GetBackupAutoSyncPolicyAvailableAssignments proxies Backup-Tools GET /auto-sync/policy/available-assignments.
func (s *Service) GetBackupAutoSyncPolicyAvailableAssignments(ctx context.Context, tokenKey, policyID, search, email string) (body []byte, status int, err error) {
	query, err := backupAutoSyncPolicyAvailableAssignmentsQuery(policyID, search, email)
	if err != nil {
		return nil, 0, err
	}
	return s.getBackupAutoSyncPolicy(ctx, tokenKey, "/auto-sync/policy/available-assignments", query)
}

// PreviewMergeBackupAutoSyncPolicies proxies Backup-Tools GET /auto-sync/policy/merge/preview.
func (s *Service) PreviewMergeBackupAutoSyncPolicies(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.getBackupAutoSyncPolicy(ctx, tokenKey, "/auto-sync/policy/merge/preview", "")
}

// MergeBackupAutoSyncPolicies proxies Backup-Tools POST /auto-sync/policy/merge.
func (s *Service) MergeBackupAutoSyncPolicies(ctx context.Context, tokenKey string, req MergeBackupAutoSyncPoliciesRequest) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	if err := req.Validate(); err != nil {
		return nil, 0, err
	}

	payload, err := req.backupToolsPayload()
	if err != nil {
		return nil, 0, Error.Wrap(err)
	}
	return s.backupToolsRequest(ctx, http.MethodPost, "/auto-sync/policy/merge", tokenKey, "", payload)
}

// DeleteBackupAutoSyncPolicy proxies Backup-Tools DELETE /auto-sync/policy/{policy_id}.
func (s *Service) DeleteBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID string) (body []byte, status int, err error) {
	defer mon.Task()(&ctx)(&err)

	if strings.TrimSpace(tokenKey) == "" {
		return nil, 0, ErrUnauthorized.New("session token is required")
	}
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, 0, ErrValidation.New("policy_id is required")
	}
	path := "/auto-sync/policy/" + url.PathEscape(policyID)
	return s.backupToolsRequest(ctx, http.MethodDelete, path, tokenKey, "", nil)
}
