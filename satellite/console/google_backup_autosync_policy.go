// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import "context"

// Legacy Google-named policy types alias the shared backup policy request types.
type (
	UpdateGoogleBackupAutoSyncPolicyRequest            = UpdateBackupAutoSyncPolicyRequest
	CreateGoogleBackupAutoSyncPolicyRequest            = CreateBackupAutoSyncPolicyRequest
	MoveGoogleBackupAutoSyncPolicyAssignmentsRequest   = MoveBackupAutoSyncPolicyAssignmentsRequest
	MergeGoogleBackupAutoSyncPoliciesRequest           = MergeBackupAutoSyncPoliciesRequest
)

func (s *Service) ListGoogleBackupAutoSyncPolicies(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.ListBackupAutoSyncPolicies(ctx, tokenKey)
}

func (s *Service) GetGoogleBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID, query string) (body []byte, status int, err error) {
	return s.GetBackupAutoSyncPolicy(ctx, tokenKey, policyID, query)
}

func (s *Service) CreateGoogleBackupAutoSyncPolicy(ctx context.Context, tokenKey string, req CreateGoogleBackupAutoSyncPolicyRequest) (body []byte, status int, err error) {
	return s.CreateBackupAutoSyncPolicy(ctx, tokenKey, req)
}

func (s *Service) UpdateGoogleBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID string, req UpdateGoogleBackupAutoSyncPolicyRequest) (body []byte, status int, err error) {
	return s.UpdateBackupAutoSyncPolicy(ctx, tokenKey, policyID, req)
}

func (s *Service) MoveGoogleBackupAutoSyncPolicyAssignments(ctx context.Context, tokenKey string, req MoveGoogleBackupAutoSyncPolicyAssignmentsRequest) (body []byte, status int, err error) {
	return s.MoveBackupAutoSyncPolicyAssignments(ctx, tokenKey, req)
}

func (s *Service) GetGoogleBackupAutoSyncPolicyOptions(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.GetBackupAutoSyncPolicyOptions(ctx, tokenKey)
}

func (s *Service) GetGoogleBackupAutoSyncPolicyAvailableAssignments(ctx context.Context, tokenKey, policyID, search, email string) (body []byte, status int, err error) {
	return s.GetBackupAutoSyncPolicyAvailableAssignments(ctx, tokenKey, policyID, search, email)
}

func (s *Service) PreviewMergeGoogleBackupAutoSyncPolicies(ctx context.Context, tokenKey string) (body []byte, status int, err error) {
	return s.PreviewMergeBackupAutoSyncPolicies(ctx, tokenKey)
}

func (s *Service) MergeGoogleBackupAutoSyncPolicies(ctx context.Context, tokenKey string, req MergeGoogleBackupAutoSyncPoliciesRequest) (body []byte, status int, err error) {
	return s.MergeBackupAutoSyncPolicies(ctx, tokenKey, req)
}

func (s *Service) DeleteGoogleBackupAutoSyncPolicy(ctx context.Context, tokenKey, policyID string) (body []byte, status int, err error) {
	return s.DeleteBackupAutoSyncPolicy(ctx, tokenKey, policyID)
}
