// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// UpdateGoogleBackupAutoSyncPolicySwaggerRequest is the UI body for PUT .../auto-sync/policy/{policy_id}.
type UpdateGoogleBackupAutoSyncPolicySwaggerRequest struct {
	// Schedule interval. Allowed: 3h, 12h, daily, weekly, monthly. UI aliases nightly, 24h, 7d normalize to daily.
	Interval string `json:"interval" binding:"required" example:"daily" enums:"3h,12h,daily,weekly,monthly"`
	// Schedule anchor (depends on interval). 3h/12h: empty string. daily: time e.g. 12am. weekly: weekday e.g. Monday. monthly: day e.g. 1.
	On string `json:"on" example:"12am"`
	// Backup retention. Allowed: never, 30_days, 1_year, 7_years. Optional — omit to leave unchanged.
	RetentionType string `json:"retention_type,omitempty" example:"1_year" enums:"never,30_days,1_year,7_years"`
	// true = Edit (all linked jobs). false = Copy (use with selected_job_ids).
	ApplyAll *bool `json:"apply_all,omitempty" example:"true"`
	// Job IDs when apply_all is false (Copy flow).
	SelectedJobIDs []int `json:"selected_job_ids,omitempty" example:"101,102"`
}

// MergeGoogleBackupAutoSyncPoliciesSwaggerRequest is the UI body for POST .../auto-sync/policy/merge.
type MergeGoogleBackupAutoSyncPoliciesSwaggerRequest struct {
	PolicyIDs []int `json:"policy_ids" binding:"required" example:"12,18,22"`
}

// GoogleBackupPolicyListItemSwagger is one policy row in list, detail, and merge responses.
type GoogleBackupPolicyListItemSwagger struct {
	PolicyID             int     `json:"policy_id" example:"12"`
	CredentialID         int     `json:"credential_id" example:"5"`
	// Schedule interval: 3h, 12h, daily, weekly, monthly.
	Interval string `json:"interval" example:"daily" enums:"3h,12h,daily,weekly,monthly"`
	// Schedule anchor: empty (3h/12h), time (daily), weekday (weekly), day-of-month (monthly).
	On string `json:"on" example:"12am"`
	// Retention: never, 30_days, 1_year, 7_years.
	RetentionType string `json:"retention_type" example:"never" enums:"never,30_days,1_year,7_years"`
	ExpiresAt            *string `json:"expires_at,omitempty" example:"2027-01-01T00:00:00Z"`
	IsExpired            bool    `json:"is_expired" example:"false"`
	LinkedJobCount       int     `json:"linked_job_count" example:"3"`
	NeedsGoogleReconnect bool    `json:"needs_google_reconnect" example:"true"`
	NeedsStorxReconnect  bool    `json:"needs_storx_reconnect" example:"false"`
}

// GoogleBackupPolicyConnectedAccountSwagger is the account block on policy detail and filtered listing.
type GoogleBackupPolicyConnectedAccountSwagger struct {
	ProjectID            string `json:"project_id" example:"abc-123"`
	GoogleEmail          string `json:"google_email" example:"admin@company.com"`
	OAuthHolderEmail     string `json:"oauth_holder_email" example:"admin@company.com"`
	CredentialID         int    `json:"credential_id" example:"5"`
	StorjProjectID       string `json:"storj_project_id,omitempty" example:"00000000-0000-0000-0000-000000000000"`
	AccountType          string `json:"account_type" example:"admin_workspace" enums:"personal,employee_workspace,admin_workspace"`
	NeedsGoogleReconnect bool   `json:"needs_google_reconnect" example:"true"`
	NeedsStorxReconnect  bool   `json:"needs_storx_reconnect" example:"false"`
	ReconnectScope       string `json:"reconnect_scope" example:"credential"`
}

// GoogleBackupPolicyLinkedJobSwagger is a job linked to a policy.
type GoogleBackupPolicyLinkedJobSwagger struct {
	JobID    int    `json:"job_id" example:"101"`
	Email    string `json:"email" example:"user1@company.com"`
	Method   string `json:"method" example:"gmail"`
	Active   bool   `json:"active" example:"false"`
	SyncType string `json:"sync_type" example:"daily"`
}

// GoogleBackupPolicyListSwaggerResponse is returned from GET .../auto-sync/policy.
type GoogleBackupPolicyListSwaggerResponse struct {
	Message  string                                 `json:"message" example:"Backup policies"`
	Policies []GoogleBackupPolicyListItemSwagger    `json:"policies"`
	Account  *GoogleBackupPolicyConnectedAccountSwagger `json:"account,omitempty"`
	Failed   []interface{}                          `json:"failed"`
}

// GoogleBackupPolicyDetailSwaggerResponse is returned from GET .../auto-sync/policy/{policy_id}.
type GoogleBackupPolicyDetailSwaggerResponse struct {
	Message    string                                 `json:"message" example:"Backup policy details"`
	Policy     GoogleBackupPolicyListItemSwagger      `json:"policy"`
	Account    GoogleBackupPolicyConnectedAccountSwagger `json:"account"`
	LinkedJobs []GoogleBackupPolicyLinkedJobSwagger   `json:"linked_jobs"`
	Failed     []interface{}                          `json:"failed"`
}

// GoogleBackupPolicyUpdateSwaggerResponse is returned from PUT .../auto-sync/policy/{policy_id}.
type GoogleBackupPolicyUpdateSwaggerResponse struct {
	Message string                            `json:"message" example:"Policy updated"`
	Policy  GoogleBackupPolicyListItemSwagger `json:"policy"`
	Failed  []interface{}                     `json:"failed"`
}

// GoogleBackupPolicyScheduleSwagger is the schedule fingerprint for merge groups.
type GoogleBackupPolicyScheduleSwagger struct {
	// Schedule interval: 3h, 12h, daily, weekly, monthly.
	Interval string `json:"interval" example:"daily" enums:"3h,12h,daily,weekly,monthly"`
	// Schedule anchor: empty (3h/12h), time (daily), weekday (weekly), day-of-month (monthly).
	On string `json:"on" example:"12am"`
	// Retention: never, 30_days, 1_year, 7_years.
	RetentionType string `json:"retention_type" example:"never" enums:"never,30_days,1_year,7_years"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	IsExpired     bool    `json:"is_expired" example:"false"`
}

// GoogleBackupPolicyMergeImpactSwagger describes job and policy counts for merge preview/execute.
type GoogleBackupPolicyMergeImpactSwagger struct {
	PolicyKept          int `json:"policy_kept" example:"1"`
	PoliciesToRemove      int `json:"policies_to_remove,omitempty" example:"2"`
	PoliciesRemoved       int `json:"policies_removed,omitempty" example:"2"`
	JobsToRebind          int `json:"jobs_to_rebind,omitempty" example:"5"`
	JobsRebound           int `json:"jobs_rebound,omitempty" example:"5"`
	TotalJobsAfterMerge   int `json:"total_jobs_after_merge" example:"8"`
}

// GoogleBackupPolicyMergePreviewPolicySwagger is a policy row in a merge preview group.
type GoogleBackupPolicyMergePreviewPolicySwagger struct {
	GoogleBackupPolicyListItemSwagger
	Role string `json:"role" example:"canonical" enums:"canonical,duplicate"`
}

// GoogleBackupPolicyMergeLinkedJobPreviewSwagger is a linked job row in merge preview.
type GoogleBackupPolicyMergeLinkedJobPreviewSwagger struct {
	JobID    int    `json:"job_id" example:"101"`
	Email    string `json:"email" example:"user1@company.com"`
	Method   string `json:"method" example:"gmail"`
	PolicyID int    `json:"policy_id" example:"12"`
}

// GoogleBackupPolicyMergePreviewGroupSwagger is one duplicate schedule group from merge preview.
type GoogleBackupPolicyMergePreviewGroupSwagger struct {
	Schedule                    GoogleBackupPolicyScheduleSwagger              `json:"schedule"`
	Account                     GoogleBackupPolicyConnectedAccountSwagger      `json:"account"`
	Impact                      GoogleBackupPolicyMergeImpactSwagger           `json:"impact"`
	RecommendedCanonicalPolicyID int                                           `json:"recommended_canonical_policy_id" example:"12"`
	CanonicalReason             string                                         `json:"canonical_reason" example:"most_linked_jobs_non_expired" enums:"most_linked_jobs_non_expired,non_expired_policy,lowest_policy_id"`
	Policies                    []GoogleBackupPolicyMergePreviewPolicySwagger  `json:"policies"`
	PolicyIDs                   []int                                          `json:"policy_ids" example:"12,18,22"`
	LinkedJobsPreview           []GoogleBackupPolicyMergeLinkedJobPreviewSwagger `json:"linked_jobs_preview"`
	JobsToRebind                int                                            `json:"jobs_to_rebind" example:"5"`
	HasMoreJobs                 bool                                           `json:"has_more_jobs" example:"false"`
}

// GoogleBackupPolicyMergePreviewSummarySwagger is the summary block on merge preview.
type GoogleBackupPolicyMergePreviewSummarySwagger struct {
	MergeableGroupCount   int `json:"mergeable_group_count" example:"2"`
	DuplicatePolicyCount  int `json:"duplicate_policy_count" example:"5"`
	JobsThatWouldMove     int `json:"jobs_that_would_move" example:"8"`
}

// GoogleBackupPolicyMergePreviewSwaggerResponse is returned from GET .../auto-sync/policy/merge/preview.
type GoogleBackupPolicyMergePreviewSwaggerResponse struct {
	Message string                                     `json:"message" example:"Duplicate policy merge preview"`
	Summary GoogleBackupPolicyMergePreviewSummarySwagger `json:"summary"`
	Groups  []GoogleBackupPolicyMergePreviewGroupSwagger `json:"groups"`
	Failed  []interface{}                              `json:"failed"`
}

// GoogleBackupPolicyMergeExecuteSwaggerResponse is returned from POST .../auto-sync/policy/merge.
type GoogleBackupPolicyMergeExecuteSwaggerResponse struct {
	Message string `json:"message" example:"Policies merged"`
	Merge   struct {
		Schedule           GoogleBackupPolicyScheduleSwagger     `json:"schedule"`
		CanonicalPolicyID  int                                   `json:"canonical_policy_id" example:"12"`
		CanonicalReason    string                                `json:"canonical_reason" example:"most_linked_jobs_non_expired"`
		RemovedPolicyIDs   []int                                 `json:"removed_policy_ids" example:"18,22"`
		PolicyIDs          []int                                 `json:"policy_ids" example:"12,18,22"`
		JobsRebound        int                                   `json:"jobs_rebound" example:"5"`
		Impact             GoogleBackupPolicyMergeImpactSwagger  `json:"impact"`
		Policy             GoogleBackupPolicyListItemSwagger     `json:"policy"`
	} `json:"merge"`
	Failed []interface{} `json:"failed"`
}
