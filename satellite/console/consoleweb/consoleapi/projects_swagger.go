// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// ProjectInfoSwaggerItem is a project returned by GET/POST /api/v0/projects and PATCH /api/v0/projects/{id}.
type ProjectInfoSwaggerItem struct {
	ID                      string    `json:"id" example:"00000000-0000-0000-0000-000000000000"`
	Name                    string    `json:"name" example:"My Project"`
	OwnerID                 string    `json:"ownerId" example:"00000000-0000-0000-0000-000000000000"`
	Description             string    `json:"description" example:"Backup vault"`
	MemberCount             int       `json:"memberCount" example:"1"`
	CreatedAt               time.Time `json:"createdAt"`
	StorageUsed             int64     `json:"storageUsed" example:"0"`
	BandwidthUsed           int64     `json:"bandwidthUsed" example:"0"`
	Versioning              int       `json:"versioning" example:"1"`
	PrevDaysUntilExpiration int       `json:"prevDaysUntilExpiration" example:"0"`
	Placement               string    `json:"placement" example:""`
	HasManagedPassphrase    bool      `json:"hasManagedPassphrase" example:"false"`
	IsClassic               bool      `json:"isClassic" example:"false"`
}

// UpsertProjectSwaggerRequest is the body for POST /api/v0/projects and PATCH /api/v0/projects/{id}.
type UpsertProjectSwaggerRequest struct {
	Name                    string `json:"name" example:"My Project"`
	Description             string `json:"description" example:"Optional description"`
	StorageLimit            int64  `json:"storageLimit" example:"0"`
	BandwidthLimit          int64  `json:"bandwidthLimit" example:"0"`
	ManagePassphrase        bool   `json:"managePassphrase" example:"false"`
	PrevDaysUntilExpiration int    `json:"prevDaysUntilExpiration" example:"0"`
}

// DeleteProjectSwaggerRequest is the multi-step body for DELETE /api/v0/projects/{id}.
type DeleteProjectSwaggerRequest struct {
	Step int    `json:"step" example:"0"`
	Data string `json:"data" example:""`
}

// DeleteProjectSwaggerResponse is returned on DELETE conflict (project not ready to delete).
type DeleteProjectSwaggerResponse struct {
	LockEnabledBuckets  int  `json:"lockEnabledBuckets" example:"0"`
	Buckets             int  `json:"buckets" example:"0"`
	APIKeys             int  `json:"apiKeys" example:"0"`
	CurrentUsage        bool `json:"currentUsage" example:"false"`
	InvoicingIncomplete bool `json:"invoicingIncomplete" example:"false"`
}

// ProjectUsageLimitsSwaggerResponse is returned by GET /api/v0/projects/{id}/usage-limits.
type ProjectUsageLimitsSwaggerResponse struct {
	StorageLimit          int64  `json:"storageLimit" example:"107374182400"`
	UserSetStorageLimit   *int64 `json:"userSetStorageLimit"`
	BandwidthLimit        int64  `json:"bandwidthLimit" example:"107374182400"`
	UserSetBandwidthLimit *int64 `json:"userSetBandwidthLimit"`
	StorageUsed           int64  `json:"storageUsed" example:"0"`
	BandwidthUsed         int64  `json:"bandwidthUsed" example:"0"`
	ObjectCount           int64  `json:"objectCount" example:"0"`
	SegmentCount          int64  `json:"segmentCount" example:"0"`
	RateLimit             int64  `json:"rateLimit" example:"0"`
	SegmentLimit          int64  `json:"segmentLimit" example:"0"`
	RateUsed              int64  `json:"rateUsed" example:"0"`
	SegmentUsed           int64  `json:"segmentUsed" example:"0"`
	BucketsUsed           int64  `json:"bucketsUsed" example:"2"`
	BucketsLimit          int64  `json:"bucketsLimit" example:"100"`
}
