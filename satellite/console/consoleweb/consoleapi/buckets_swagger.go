// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// ReservedBucketUsageItem is one vault row from GET /api/v0/buckets/usage-totals-for-reserved.
// For Protected Services UI, filter by bucketName: gmail, google-drive, google-photos, google-contacts, google-calendar.
type ReservedBucketUsageItem struct {
	ProjectID    string  `json:"projectID" example:"00000000-0000-0000-0000-000000000001"`
	BucketName   string  `json:"bucketName" example:"gmail"`
	Location     string  `json:"location" example:"us-east-1"`
	Storage      float64 `json:"storage" example:"210.5"`
	Egress       float64 `json:"egress" example:"12.3"`
	ObjectCount  int64   `json:"objectCount" example:"124"`
	SegmentCount int64   `json:"segmentCount" example:"500"`
	CreatedAt    string  `json:"createdAt" example:"2024-03-20T10:00:00Z"`
	Since        string  `json:"since" example:"2024-03-20T10:00:00Z"`
	Before       string  `json:"before" example:"2026-05-28T10:00:00Z"`
}
