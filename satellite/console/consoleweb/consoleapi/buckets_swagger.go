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

// BucketUsageTotalsItemSwagger is one bucket row in GET /api/v0/buckets/usage-totals.
type BucketUsageTotalsItemSwagger struct {
	ProjectID    string  `json:"projectID" example:"37159d9b-6f3c-4c38-bfe2-0efbbc4b568d"`
	BucketName   string  `json:"bucketName" example:"my-bucket"`
	Location     string  `json:"location" example:"us-east-1"`
	Storage      float64 `json:"storage" example:"1.5"`
	Egress       float64 `json:"egress" example:"0.2"`
	ObjectCount  int64   `json:"objectCount" example:"42"`
	SegmentCount int64   `json:"segmentCount" example:"100"`
	CreatorEmail string  `json:"creatorEmail" example:"user@example.com"`
	Since        string  `json:"since" example:"2026-06-01T00:00:00.000Z"`
	Before       string  `json:"before" example:"2026-06-03T09:01:55.204Z"`
	CreatedAt    string  `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

// BucketUsageTotalsPageSwagger is the paginated response for GET /api/v0/buckets/usage-totals.
type BucketUsageTotalsPageSwagger struct {
	BucketUsages []BucketUsageTotalsItemSwagger `json:"bucketUsages"`
	Search       string                         `json:"search" example:""`
	Limit        uint                           `json:"limit" example:"10"`
	Offset       uint64                         `json:"offset" example:"0"`
	PageCount    uint                           `json:"pageCount" example:"1"`
	CurrentPage  uint                           `json:"currentPage" example:"1"`
	TotalCount   uint64                         `json:"totalCount" example:"3"`
}

// CheckUploadSwaggerRequest is the body for POST /api/v0/buckets/check-upload.
type CheckUploadSwaggerRequest struct {
	ProjectID string `json:"project_id" binding:"required" example:"37159d9b-6f3c-4c38-bfe2-0efbbc4b568d"`
	FileSize  *int64 `json:"file_size,omitempty" example:"1048576"`
	Operation string `json:"operation" binding:"required" example:"login" enums:"login,upload,download"`
}

// CheckUploadSwaggerResponse is returned by POST /api/v0/buckets/check-upload (storage/bandwidth quota popup).
type CheckUploadSwaggerResponse struct {
	PopupShow                 bool    `json:"popup_show" example:"true"`
	AllowUpload               bool    `json:"allow_upload" example:"false"`
	AllowDownload             bool    `json:"allow_download" example:"true"`
	TotalSpace                int64   `json:"total_space" example:"2147483648"`
	RemainingSpace            int64   `json:"remaining_space" example:"0"`
	StorageUsagePercent       float64 `json:"storage_usage_percent" example:"100"`
	TotalBandwidth            int64   `json:"total_bandwidth" example:"2147483648"`
	RemainingBandwidth        int64   `json:"remaining_bandwidth" example:"2055208960"`
	BandwidthUsagePercent     float64 `json:"bandwidth_usage_percent" example:"4.2"`
	StorageWarningThreshold   float64 `json:"storage_warning_threshold" example:"80"`
	BandwidthWarningThreshold float64 `json:"bandwidth_warning_threshold" example:"80"`
	Message                   string  `json:"message" example:"You have used 100% of your storage quota."`
	UpgradeURL                string  `json:"upgrade_url" example:"https://billing.example.com"`
}
