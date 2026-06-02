// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// ProjectUsageByDayItem is one day's usage value (bytes).
type ProjectUsageByDayItem struct {
	Date  string `json:"date" example:"2026-05-26T00:00:00Z"`
	Value int64  `json:"value" example:"9007199254740992"`
}

// ProjectDailyUsageResponse is returned by GET /api/v0/projects/{id}/daily-usage.
type ProjectDailyUsageResponse struct {
	StorageUsage            []ProjectUsageByDayItem `json:"storageUsage"`
	AllocatedBandwidthUsage []ProjectUsageByDayItem `json:"allocatedBandwidthUsage"`
	SettledBandwidthUsage   []ProjectUsageByDayItem `json:"settledBandwidthUsage"`
}
