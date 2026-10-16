// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// MicrosoftBackupUsersGroupsJobsActiveSwaggerRequest is the UI body for bulk pause/resume.
type MicrosoftBackupUsersGroupsJobsActiveSwaggerRequest struct {
	JobIDs []int `json:"job_ids" binding:"required" example:"101,102"`
	Active bool  `json:"active" binding:"required" example:"false"`
}
