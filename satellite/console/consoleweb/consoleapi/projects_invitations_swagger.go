// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// UserProjectInvitationSwaggerItem is one pending invitation for the logged-in user.
type UserProjectInvitationSwaggerItem struct {
	ProjectID          string    `json:"projectID" example:"00000000-0000-0000-0000-000000000000"`
	ProjectName        string    `json:"projectName" example:"My Project"`
	ProjectDescription string    `json:"projectDescription" example:"Shared backup project"`
	InviterEmail       string    `json:"inviterEmail" example:"owner@example.com"`
	CreatedAt          time.Time `json:"createdAt"`
}

// RespondToProjectInvitationSwaggerRequest is the body for POST .../invitations/{id}/respond.
// `response`: 0 = decline, 1 = accept (see console.ProjectInvitationResponse).
type RespondToProjectInvitationSwaggerRequest struct {
	Response int `json:"response" example:"1"`
}
