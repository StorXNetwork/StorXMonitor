// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// UserProjectInvitationSwaggerItem is one pending invitation for the logged-in user.
type UserProjectInvitationSwaggerItem struct {
	ProjectID          string     `json:"projectID" example:"00000000-0000-0000-0000-000000000000"`
	ProjectName        string     `json:"projectName" example:"My Project"`
	ProjectDescription string     `json:"projectDescription" example:"Shared backup project"`
	InviterEmail       string     `json:"inviterEmail" example:"owner@example.com"`
	CreatedAt          time.Time  `json:"createdAt"`
	LinkExpiresAt      time.Time  `json:"linkExpiresAt"`
	VaultExpiresAt     *time.Time `json:"vaultExpiresAt,omitempty"`
	Vaults             []string   `json:"vaults,omitempty"`
}

// RespondToProjectInvitationSwaggerRequest is the body for POST .../invitations/{id}/respond.
// `response`: 0 = decline, 1 = accept (see console.ProjectInvitationResponse).
type RespondToProjectInvitationSwaggerRequest struct {
	Response int `json:"response" example:"1"`
}

// ProjectMemberSwaggerItem is one member in GET .../members and PATCH .../members/{memberID}.
// Role: 0 = Admin, 1 = Member.
type ProjectMemberSwaggerItem struct {
	ID        string    `json:"id" example:"00000000-0000-0000-0000-000000000001"`
	FullName  string    `json:"fullName" example:"Jane Doe"`
	ShortName string    `json:"shortName" example:"Jane"`
	Email     string    `json:"email" example:"jane@example.com"`
	Role      int       `json:"role" example:"1"`
	JoinedAt  time.Time `json:"joinedAt"`
}

// ProjectInvitationSwaggerItem is one pending invitee in GET .../members.
type ProjectInvitationSwaggerItem struct {
	Email     string    `json:"email" example:"invitee@example.com"`
	CreatedAt time.Time `json:"createdAt"`
	Expired   bool      `json:"expired" example:"false"`
}

// ProjectMembersPageSwaggerResponse is returned by GET /api/v0/projects/{id}/members.
type ProjectMembersPageSwaggerResponse struct {
	ProjectMembers     []ProjectMemberSwaggerItem     `json:"projectMembers"`
	ProjectInvitations []ProjectInvitationSwaggerItem `json:"projectInvitations"`
	TotalCount         int                            `json:"totalCount" example:"3"`
	Offset             int                            `json:"offset" example:"0"`
	Limit              int                            `json:"limit" example:"100"`
	Order              int                            `json:"order" example:"1"`
	OrderDirection     int                            `json:"orderDirection" example:"1"`
	Search             string                         `json:"search" example:""`
	CurrentPage        int                            `json:"currentPage" example:"1"`
	PageCount          int                            `json:"pageCount" example:"1"`
}

// ProjectMemberDetailSwaggerResponse is returned by GET /api/v0/projects/{id}/members/{memberID}.
// Role: 0 = Admin, 1 = Member.
type ProjectMemberDetailSwaggerResponse struct {
	ID        string    `json:"id" example:"00000000-0000-0000-0000-000000000001"`
	ProjectID string    `json:"projectID" example:"00000000-0000-0000-0000-000000000000"`
	Role      int       `json:"role" example:"1"`
	JoinedAt  time.Time `json:"joinedAt"`
}

// ReinviteProjectMembersSwaggerRequest is the body for POST .../reinvite.
type ReinviteProjectMembersSwaggerRequest struct {
	Emails []string `json:"emails" example:"invitee@example.com,other@example.com"`
}

// BulkInviteProjectMemberSwaggerItem is one entry in POST .../invites (same as single invite + vaults).
type BulkInviteProjectMemberSwaggerItem struct {
	Email  string   `json:"email" example:"alice@example.com"`
	Vaults []string `json:"vaults" example:"gmail,google-drive"`
}

// BulkInviteProjectMembersSwaggerRequest is the body for POST .../invites (multi-invite).
// Per invite: email + vault bucket names. Server builds List+Download on {email}/ — no grants/scopes in body.
type BulkInviteProjectMembersSwaggerRequest struct {
	Invites []BulkInviteProjectMemberSwaggerItem `json:"invites"`
}

// BulkInviteProjectMemberSwaggerResult is one per-email outcome from POST .../invites.
type BulkInviteProjectMemberSwaggerResult struct {
	Email string `json:"email" example:"alice@example.com"`
	OK    bool   `json:"ok" example:"true"`
	Error string `json:"error,omitempty" example:""`
}

// BulkInviteProjectMembersSwaggerResponse is returned by POST .../invites.
type BulkInviteProjectMembersSwaggerResponse struct {
	Results []BulkInviteProjectMemberSwaggerResult `json:"results"`
}

// DeleteMembersAndInvitationsSwaggerRequest is the body for DELETE .../members.
type DeleteMembersAndInvitationsSwaggerRequest struct {
	Emails         []string `json:"emails" example:"member@example.com,pending@example.com"`
	RemoveAccesses bool     `json:"removeAccesses" example:"true"`
}
