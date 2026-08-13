// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// ProjectMemberACLBucketSwaggerItem is one registry row from GET/POST .../member-acl-buckets.
type ProjectMemberACLBucketSwaggerItem struct {
	ProjectID  string    `json:"projectId" example:"00000000-0000-0000-0000-000000000000"`
	BucketName string    `json:"bucketName" example:"gmail"`
	CreatedAt  time.Time `json:"createdAt"`
}

// AddProjectMemberACLBucketSwaggerRequest is the body for POST .../member-acl-buckets.
type AddProjectMemberACLBucketSwaggerRequest struct {
	BucketName string `json:"bucketName" example:"gmail"`
}

// MemberBucketGrantSwaggerItem is one grant from GET/PUT .../members/{memberID}/bucket-grants.
type MemberBucketGrantSwaggerItem struct {
	ID            string     `json:"id" example:"00000000-0000-0000-0000-000000000000"`
	ProjectID     string     `json:"projectId" example:"00000000-0000-0000-0000-000000000000"`
	MemberID      *string    `json:"memberId,omitempty" example:"00000000-0000-0000-0000-000000000001"`
	InviteEmail   string     `json:"inviteEmail" example:"member@example.com"`
	Bucket        string     `json:"bucket" example:"gmail"`
	Prefix        string     `json:"prefix" example:"member@example.com/"`
	AllowList     bool       `json:"allowList" example:"true"`
	AllowDownload bool       `json:"allowDownload" example:"true"`
	AllowUpload   bool       `json:"allowUpload" example:"false"` // always false; unsupported
	AllowDelete   bool       `json:"allowDelete" example:"false"` // always false; unsupported
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// MemberBucketGrantInputSwagger is Admin-supplied grant shape for PUT/invite.
// Only allowList and allowDownload are honored; allowUpload/allowDelete are ignored.
type MemberBucketGrantInputSwagger struct {
	Bucket        string `json:"bucket" example:"gmail"`
	Prefix        string `json:"prefix" example:"member@example.com/"`
	AllowList     bool   `json:"allowList" example:"true"`
	AllowDownload bool   `json:"allowDownload" example:"true"`
	AllowUpload   bool   `json:"allowUpload" example:"false"` // ignored
	AllowDelete   bool   `json:"allowDelete" example:"false"` // ignored
}

// PutMemberBucketGrantsSwaggerRequest is the body for PUT .../members/{memberID}/bucket-grants.
// Empty grants [] clears all Member scoped access for that member.
type PutMemberBucketGrantsSwaggerRequest struct {
	Grants []MemberBucketGrantInputSwagger `json:"grants"`
}

// InviteProjectMemberWithGrantsSwaggerRequest is optional body for POST .../invite/{email}.
// Omit body or omit grants → defaults from current ACL registry ({inviteEmail}/ List+Download).
// Explicit grants:[] → no pending folder grants.
type InviteProjectMemberWithGrantsSwaggerRequest struct {
	Grants []MemberBucketGrantInputSwagger `json:"grants"`
}
