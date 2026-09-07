// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"time"

	"github.com/StorXNetwork/common/uuid"
)

// ProjectMemberACLBucket is one Admin-registered bucket allowed for Member ACL grants.
type ProjectMemberACLBucket struct {
	ProjectID  uuid.UUID `json:"projectId"`
	BucketName string    `json:"bucketName"`
	CreatedAt  time.Time `json:"createdAt"`
}

// ProjectMemberACLBuckets is the registry of buckets that can receive Member ACL grants.
type ProjectMemberACLBuckets interface {
	List(ctx context.Context, projectID uuid.UUID) ([]ProjectMemberACLBucket, error)
	Get(ctx context.Context, projectID uuid.UUID, bucketName string) (*ProjectMemberACLBucket, error)
	Add(ctx context.Context, projectID uuid.UUID, bucketName string) (*ProjectMemberACLBucket, error)
	Remove(ctx context.Context, projectID uuid.UUID, bucketName string) error
}

// MemberBucketGrant is a pending or active Member prefix ACL row.
// Only List + Download are enforced; Upload/Delete are always false.
type MemberBucketGrant struct {
	ID            uuid.UUID  `json:"id"`
	ProjectID     uuid.UUID  `json:"projectId"`
	MemberID      *uuid.UUID `json:"memberId,omitempty"`
	InviteEmail   string     `json:"inviteEmail"`
	Bucket        string     `json:"bucket"`
	Prefix        string     `json:"prefix"`
	AllowList     bool       `json:"allowList"`
	AllowDownload bool       `json:"allowDownload"`
	AllowUpload   bool       `json:"allowUpload"` // always false
	AllowDelete   bool       `json:"allowDelete"` // always false
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	// ExpiresAt is when vault folder access from this grant ends (nil = no expiry).
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// MemberBucketGrantInput is the Admin-supplied grant shape for PUT/invite.
// Only List and Download are supported; AllowUpload/AllowDelete are ignored and always stored false.
type MemberBucketGrantInput struct {
	Bucket        string `json:"bucket"`
	Prefix        string `json:"prefix"`
	AllowList     bool   `json:"allowList"`
	AllowDownload bool   `json:"allowDownload"`
	AllowUpload   bool   `json:"allowUpload"` // deprecated: ignored, always false
	AllowDelete   bool   `json:"allowDelete"` // deprecated: ignored, always false
}

// MemberBucketGrants persists Member prefix ACL rows.
type MemberBucketGrants interface {
	CreatePending(ctx context.Context, projectID uuid.UUID, inviteEmail string, grants []MemberBucketGrantInput, expiresAt *time.Time) ([]MemberBucketGrant, error)
	GetByMember(ctx context.Context, projectID, memberID uuid.UUID) ([]MemberBucketGrant, error)
	GetByInviteEmail(ctx context.Context, projectID uuid.UUID, inviteEmail string) ([]MemberBucketGrant, error)
	ReplaceForMember(ctx context.Context, projectID, memberID uuid.UUID, inviteEmail string, grants []MemberBucketGrantInput, expiresAt *time.Time) ([]MemberBucketGrant, error)
	// ReplacePendingForInviteEmail deletes existing pending grants for the invite email, then creates the new set.
	ReplacePendingForInviteEmail(ctx context.Context, projectID uuid.UUID, inviteEmail string, grants []MemberBucketGrantInput, expiresAt *time.Time) ([]MemberBucketGrant, error)
	BindPendingToMember(ctx context.Context, projectID uuid.UUID, inviteEmail string, memberID uuid.UUID) error
	DeleteByMember(ctx context.Context, projectID, memberID uuid.UUID) error
	DeleteByInviteEmail(ctx context.Context, projectID uuid.UUID, inviteEmail string) error
}
