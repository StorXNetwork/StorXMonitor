// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/grant"
)

// ErrMemberBucketGrant is the error class for Member ACL grant validation.
var ErrMemberBucketGrant = errs.Class("member bucket grant")

// ValidateBucketNameForMemberACL checks Storj-style bucket name rules (no allowlist).
func ValidateBucketNameForMemberACL(bucket string) error {
	if len(bucket) < 3 || len(bucket) > 63 {
		return ErrMemberBucketGrant.New("bucket name must be between 3 and 63 characters")
	}
	for i, r := range bucket {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if r == '-' || r == '.' {
			if i == 0 || i == len(bucket)-1 {
				return ErrMemberBucketGrant.New("bucket name cannot start or end with '-' or '.'")
			}
			continue
		}
		return ErrMemberBucketGrant.New("bucket name contains invalid character")
	}
	return nil
}

// NormalizeMemberGrantInputs clears unsupported Upload/Delete flags in place.
// Member ACL only supports List + Download.
func NormalizeMemberGrantInputs(grants []MemberBucketGrantInput) {
	for i := range grants {
		grants[i].AllowUpload = false
		grants[i].AllowDelete = false
	}
}

// MaxBulkProjectInvites is the maximum number of emails accepted by InviteNewProjectMembers.
const MaxBulkProjectInvites = 50

// ValidateBulkInviteCount checks bulk invite batch size.
func ValidateBulkInviteCount(n int) error {
	if n == 0 {
		return ErrValidation.New("at least one invite is required")
	}
	if n > MaxBulkProjectInvites {
		return ErrValidation.New("at most %d invites allowed per request", MaxBulkProjectInvites)
	}
	return nil
}

// ValidateGrantSet validates a full-replace grant set: valid bucket names, trailing slash,
// at least one of list/download, no overlaps, no bucket-wide prefixes.
// Upload/Delete on input are ignored (forced false).
// Bucket existence on the project is checked separately (no ACL registry required).
func ValidateGrantSet(grants []MemberBucketGrantInput) error {
	NormalizeMemberGrantInputs(grants)

	type key struct {
		bucket string
		prefix string
	}
	seen := make(map[key]struct{}, len(grants))

	for i, g := range grants {
		if err := ValidateBucketNameForMemberACL(g.Bucket); err != nil {
			return ErrMemberBucketGrant.Wrap(err)
		}
		if g.Prefix == "" || !strings.HasSuffix(g.Prefix, "/") {
			return ErrMemberBucketGrant.New("prefix must be non-empty and end with '/'")
		}
		// Reject bare bucket-wide style like just "/" — require a folder segment.
		trimmed := strings.TrimSuffix(g.Prefix, "/")
		if trimmed == "" {
			return ErrMemberBucketGrant.New("bucket-wide prefixes are not allowed")
		}
		if !g.AllowList && !g.AllowDownload {
			return ErrMemberBucketGrant.New("grant must allow at least one of list or download")
		}

		k := key{bucket: g.Bucket, prefix: g.Prefix}
		if _, ok := seen[k]; ok {
			return ErrMemberBucketGrant.New("duplicate grant for bucket %q prefix %q", g.Bucket, g.Prefix)
		}
		seen[k] = struct{}{}

		for j, other := range grants {
			if i == j || g.Bucket != other.Bucket {
				continue
			}
			if prefixesOverlap(g.Prefix, other.Prefix) {
				return ErrMemberBucketGrant.New("overlapping prefixes %q and %q on bucket %q", g.Prefix, other.Prefix, g.Bucket)
			}
		}
	}
	return nil
}

func prefixesOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// IsPrefixAllowed reports whether requestedBucket/requestedPrefix is equal to or a child of some ACL grant.
func IsPrefixAllowed(requestedBucket, requestedPrefix string, aclGrants []MemberBucketGrant) bool {
	for _, g := range aclGrants {
		if g.Bucket != requestedBucket {
			continue
		}
		if requestedPrefix == g.Prefix || strings.HasPrefix(requestedPrefix, g.Prefix) {
			return true
		}
	}
	return false
}

// FindMatchingGrant returns the ACL grant that covers requestedBucket/requestedPrefix, if any.
// Prefers the longest matching ACL prefix.
func FindMatchingGrant(requestedBucket, requestedPrefix string, aclGrants []MemberBucketGrant) *MemberBucketGrant {
	var best *MemberBucketGrant
	for i := range aclGrants {
		g := &aclGrants[i]
		if g.Bucket != requestedBucket {
			continue
		}
		if requestedPrefix == g.Prefix || strings.HasPrefix(requestedPrefix, g.Prefix) {
			if best == nil || len(g.Prefix) > len(best.Prefix) {
				best = g
			}
		}
	}
	return best
}

// IntersectPermission ANDs requested permissions with an ACL grant.
// Member ACL only supports List + Download; Upload/Delete are always denied.
func IntersectPermission(requested *grant.Permission, acl MemberBucketGrant) grant.Permission {
	out := grant.Permission{}
	if requested == nil {
		out.AllowList = acl.AllowList
		out.AllowDownload = acl.AllowDownload
		return out
	}
	out.AllowList = requested.AllowList && acl.AllowList
	out.AllowDownload = requested.AllowDownload && acl.AllowDownload
	return out
}

// DefaultInviteGrants builds List+Download grants for inviteEmail under each registered bucket.
func DefaultInviteGrants(inviteEmail string, registeredBuckets []string) []MemberBucketGrantInput {
	return GrantsFromVaults(inviteEmail, registeredBuckets)
}

// GrantsFromVaults builds List+Download grants for inviteEmail under each vault (bucket) name.
// Prefix is always `{email}/`. Upload/Delete are never set.
func GrantsFromVaults(inviteEmail string, vaults []string) []MemberBucketGrantInput {
	email := strings.TrimSpace(inviteEmail)
	prefix := fmt.Sprintf("%s/", email)
	out := make([]MemberBucketGrantInput, 0, len(vaults))
	for _, bucket := range vaults {
		bucket = strings.TrimSpace(bucket)
		if bucket == "" {
			continue
		}
		out = append(out, MemberBucketGrantInput{
			Bucket:        bucket,
			Prefix:        prefix,
			AllowList:     true,
			AllowDownload: true,
		})
	}
	return out
}
