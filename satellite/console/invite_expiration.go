// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"strings"
	"time"
)

// Invite link / vault expiration option codes (Grant Access modal).
const (
	InviteExpiration24Hours = "24h" // default link expiration
	InviteExpiration3Days   = "3d"
	InviteExpiration7Days   = "7d"
	InviteExpiration30Days  = "30d"
)

// DefaultInviteLinkExpiration is the UI/API default ("24 Hours (Default)").
const DefaultInviteLinkExpiration = InviteExpiration24Hours

// ParseInviteExpirationOption maps UI/API codes to a duration.
// Accepts 24h|3d|7d|30d and common display labels.
func ParseInviteExpirationOption(raw string) (time.Duration, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "(default)", "")
	switch s {
	case "", InviteExpiration24Hours, "24hours", "24hour", "1d", "1day":
		return 24 * time.Hour, nil
	case InviteExpiration7Days, "7days", "7day":
		return 7 * 24 * time.Hour, nil
	case InviteExpiration3Days, "3days", "3day":
		return 3 * 24 * time.Hour, nil
	case InviteExpiration30Days, "30days", "30day":
		return 30 * 24 * time.Hour, nil
	default:
		return 0, ErrValidation.New("invalid expiration option %q (use 24h, 3d, 7d, or 30d)", raw)
	}
}

// ParseOptionalVaultExpiration returns nil when vault access should not expire.
func ParseOptionalVaultExpiration(raw string) (*time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	d, err := ParseInviteExpirationOption(raw)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// InviteLinkExpiresAt computes link expiry from createdAt and option (empty = 24h default).
func InviteLinkExpiresAt(createdAt time.Time, option string) (time.Time, error) {
	d, err := ParseInviteExpirationOption(option)
	if err != nil {
		return time.Time{}, err
	}
	return createdAt.Add(d), nil
}

// VaultExpiresAtPtr returns createdAt+duration, or nil when duration is nil.
func VaultExpiresAtPtr(createdAt time.Time, d *time.Duration) *time.Time {
	if d == nil {
		return nil
	}
	t := createdAt.Add(*d)
	return &t
}
