// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

const (
	// OrgRoleAdmin is the organization admin role.
	OrgRoleAdmin = "admin"
	// OrgRoleMember is the organization member role.
	OrgRoleMember = "member"

	ownNodesOperatorEmailPrefix = "ownnodes:"
)

var (
	// ErrOrgNotFound is used when an organization is missing.
	ErrOrgNotFound = errs.Class("organization not found")

	// ErrOrgForbidden is used when the caller lacks org permissions.
	ErrOrgForbidden = errs.Class("organization forbidden")

	// ErrOrgInvalid is used for invalid org input.
	ErrOrgInvalid = errs.Class("organization invalid")

	// ErrOrgNodeAlreadyClaimed is used when a node is already claimed by an org.
	ErrOrgNodeAlreadyClaimed = errs.Class("org node already claimed")

	// ErrOrgNodeNotFound is used when an org node claim is missing.
	ErrOrgNodeNotFound = errs.Class("org node not found")
)

// Organization is a multi-user group that can claim storage nodes.
type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedBy uuid.UUID `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
}

// OrgMember is a user's membership in an organization.
type OrgMember struct {
	OrgID     uuid.UUID `json:"orgId"`
	UserID    uuid.UUID `json:"userId"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}

// OrgNode is an organization ↔ storage node claim.
type OrgNode struct {
	OrgID     uuid.UUID           `json:"orgId"`
	NodeID    storxnetwork.NodeID `json:"nodeId"`
	ClaimedBy uuid.UUID           `json:"claimedBy"`
	CreatedAt time.Time           `json:"createdAt"`
}

// NodeSetupInfo describes how to configure storage nodes for an org.
type NodeSetupInfo struct {
	UserID           uuid.UUID `json:"userId"`
	OrgID            uuid.UUID `json:"orgId"`
	Wallet           string    `json:"wallet,omitempty"`
	SatelliteAddress string    `json:"satelliteAddress"`
	Commands         []string  `json:"commands"`
	NodeCount        int       `json:"nodeCount"`
	MinNodes         int       `json:"minNodes"`
	Ready            bool      `json:"ready"`
	Message          string    `json:"message,omitempty"`
	GuideURL         string    `json:"guideUrl"`
}

// Organizations is the repository for organizations.
//
// architecture: Database
type Organizations interface {
	Create(ctx context.Context, name string, createdBy uuid.UUID) (*Organization, error)
	Get(ctx context.Context, id uuid.UUID) (*Organization, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]Organization, error)
}

// OrgMembers is the repository for organization membership.
//
// architecture: Database
type OrgMembers interface {
	Insert(ctx context.Context, orgID, userID uuid.UUID, role string) (*OrgMember, error)
	Get(ctx context.Context, orgID, userID uuid.UUID) (*OrgMember, error)
	ListByOrgID(ctx context.Context, orgID uuid.UUID) ([]OrgMember, error)
	Delete(ctx context.Context, orgID, userID uuid.UUID) error
	CountAdmins(ctx context.Context, orgID uuid.UUID) (int, error)
	GetMembership(ctx context.Context, orgID, userID uuid.UUID) (*OrgMember, error)
}

// OrgNodes is the repository for organization ↔ storage node claims.
//
// architecture: Database
type OrgNodes interface {
	Insert(ctx context.Context, orgID uuid.UUID, nodeID storxnetwork.NodeID, claimedBy uuid.UUID) (*OrgNode, error)
	Delete(ctx context.Context, orgID uuid.UUID, nodeID storxnetwork.NodeID) error
	ListByOrgID(ctx context.Context, orgID uuid.UUID) ([]OrgNode, error)
	GetNodeIDsByOrgID(ctx context.Context, orgID uuid.UUID) ([]storxnetwork.NodeID, error)
	GetByNodeID(ctx context.Context, nodeID storxnetwork.NodeID) (*OrgNode, error)
	CountByOrgID(ctx context.Context, orgID uuid.UUID) (int, error)
	AllNodeIDs(ctx context.Context) ([]storxnetwork.NodeID, error)
	CountOnlineByOrgID(ctx context.Context, orgID uuid.UUID, onlineWindow time.Duration) (int, error)
	// NodeExists reports whether the node is present in the overlay nodes table.
	NodeExists(ctx context.Context, nodeID storxnetwork.NodeID) (exists bool, operatorEmail string, err error)
}

// SplitOwnNodesCheckInEmail splits check-in operator email into bind token and
// optional contact email. Forms:
//
//	ownnodes:<userUUID>[:<orgUUID>][|<contactEmail>]
//
// When the value is a normal email (no ownnodes: prefix), bindToken is empty and
// contactEmail is the original value.
func SplitOwnNodesCheckInEmail(email string) (bindToken, contactEmail string) {
	email = strings.TrimSpace(email)
	if !strings.HasPrefix(email, ownNodesOperatorEmailPrefix) {
		return "", email
	}
	if i := strings.IndexByte(email, '|'); i >= 0 {
		return email[:i], strings.TrimSpace(email[i+1:])
	}
	return email, ""
}

// ParseOwnNodesOperatorEmail parses operator email of the form:
//
//	ownnodes:<userUUID>           (preferred — node group resolved on check-in)
//	ownnodes:<userUUID>:<orgUUID> (legacy)
//
// Optional "|<contactEmail>" suffix is ignored for mapping.
func ParseOwnNodesOperatorEmail(email string) (userID, orgID uuid.UUID, ok bool) {
	bindToken, _ := SplitOwnNodesCheckInEmail(email)
	if bindToken == "" {
		return uuid.UUID{}, uuid.UUID{}, false
	}
	rest := strings.TrimPrefix(bindToken, ownNodesOperatorEmailPrefix)
	parts := strings.Split(rest, ":")
	if len(parts) < 1 || len(parts) > 2 {
		return uuid.UUID{}, uuid.UUID{}, false
	}
	userID, err := uuid.FromString(parts[0])
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false
	}
	if len(parts) == 1 || strings.TrimSpace(parts[1]) == "" {
		return userID, uuid.UUID{}, true
	}
	orgID, err = uuid.FromString(parts[1])
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false
	}
	return userID, orgID, true
}

// FormatOwnNodesOperatorEmail builds operator email with user id only.
// Node group is resolved from the user's memberships on check-in.
func FormatOwnNodesOperatorEmail(userID uuid.UUID) string {
	return ownNodesOperatorEmailPrefix + userID.String()
}

// FormatOwnNodesOperatorEmailWithOrg is the legacy user+org encoding.
func FormatOwnNodesOperatorEmailWithOrg(userID, orgID uuid.UUID) string {
	return ownNodesOperatorEmailPrefix + userID.String() + ":" + orgID.String()
}
