// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

// CreateOrganization creates an organization and adds the caller as admin.
func (s *Service) CreateOrganization(ctx context.Context, name string) (org *Organization, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrOrgInvalid.New("organization name is required")
	}

	org, err = s.store.Organizations().Create(ctx, name, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, err = s.store.OrgMembers().Insert(ctx, org.ID, user.ID, OrgRoleAdmin)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// If user already chose own_nodes, link active projects to this new group.
	if dest, destErr := s.store.StorageDestinations().GetByUserID(ctx, user.ID); destErr == nil &&
		dest != nil && dest.Mode == StorageDestinationOwnNodes {
		if applyErr := s.applyStorageDestinationPlacement(ctx, user.ID, StorageDestinationOwnNodes); applyErr != nil {
			s.log.Warn("failed to link projects to new node group",
				zap.String("org_id", org.ID.String()),
				zap.Error(applyErr),
			)
		}
	}
	return org, nil
}

// ListOrganizations returns organizations the current user belongs to.
func (s *Service) ListOrganizations(ctx context.Context) (orgs []Organization, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	orgs, err = s.store.Organizations().ListByUserID(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if orgs == nil {
		orgs = []Organization{}
	}
	return orgs, nil
}

// GetOrganization returns an organization if the current user is a member.
func (s *Service) GetOrganization(ctx context.Context, orgID uuid.UUID) (org *Organization, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	if _, err = s.requireOrgMember(ctx, orgID, user.ID); err != nil {
		return nil, err
	}
	org, err = s.store.Organizations().Get(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return org, nil
}

// AddOrgMember adds a user to an organization. Admin only.
// userIDOrEmail may be a UUID string or an email address.
func (s *Service) AddOrgMember(ctx context.Context, orgID uuid.UUID, userIDOrEmail, role string) (member *OrgMember, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if _, err = s.requireOrgAdmin(ctx, orgID, user.ID); err != nil {
		return nil, err
	}

	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		role = OrgRoleMember
	}
	if role != OrgRoleAdmin && role != OrgRoleMember {
		return nil, ErrOrgInvalid.New("role must be %q or %q", OrgRoleAdmin, OrgRoleMember)
	}

	targetID, err := s.resolveUserIDOrEmail(ctx, userIDOrEmail)
	if err != nil {
		return nil, err
	}

	member, err = s.store.OrgMembers().Insert(ctx, orgID, targetID, role)
	if err != nil {
		return nil, err
	}
	return member, nil
}

// RemoveOrgMember removes a member from an organization. Admin only.
func (s *Service) RemoveOrgMember(ctx context.Context, orgID, memberUserID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return ErrUnauthorized.Wrap(err)
	}
	if _, err = s.requireOrgAdmin(ctx, orgID, user.ID); err != nil {
		return err
	}

	member, err := s.store.OrgMembers().GetMembership(ctx, orgID, memberUserID)
	if err != nil {
		return err
	}
	if member.Role == OrgRoleAdmin {
		admins, err := s.store.OrgMembers().CountAdmins(ctx, orgID)
		if err != nil {
			return Error.Wrap(err)
		}
		if admins <= 1 {
			return ErrOrgInvalid.New("cannot remove the last admin")
		}
	}

	return s.store.OrgMembers().Delete(ctx, orgID, memberUserID)
}

// ListOrgNodes returns nodes claimed by an organization.
func (s *Service) ListOrgNodes(ctx context.Context, orgID uuid.UUID) (nodes []OrgNode, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if _, err = s.requireOrgMember(ctx, orgID, user.ID); err != nil {
		return nil, err
	}

	nodes, err = s.store.OrgNodes().ListByOrgID(ctx, orgID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if nodes == nil {
		nodes = []OrgNode{}
	}
	return nodes, nil
}

// GetNodeSetup returns setup commands and counts for org own-nodes.
func (s *Service) GetNodeSetup(ctx context.Context, orgID uuid.UUID) (info *NodeSetupInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	if _, err = s.requireOrgMember(ctx, orgID, user.ID); err != nil {
		return nil, err
	}

	count, err := s.store.OrgNodes().CountByOrgID(ctx, orgID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	satelliteAddr := s.SatelliteNodeAddress
	if satelliteAddr == "" {
		satelliteAddr = s.ExternalAddressForContext(ctx)
	}

	minNodes := MinOwnNodesRequired
	bindEmail := FormatOwnNodesOperatorEmail(user.ID)
	wallet := strings.TrimSpace(user.WalletId)
	contactEmail := strings.TrimSpace(user.Email)

	commands := buildOwnNodesShellCommands(bindEmail, contactEmail, wallet, satelliteAddr)

	info = &NodeSetupInfo{
		UserID:           user.ID,
		OrgID:            orgID,
		Wallet:           wallet,
		SatelliteAddress: satelliteAddr,
		Commands:         commands,
		NodeCount:        count,
		MinNodes:         minNodes,
		Ready:            count >= minNodes,
		GuideURL:         "/guides?type=cyberls-storage-node-shell",
	}
	if !info.Ready {
		info.Message = fmt.Sprintf(ownNodesInsufficientMessage, minNodes, count)
	}
	return info, nil
}

func buildOwnNodesShellCommands(bindEmail, contactEmail, wallet, satelliteAddr string) []string {
	_ = satelliteAddr
	_ = wallet
	// bindEmail is ownnodes:<userUUID>; extract user id for USER_ID=.
	userID := strings.TrimPrefix(bindEmail, "ownnodes:")
	if i := strings.IndexByte(userID, ':'); i >= 0 {
		userID = userID[:i]
	}
	// Escape single quotes for embedding in sed inside single-quoted bash -c.
	safeEmail := strings.ReplaceAll(contactEmail, "'", "'\\''")
	emailLine := ""
	if safeEmail != "" {
		emailLine = " && (grep -q \"^EMAIL=\" .env || echo \"EMAIL=\" >> .env)" +
			" && sed -i \"s/^EMAIL=.*/EMAIL=" + safeEmail + "/\" .env"
	}
	cloneBind := "sudo su -c 'bash <(wget -qO- https://raw.githubusercontent.com/StorXNetwork/Storage-Node/main/clone_repo.sh)" +
		" && cd Storage-Node && cp -n .env.sample .env" +
		" && (grep -q \"^USER_ID=\" .env || echo \"USER_ID=\" >> .env)" +
		" && sed -i \"s/^USER_ID=.*/USER_ID=" + userID + "/\" .env" +
		emailLine +
		"' root"
	return []string{
		"# 1) Clone & bind (USER_ID for mapping; EMAIL stays your contact address)",
		cloneBind,
		"",
		"# 2) Identity",
		"sudo bash bootstrap.sh",
		"",
		"# 3) Start node",
		"sudo bash start-node.sh",
		"",
		"# 4) Check logs",
		"sudo bash check-logs.sh",
	}
}

// GetOrgNodeCount returns the number of nodes claimed by an organization.
func (s *Service) GetOrgNodeCount(ctx context.Context, orgID uuid.UUID) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return 0, ErrUnauthorized.Wrap(err)
	}
	if _, err = s.requireOrgMember(ctx, orgID, user.ID); err != nil {
		return 0, err
	}
	return s.store.OrgNodes().CountByOrgID(ctx, orgID)
}

// MapNodeFromCheckIn maps a storage node when operator email is ownnodes:<userUUID>
// (preferred) or legacy ownnodes:<userUUID>:<orgUUID>. With user-only form, the
// node is attached to the user's node group automatically.
func (s *Service) MapNodeFromCheckIn(ctx context.Context, nodeID storxnetwork.NodeID, operatorEmail string) (err error) {
	defer mon.Task()(&ctx)(&err)

	userID, orgID, ok := ParseOwnNodesOperatorEmail(operatorEmail)
	if !ok {
		return nil
	}

	if orgID.IsZero() {
		orgs, listErr := s.store.Organizations().ListByUserID(ctx, userID)
		if listErr != nil {
			return Error.Wrap(listErr)
		}
		if len(orgs) == 0 {
			s.log.Info("own-nodes check-in mapping skipped; user has no node group",
				zap.String("node_id", nodeID.String()),
				zap.String("user_id", userID.String()),
			)
			return nil
		}
		// Prefer a group this user created; otherwise first membership.
		orgID = orgs[0].ID
		for _, o := range orgs {
			if o.CreatedBy == userID {
				orgID = o.ID
				break
			}
		}
	}

	if _, err = s.store.OrgMembers().GetMembership(ctx, orgID, userID); err != nil {
		s.log.Info("own-nodes check-in mapping skipped; user not node-group member",
			zap.String("node_id", nodeID.String()),
			zap.String("user_id", userID.String()),
			zap.String("org_id", orgID.String()),
			zap.Error(err),
		)
		return nil
	}

	_, err = s.store.OrgNodes().Insert(ctx, orgID, nodeID, userID)
	if err != nil {
		// Idempotent check-in: already mapped (or raced) is success for same org.
		if ErrOrgNodeAlreadyClaimed.Has(err) {
			existing, getErr := s.store.OrgNodes().GetByNodeID(ctx, nodeID)
			if getErr == nil && existing != nil && existing.OrgID == orgID {
				return nil
			}
			s.log.Info("own-nodes check-in mapping skipped; node already claimed by another group",
				zap.String("node_id", nodeID.String()),
				zap.String("org_id", orgID.String()),
			)
			return nil
		}
		return Error.Wrap(err)
	}
	return nil
}

func (s *Service) requireOrgMember(ctx context.Context, orgID, userID uuid.UUID) (*OrgMember, error) {
	member, err := s.store.OrgMembers().GetMembership(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	return member, nil
}

func (s *Service) requireOrgAdmin(ctx context.Context, orgID, userID uuid.UUID) (*OrgMember, error) {
	member, err := s.requireOrgMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if member.Role != OrgRoleAdmin {
		return nil, ErrOrgForbidden.New("admin role required")
	}
	return member, nil
}

func (s *Service) resolveUserIDOrEmail(ctx context.Context, userIDOrEmail string) (uuid.UUID, error) {
	userIDOrEmail = strings.TrimSpace(userIDOrEmail)
	if userIDOrEmail == "" {
		return uuid.UUID{}, ErrOrgInvalid.New("user id or email is required")
	}
	if id, err := uuid.FromString(userIDOrEmail); err == nil {
		if _, getErr := s.store.Users().Get(ctx, id); getErr != nil {
			return uuid.UUID{}, ErrOrgInvalid.New("user not found")
		}
		return id, nil
	}
	u, err := s.store.Users().GetByEmail(ctx, userIDOrEmail)
	if err != nil {
		return uuid.UUID{}, ErrOrgInvalid.New("user not found")
	}
	return u.ID, nil
}
