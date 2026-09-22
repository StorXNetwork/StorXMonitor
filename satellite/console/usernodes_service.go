// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
)

// GetUserNodes returns storage nodes claimed by the current user.
func (s *Service) GetUserNodes(ctx context.Context) (nodes []UserNode, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	nodes, err = s.store.UserNodes().GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if nodes == nil {
		nodes = []UserNode{}
	}
	return nodes, nil
}

// ClaimUserNode claims a storage node for the current user.
//
// Ownership policy: a node may be claimed if it exists in the overlay nodes
// table. Operator email matching the console user email is preferred (soft
// check) but is not required. A node may only be claimed by one user.
func (s *Service) ClaimUserNode(ctx context.Context, nodeIDStr string) (node *UserNode, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	nodeID, err := ParseNodeID(nodeIDStr)
	if err != nil {
		return nil, err
	}

	exists, operatorEmail, err := s.store.UserNodes().NodeExists(ctx, nodeID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !exists {
		return nil, ErrUserNodeInvalid.New("node does not exist")
	}

	if operatorEmail != "" && !strings.EqualFold(operatorEmail, user.Email) {
		s.log.Info("claiming node without matching operator email",
			zap.String("user_email", user.Email),
			zap.String("operator_email", operatorEmail),
			zap.String("node_id", nodeID.String()),
		)
	}

	node, err = s.store.UserNodes().Insert(ctx, user.ID, nodeID)
	if err != nil {
		return nil, err
	}
	return node, nil
}

// UnclaimUserNode removes a storage node claim for the current user.
func (s *Service) UnclaimUserNode(ctx context.Context, nodeIDStr string) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return ErrUnauthorized.Wrap(err)
	}

	nodeID, err := ParseNodeID(nodeIDStr)
	if err != nil {
		return err
	}

	return s.store.UserNodes().Delete(ctx, user.ID, nodeID)
}

// GetOwnNodesOnlyStatus returns whether the given (or first owned) project uses OwnNodesPlacement.
func (s *Service) GetOwnNodesOnlyStatus(ctx context.Context, projectID uuid.UUID) (status *OwnNodesOnlyStatus, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	project, err := s.resolveOwnNodesProject(ctx, user.ID, projectID)
	if err != nil {
		return nil, err
	}

	return &OwnNodesOnlyStatus{
		Enabled:   project.DefaultPlacement == nodeselection.OwnNodesPlacement,
		ProjectID: project.PublicID,
		Placement: int(project.DefaultPlacement),
	}, nil
}

// SetOwnNodesOnly enables or disables own-nodes-only uploads for a project by
// setting DefaultPlacement to OwnNodesPlacement or DefaultPlacement.
func (s *Service) SetOwnNodesOnly(ctx context.Context, projectID uuid.UUID, enabled bool) (status *OwnNodesOnlyStatus, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	project, err := s.resolveOwnNodesProject(ctx, user.ID, projectID)
	if err != nil {
		return nil, err
	}

	if project.OwnerID != user.ID {
		return nil, ErrForbidden.New("only the project owner can change own-nodes-only")
	}

	placement := storxnetwork.DefaultPlacement
	if enabled {
		placement = nodeselection.OwnNodesPlacement
	}

	err = s.store.Projects().UpdateDefaultPlacement(ctx, project.ID, placement)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &OwnNodesOnlyStatus{
		Enabled:   enabled,
		ProjectID: project.PublicID,
		Placement: int(placement),
	}, nil
}

func (s *Service) resolveOwnNodesProject(ctx context.Context, userID, projectID uuid.UUID) (*Project, error) {
	if projectID.IsZero() {
		projects, err := s.store.Projects().GetOwnActive(ctx, userID)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		if len(projects) == 0 {
			return nil, ErrNotFound.New("no project found")
		}
		return &projects[0], nil
	}

	membership, err := s.isProjectMember(ctx, userID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	return membership.project, nil
}
