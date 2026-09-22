// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/common/uuid"
)

var (
	// ErrUserNodesAPI - console user nodes api error type.
	ErrUserNodesAPI = errs.Class("console user nodes")
)

// UserNodes is an api controller for own-nodes claim management.
type UserNodes struct {
	log     *zap.Logger
	service *console.Service
}

// NewUserNodes is a constructor for UserNodes controller.
func NewUserNodes(log *zap.Logger, service *console.Service) *UserNodes {
	return &UserNodes{log: log, service: service}
}

// GetUserNodes returns nodes claimed by the current user.
func (c *UserNodes) GetUserNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	nodes, err := c.service.GetUserNodes(ctx)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(nodes)
	if err != nil {
		c.log.Error("failed to write user nodes response", zap.Error(ErrUserNodesAPI.Wrap(err)))
	}
}

// ClaimUserNode claims a node for the current user.
func (c *UserNodes) ClaimUserNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		NodeID string `json:"nodeId"`
	}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	node, err := c.service.ClaimUserNode(ctx, payload.NodeID)
	c.service.RecordUserAudit(ctx, "USER_NODE_CLAIM", "UserNode", "Node claimed", err)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(node)
	if err != nil {
		c.log.Error("failed to write claim user node response", zap.Error(ErrUserNodesAPI.Wrap(err)))
	}
}

// UnclaimUserNode removes a node claim for the current user.
func (c *UserNodes) UnclaimUserNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	nodeID, ok := mux.Vars(r)["nodeId"]
	if !ok || nodeID == "" {
		c.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing nodeId route param"))
		return
	}

	err = c.service.UnclaimUserNode(ctx, nodeID)
	c.service.RecordUserAudit(ctx, "USER_NODE_UNCLAIM", "UserNode", "Node unclaimed", err)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetOwnNodesOnly returns own-nodes-only status for a project.
func (c *UserNodes) GetOwnNodesOnly(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectID, err := optionalProjectID(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	status, err := c.service.GetOwnNodesOnlyStatus(ctx, projectID)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(status)
	if err != nil {
		c.log.Error("failed to write own-nodes-only status", zap.Error(ErrUserNodesAPI.Wrap(err)))
	}
}

// SetOwnNodesOnly enables or disables own-nodes-only for a project.
func (c *UserNodes) SetOwnNodesOnly(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Enabled   bool   `json:"enabled"`
		ProjectID string `json:"projectId"`
	}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var projectID uuid.UUID
	if payload.ProjectID != "" {
		projectID, err = uuid.FromString(payload.ProjectID)
		if err != nil {
			c.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	}

	status, err := c.service.SetOwnNodesOnly(ctx, projectID, payload.Enabled)
	c.service.RecordUserAudit(ctx, "USER_NODE_OWN_NODES_ONLY", "UserNode", "Own nodes only updated", err)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(status)
	if err != nil {
		c.log.Error("failed to write own-nodes-only update response", zap.Error(ErrUserNodesAPI.Wrap(err)))
	}
}

func optionalProjectID(r *http.Request) (uuid.UUID, error) {
	raw := r.URL.Query().Get("projectId")
	if raw == "" {
		return uuid.UUID{}, nil
	}
	return uuid.FromString(raw)
}

func (c *UserNodes) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if status == 0 {
		status = http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err):
			status = http.StatusUnauthorized
		case console.ErrForbidden.Has(err):
			status = http.StatusForbidden
		case console.ErrNotFound.Has(err), console.ErrUserNodeNotFound.Has(err):
			status = http.StatusNotFound
		case console.ErrUserNodeAlreadyClaimed.Has(err):
			status = http.StatusConflict
		case console.ErrUserNodeInvalid.Has(err):
			status = http.StatusBadRequest
		}
	}
	web.ServeJSONError(ctx, c.log, w, status, err)
}
