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
	// ErrOrgsAPI - console organizations api error type.
	ErrOrgsAPI = errs.Class("console organizations")
)

// Orgs is an api controller for organization own-nodes management.
type Orgs struct {
	log     *zap.Logger
	service *console.Service
}

// NewOrgs is a constructor for Orgs controller.
func NewOrgs(log *zap.Logger, service *console.Service) *Orgs {
	return &Orgs{log: log, service: service}
}

// ListOrgs returns organizations for the current user.
func (c *Orgs) ListOrgs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	orgs, err := c.service.ListOrganizations(ctx)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(orgs)
	if err != nil {
		c.log.Error("failed to write orgs list response", zap.Error(ErrOrgsAPI.Wrap(err)))
	}
}

// CreateOrg creates an organization.
func (c *Orgs) CreateOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Name string `json:"name"`
	}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	org, err := c.service.CreateOrganization(ctx, payload.Name)
	c.service.RecordUserAudit(ctx, "ORG_CREATE", "Organization", "Organization created", err)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(org)
	if err != nil {
		c.log.Error("failed to write create org response", zap.Error(ErrOrgsAPI.Wrap(err)))
	}
}

// GetOrg returns a single organization.
func (c *Orgs) GetOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	orgID, err := orgIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	org, err := c.service.GetOrganization(ctx, orgID)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(org)
	if err != nil {
		c.log.Error("failed to write get org response", zap.Error(ErrOrgsAPI.Wrap(err)))
	}
}

// AddMember adds a member to an organization.
func (c *Orgs) AddMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	orgID, err := orgIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var payload struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
		Role   string `json:"role"`
	}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	userRef := payload.UserID
	if userRef == "" {
		userRef = payload.Email
	}

	member, err := c.service.AddOrgMember(ctx, orgID, userRef, payload.Role)
	c.service.RecordUserAudit(ctx, "ORG_MEMBER_ADD", "Organization", "Org member added", err)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(member)
	if err != nil {
		c.log.Error("failed to write add org member response", zap.Error(ErrOrgsAPI.Wrap(err)))
	}
}

// RemoveMember removes a member from an organization.
func (c *Orgs) RemoveMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	orgID, err := orgIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}
	userIDStr, ok := mux.Vars(r)["userId"]
	if !ok || userIDStr == "" {
		c.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing userId route param"))
		return
	}
	userID, err := uuid.FromString(userIDStr)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	err = c.service.RemoveOrgMember(ctx, orgID, userID)
	c.service.RecordUserAudit(ctx, "ORG_MEMBER_REMOVE", "Organization", "Org member removed", err)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListNodes returns nodes claimed by an organization.
func (c *Orgs) ListNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	orgID, err := orgIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	nodes, err := c.service.ListOrgNodes(ctx, orgID)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(nodes)
	if err != nil {
		c.log.Error("failed to write org nodes response", zap.Error(ErrOrgsAPI.Wrap(err)))
	}
}

// GetNodeSetup returns setup info for connecting org nodes.
func (c *Orgs) GetNodeSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	orgID, err := orgIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	info, err := c.service.GetNodeSetup(ctx, orgID)
	if err != nil {
		c.serveJSONError(ctx, w, 0, err)
		return
	}

	err = json.NewEncoder(w).Encode(info)
	if err != nil {
		c.log.Error("failed to write node setup response", zap.Error(ErrOrgsAPI.Wrap(err)))
	}
}

func orgIDFromVars(r *http.Request) (uuid.UUID, error) {
	raw, ok := mux.Vars(r)["id"]
	if !ok || raw == "" {
		return uuid.UUID{}, errs.New("missing id route param")
	}
	return uuid.FromString(raw)
}

func (c *Orgs) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if status == 0 {
		status = http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err):
			status = http.StatusUnauthorized
		case console.ErrForbidden.Has(err), console.ErrOrgForbidden.Has(err):
			status = http.StatusForbidden
		case console.ErrNotFound.Has(err), console.ErrOrgNotFound.Has(err), console.ErrOrgNodeNotFound.Has(err):
			status = http.StatusNotFound
		case console.ErrOrgNodeAlreadyClaimed.Has(err):
			status = http.StatusConflict
		case console.ErrOrgInvalid.Has(err), console.ErrUserNodeInvalid.Has(err):
			status = http.StatusBadRequest
		}
	}
	web.ServeJSONError(ctx, c.log, w, status, err)
}
