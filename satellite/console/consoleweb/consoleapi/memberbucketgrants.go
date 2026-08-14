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

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

// MemberBucketGrants exposes Member ACL registry and grant HTTP APIs.
type MemberBucketGrants struct {
	log     *zap.Logger
	service *console.Service
}

// NewMemberBucketGrants is a constructor for MemberBucketGrants controller.
func NewMemberBucketGrants(log *zap.Logger, service *console.Service) *MemberBucketGrants {
	return &MemberBucketGrants{log: log, service: service}
}

func (c *MemberBucketGrants) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, c.log, w, status, err)
}

func (c *MemberBucketGrants) serveMemberACLError(ctx context.Context, w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case console.ErrUnauthorized.Has(err), console.ErrNoMembership.Has(err):
		status = http.StatusUnauthorized
	case console.ErrForbidden.Has(err):
		status = http.StatusForbidden
	case console.ErrValidation.Has(err), console.ErrMemberBucketGrant.Has(err):
		status = http.StatusBadRequest
	case console.ErrConflict.Has(err):
		status = http.StatusConflict
	}
	c.serveJSONError(ctx, w, status, err)
}

// ListACLBuckets returns registered Member ACL buckets for a project.
//
// @Summary      [3] List ACL bucket registry
// @Description  **Full route:** `GET /api/v0/projects/{id}/member-acl-buckets`
//
// Admin-managed list of buckets allowed for Member folder grants. Starts empty — register buckets before inviting with defaults. Owner/Admin only.
// @Tags         member-bucket-restriction
// @Produce      json
// @Param        id   path  string  true  "Project UUID"
// @Success      200  {array}   ProjectMemberACLBucketSwaggerItem
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/member-acl-buckets [get]
func (c *MemberBucketGrants) ListACLBuckets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, err := projectIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	rows, err := c.service.ListProjectMemberACLBuckets(ctx, projectID)
	if err != nil {
		c.serveMemberACLError(ctx, w, err)
		return
	}
	if err := json.NewEncoder(w).Encode(rows); err != nil {
		c.log.Error("failed to write member acl buckets response", zap.Error(err))
	}
}

// AddACLBucket registers a project bucket for Member ACL.
//
// @Summary      [3] Register bucket for Member ACL
// @Description  **Full route:** `POST /api/v0/projects/{id}/member-acl-buckets`
//
// Body: `{"bucketName":"gmail"}`. Bucket must already exist on the project. After this, invites can get default `{email}/` grants on this bucket. Owner/Admin. CSRF when enabled.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project UUID"
// @Param        body  body  AddProjectMemberACLBucketSwaggerRequest  true  "Bucket to register"
// @Success      201   {object}  ProjectMemberACLBucketSwaggerItem
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      403   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/member-acl-buckets [post]
func (c *MemberBucketGrants) AddACLBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, err := projectIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var body struct {
		BucketName string `json:"bucketName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	row, err := c.service.AddProjectMemberACLBucket(ctx, projectID, body.BucketName)
	if err != nil {
		c.serveMemberACLError(ctx, w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(row); err != nil {
		c.log.Error("failed to write add member acl bucket response", zap.Error(err))
	}
}

// RemoveACLBucket removes a bucket from the Member ACL registry.
//
// @Summary      [3] Unregister ACL bucket
// @Description  **Full route:** `DELETE /api/v0/projects/{id}/member-acl-buckets/{bucket}`
//
// Removes bucket from optional registry only (existing grant rows not auto-deleted). Registry is optional — invites/grants only require the bucket to exist on the project. Owner/Admin. CSRF when enabled.
// @Tags         member-bucket-restriction
// @Param        id      path  string  true  "Project UUID"
// @Param        bucket  path  string  true  "Bucket name"
// @Success      204     "No Content"
// @Failure      400     {object}  SwaggerErrorResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      403     {object}  SwaggerErrorResponse
// @Failure      500     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/member-acl-buckets/{bucket} [delete]
func (c *MemberBucketGrants) RemoveACLBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, err := projectIDFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}
	bucket, ok := mux.Vars(r)["bucket"]
	if !ok || bucket == "" {
		c.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing bucket route param"))
		return
	}

	if err := c.service.RemoveProjectMemberACLBucket(ctx, projectID, bucket); err != nil {
		c.serveMemberACLError(ctx, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetMemberGrants returns bucket grants for a project member.
//
// @Summary      [7] Get Member folder grants
// @Description  **Full route:** `GET /api/v0/projects/{id}/members/{memberID}/bucket-grants`
//
// Returns `(bucket, prefix, allowList/Download)` rows. Upload/Delete are always false (unsupported). Admin any member; Member own only. When flag ON, Member Access Grants are limited to these rows.
// @Tags         member-bucket-restriction
// @Produce      json
// @Param        id        path  string  true  "Project UUID"
// @Param        memberID  path  string  true  "Member user UUID"
// @Success      200  {array}   MemberBucketGrantSwaggerItem
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/members/{memberID}/bucket-grants [get]
func (c *MemberBucketGrants) GetMemberGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, memberID, err := projectAndMemberIDsFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	grants, err := c.service.GetMemberBucketGrants(ctx, projectID, memberID)
	if err != nil {
		c.serveMemberACLError(ctx, w, err)
		return
	}
	if err := json.NewEncoder(w).Encode(grants); err != nil {
		c.log.Error("failed to write member bucket grants response", zap.Error(err))
	}
}

// PutMemberGrants full-replaces bucket grants for a project member.
//
// @Summary      [7] Replace Member folder grants
// @Description  **Full route:** `PUT /api/v0/projects/{id}/members/{memberID}/bucket-grants`
//
// Full replace. Buckets must exist on the project. Prefix must end with `/`. ≥1 of List/Download. `{"grants":[]}` clears all Member object access. Invalidates member project API keys. Owner/Admin. CSRF when enabled.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id        path  string  true  "Project UUID"
// @Param        memberID  path  string  true  "Member user UUID"
// @Param        body      body  PutMemberBucketGrantsSwaggerRequest  true  "Full grant set (empty clears access)"
// @Success      200  {array}   MemberBucketGrantSwaggerItem
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/members/{memberID}/bucket-grants [put]
func (c *MemberBucketGrants) PutMemberGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID, memberID, err := projectAndMemberIDsFromVars(r)
	if err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var body struct {
		Grants []console.MemberBucketGrantInput `json:"grants"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		c.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}
	if body.Grants == nil {
		body.Grants = []console.MemberBucketGrantInput{}
	}

	grants, err := c.service.ReplaceMemberBucketGrants(ctx, projectID, memberID, body.Grants)
	if err != nil {
		c.serveMemberACLError(ctx, w, err)
		return
	}
	if err := json.NewEncoder(w).Encode(grants); err != nil {
		c.log.Error("failed to write put member bucket grants response", zap.Error(err))
	}
}

func projectIDFromVars(r *http.Request) (uuid.UUID, error) {
	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		return uuid.UUID{}, errs.New("missing project id route param")
	}
	return uuid.FromString(idParam)
}

func projectAndMemberIDsFromVars(r *http.Request) (projectID, memberID uuid.UUID, err error) {
	projectID, err = projectIDFromVars(r)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, err
	}
	memberParam, ok := mux.Vars(r)["memberID"]
	if !ok {
		return uuid.UUID{}, uuid.UUID{}, errs.New("missing member id route param")
	}
	memberID, err = uuid.FromString(memberParam)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, err
	}
	return projectID, memberID, nil
}
