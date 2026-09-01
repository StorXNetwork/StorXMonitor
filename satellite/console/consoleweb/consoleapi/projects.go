// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/grant"
	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/utils"
)

// Projects is an api controller that exposes projects related functionality.
type Projects struct {
	log     *zap.Logger
	service *console.Service
}

// ProjectMembersPage contains information about a page of project members and invitations.
type ProjectMembersPage struct {
	Members        []Member     `json:"projectMembers"`
	Invitations    []Invitation `json:"projectInvitations"`
	TotalCount     int          `json:"totalCount"`
	Offset         int          `json:"offset"`
	Limit          int          `json:"limit"`
	Order          int          `json:"order"`
	OrderDirection int          `json:"orderDirection"`
	Search         string       `json:"search"`
	CurrentPage    int          `json:"currentPage"`
	PageCount      int          `json:"pageCount"`
}

// Member is a project member in a ProjectMembersPage.
type Member struct {
	ID        uuid.UUID                 `json:"id"`
	FullName  string                    `json:"fullName"`
	ShortName string                    `json:"shortName"`
	Email     string                    `json:"email"`
	Role      console.ProjectMemberRole `json:"role"`
	JoinedAt  time.Time                 `json:"joinedAt"`
	// IsOwner is true when this member is projects.owner_id (ownership, not a stored role).
	IsOwner bool `json:"isOwner"`
	// Vaults are distinct bucket names from member_bucket_grants (active member ACL).
	Vaults []string `json:"vaults,omitempty"`
	// VaultExpiresAt is the earliest grant expiry (omit when none expire).
	VaultExpiresAt *time.Time `json:"vaultExpiresAt,omitempty"`
}

// Invitation is a project invitation in a ProjectMembersPage.
type Invitation struct {
	Email          string     `json:"email"`
	CreatedAt      time.Time  `json:"createdAt"`
	Expired        bool       `json:"expired"`
	LinkExpiresAt  time.Time  `json:"linkExpiresAt"`
	VaultExpiresAt *time.Time `json:"vaultExpiresAt,omitempty"`
	Vaults         []string   `json:"vaults,omitempty"`
}

// NewProjects is a constructor for api analytics controller.
func NewProjects(log *zap.Logger, service *console.Service) *Projects {
	return &Projects{
		log:     log,
		service: service,
	}
}

// GetUserProjects returns the user's projects.
//
// @Summary      List my projects
// @Description  **Full route:** `GET /api/v0/projects`
//
// Returns all projects the authenticated user owns or is a member of.
// @Tags         projects
// @Produce      json
// @Success      200  {array}   ProjectInfoSwaggerItem
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects [get]
func (p *Projects) GetUserProjects(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projects, err := p.service.GetUsersProjects(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	response := make([]console.ProjectInfo, 0)
	for _, project := range projects {
		response = append(response, p.service.GetMinimalProject(&project))
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// UpdateProject handles updating projects.
//
// @Summary      Update project
// @Description  **Full route:** `PATCH /api/v0/projects/{id}`
// @Tags         projects
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project public UUID"
// @Param        body  body  UpsertProjectSwaggerRequest  true  "Fields to update"
// @Success      200   "OK"
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id} [patch]
func (p *Projects) UpdateProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["id"]; !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var payload console.UpsertProjectInfo

	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	_, err = p.service.UpdateProject(ctx, id, payload)
	p.service.RecordUserAudit(ctx, "PROJECT_UPDATE", "Project", "Project updated", err)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		if console.ErrInvalidProjectLimit.Has(err) || console.ErrValidation.Has(err) {
			p.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// DeleteProject handles deleting projects.
//
// @Summary      Delete project (multi-step)
// @Description  **Full route:** `DELETE /api/v0/projects/{id}`
//
// Multi-step deletion flow via `step` and `data` in the JSON body. Returns 409 with blockers when the project cannot be deleted yet.
// @Tags         projects
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project public UUID"
// @Param        body  body  DeleteProjectSwaggerRequest  true  "Deletion step payload"
// @Success      200   "OK"
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      409   {object}  DeleteProjectSwaggerResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id} [delete]
func (p *Projects) DeleteProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["id"]; !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var data AccountActionData
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	if data.Step < console.DeleteProjectInit || data.Step > console.DeleteProjectStep {
		p.serveJSONError(ctx, w, http.StatusBadRequest, console.ErrValidation.New("step value is out of range"))
		return
	}

	if data.Step > console.DeleteProjectInit && data.Step != console.DeleteProjectStep && data.Data == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, console.ErrValidation.New("data value can't be empty"))
		return
	}

	resp, err := p.service.DeleteProject(ctx, id, data.Step, data.Data)
	p.service.RecordUserAudit(ctx, "PROJECT_DELETE", "Project", "Project deleted", err)
	if err != nil {
		if resp != nil {
			w.WriteHeader(http.StatusConflict)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				p.log.Error("could not encode project deletion response", zap.Error(ErrAuthAPI.Wrap(err)))
			}
			return
		}
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// UpdateUserSpecifiedLimits is a method for updating project user specified limits.
func (p *Projects) UpdateUserSpecifiedLimits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["id"]; !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var payload console.UpdateLimitsInfo

	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	err = p.service.UpdateUserSpecifiedLimits(ctx, id, payload)
	p.service.RecordUserAudit(ctx, "PROJECT_LIMITS_UPDATE", "Project limits", "Project limits updated", err)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		if console.ErrInvalidProjectLimit.Has(err) || console.ErrValidation.Has(err) {
			p.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// RequestLimitIncrease handles requesting limit increase for projects.
func (p *Projects) RequestLimitIncrease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["id"]; !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var payload console.LimitRequestInfo

	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	if payload.LimitType == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing limit type"))
		return
	}
	if payload.DesiredLimit == 0 {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing desired limit"))
		return
	}
	if payload.CurrentLimit == 0 {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing current limit"))
		return
	}

	err = p.service.RequestLimitIncrease(ctx, id, payload)
	p.service.RecordUserAudit(ctx, "PROJECT_LIMIT_INCREASE", "Project", "Project limit increase requested", err)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// CreateProject handles creating projects.
//
// @Summary      Create project
// @Description  **Full route:** `POST /api/v0/projects`
// @Tags         projects
// @Accept       json
// @Produce      json
// @Param        body  body  UpsertProjectSwaggerRequest  true  "Project name and optional limits"
// @Success      201   {object}  ProjectInfoSwaggerItem
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      403   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects [post]
func (p *Projects) CreateProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var payload console.UpsertProjectInfo

	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	project, err := p.service.CreateProject(ctx, payload)
	p.service.RecordUserAudit(ctx, "PROJECT_CREATE", "Project", "Project created", err)
	if err != nil {
		if console.ErrBotUser.Has(err) {
			p.serveJSONError(ctx, w, http.StatusForbidden, err)
			return
		}

		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		if console.ErrValidation.Has(err) {
			p.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}

		if console.ErrConflict.Has(err) {
			p.serveJSONError(ctx, w, http.StatusConflict, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(p.service.GetMinimalProject(project))
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetMembersAndInvitations returns the project's members and invitees.
//
// @Summary      [5] List project members and pending invites
// @Description  **Full route:** `GET /api/v0/projects/{id}/members`
//
// Step in Member bucket restriction flow: after invite, list members + pending invitations. Query `order`: 1=name, 2=email, 3=created. `order-direction`: 1=asc, 2=desc. Member `role`: 0=Admin, 1=Member.
// @Tags         member-bucket-restriction
// @Produce      json
// @Param        id               path   string  true   "Project UUID"
// @Param        limit            query  int     true   "Page size" default(100)
// @Param        page             query  int     false  "Page number (1-based)" default(1)
// @Param        search           query  string  false  "Search by name/email"
// @Param        order            query  int     false  "Sort field: 1=name, 2=email, 3=created" default(1)
// @Param        order-direction  query  int     false  "1=asc, 2=desc" default(1)
// @Param        kind             query  string  false  "all|members|pending|admins"
// @Param        role             query  string  false  "admin|member or 0|1 (members only; excludes owner)"
// @Param        status           query  string  false  "all|active|pending|expired"
// @Param        vault            query  string  false  "Filter by vault bucket name with ACL grant"
// @Success      200  {object}  ProjectMembersPageSwaggerResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/members [get]
func (p *Projects) GetMembersAndInvitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing id route param"))
		return
	}

	publicID, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	project, err := p.service.GetProject(ctx, publicID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing limit query param"))
		return
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid limit parameter: %s", limitStr))
		return
	}

	search := r.URL.Query().Get("search")

	pageStr := r.URL.Query().Get("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid page parameter: %s", pageStr))
		return
	}

	orderStr := r.URL.Query().Get("order")
	if orderStr == "" {
		orderStr = "1"
	}
	order, err := strconv.Atoi(orderStr)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid order parameter: %s", orderStr))
		return
	}

	orderDirStr := r.URL.Query().Get("order-direction")
	if orderDirStr == "" {
		orderDirStr = "1"
	}
	orderDir, err := strconv.Atoi(orderDirStr)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid order-direction parameter: %s", orderDirStr))
		return
	}

	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	switch kind {
	case "", console.ProjectMemberListKindAll, console.ProjectMemberListKindMembers,
		console.ProjectMemberListKindPending, console.ProjectMemberListKindAdmins:
	default:
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid kind parameter: %s", kind))
		return
	}

	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	switch status {
	case "", console.ProjectMemberListStatusAll, console.ProjectMemberListStatusActive,
		console.ProjectMemberListStatusPending, console.ProjectMemberListStatusExpired:
	default:
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid status parameter: %s", status))
		return
	}

	vaultFilter := strings.TrimSpace(r.URL.Query().Get("vault"))

	var roleFilter *console.ProjectMemberRole
	if roleStr := strings.TrimSpace(r.URL.Query().Get("role")); roleStr != "" {
		parsed, parseErr := parseProjectMemberRoleQuery(roleStr)
		if parseErr != nil {
			p.serveJSONError(ctx, w, http.StatusBadRequest, parseErr)
			return
		}
		roleFilter = &parsed
	}

	var memberPage ProjectMembersPage
	membersAndInvitations, err := p.service.GetProjectMembersAndInvitations(ctx, project.ID, console.ProjectMembersCursor{
		Search:         search,
		Limit:          uint(limit),
		Page:           uint(page),
		Order:          console.ProjectMemberOrder(order),
		OrderDirection: console.OrderDirection(orderDir),
		Kind:           kind,
		Role:           roleFilter,
		Status:         status,
		Vault:          vaultFilter,
	})
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}
	memberPage.Search = membersAndInvitations.Search
	memberPage.Limit = int(membersAndInvitations.Limit)
	memberPage.Order = int(membersAndInvitations.Order)
	memberPage.OrderDirection = int(membersAndInvitations.OrderDirection)
	memberPage.Offset = int(membersAndInvitations.Offset)
	memberPage.PageCount = int(membersAndInvitations.PageCount)
	memberPage.CurrentPage = int(membersAndInvitations.CurrentPage)
	memberPage.TotalCount = int(membersAndInvitations.TotalCount)
	memberPage.Members = []Member{}
	memberPage.Invitations = []Invitation{}

	for _, m := range membersAndInvitations.ProjectMembers {
		user, err := p.service.GetUser(ctx, m.MemberID)
		if err != nil {
			p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
			return
		}
		member := Member{
			ID:        user.ID,
			FullName:  user.FullName,
			ShortName: user.ShortName,
			Email:     user.Email,
			Role:      m.Role,
			JoinedAt:  m.CreatedAt,
			IsOwner:   m.MemberID == project.OwnerID,
		}
		if grants, gErr := p.service.GetMemberBucketGrants(ctx, project.ID, m.MemberID); gErr == nil {
			member.Vaults, member.VaultExpiresAt = console.SummarizeVaultGrants(grants)
		}
		memberPage.Members = append(memberPage.Members, member)
	}
	for _, inv := range membersAndInvitations.ProjectInvitations {
		invitee := Invitation{
			Email:         inv.Email,
			CreatedAt:     inv.CreatedAt,
			Expired:       p.service.IsProjectInvitationExpired(&inv),
			LinkExpiresAt: p.service.InviteLinkExpiresAt(&inv),
		}
		if grants, gErr := p.service.GetPendingInviteBucketGrants(ctx, project.ID, inv.Email); gErr == nil {
			invitee.Vaults, invitee.VaultExpiresAt = console.SummarizeVaultGrants(grants)
		}
		memberPage.Invitations = append(memberPage.Invitations, invitee)
	}
	err = json.NewEncoder(w).Encode(memberPage)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// UpdateMemberRole updates project member role.
//
// @Summary      [8] Update member role (Admin/Member)
// @Description  **Full route:** `PATCH /api/v0/projects/{id}/members/{memberID}`
//
// Body is a raw integer (not JSON object): `0` = Admin, `1` = Member. Promote→Admin keeps ACL rows but skips enforcement. Demote→Member reuses ACL or creates email defaults from registry. CSRF required when enabled.
// @Tags         member-bucket-restriction
// @Accept       plain
// @Produce      json
// @Param        id        path  string  true  "Project UUID"
// @Param        memberID  path  string  true  "Member user UUID"
// @Param        body      body  int     true  "Role: 0=Admin, 1=Member" example(1)
// @Success      200  {object}  ProjectMemberSwaggerItem
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Failure      409  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/members/{memberID} [patch]
func (p *Projects) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	publicID, err := uuid.FromString(projectIDParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	memberIDParam, ok := mux.Vars(r)["memberID"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing member id route param"))
		return
	}

	memberID, err := uuid.FromString(memberIDParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	newRoleBytes, err := io.ReadAll(r.Body)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	newRoleInt, err := strconv.Atoi(string(newRoleBytes))
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var newRole console.ProjectMemberRole
	switch newRoleInt {
	case int(console.RoleAdmin), int(console.RoleMember):
		newRole = console.ProjectMemberRole(newRoleInt)
	default:
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid role value"))
		return
	}

	updatedMember, err := p.service.UpdateProjectMemberRole(ctx, memberID, publicID, newRole)
	p.service.RecordUserAudit(ctx, "PROJECT_MEMBER_UPDATE", "Project member", "Project member updated", err)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		if console.ErrForbidden.Has(err) {
			p.serveJSONError(ctx, w, http.StatusForbidden, err)
			return
		}
		if console.ErrConflict.Has(err) {
			p.serveJSONError(ctx, w, http.StatusConflict, err)
			return
		}
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	user, err := p.service.GetUser(ctx, updatedMember.MemberID)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	member := Member{
		ID:        user.ID,
		FullName:  user.FullName,
		ShortName: user.ShortName,
		Email:     user.Email,
		Role:      updatedMember.Role,
		JoinedAt:  updatedMember.CreatedAt,
	}

	err = json.NewEncoder(w).Encode(member)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetMember returns project member.
//
// @Summary      [8] Get one project member
// @Description  **Full route:** `GET /api/v0/projects/{id}/members/{memberID}`
//
// Returns member id, projectID, role (0=Admin, 1=Member), and joinedAt. Use memberID for bucket-grants APIs.
// @Tags         member-bucket-restriction
// @Produce      json
// @Param        id        path  string  true  "Project UUID"
// @Param        memberID  path  string  true  "Member user UUID"
// @Success      200  {object}  ProjectMemberDetailSwaggerResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/members/{memberID} [get]
func (p *Projects) GetMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	publicID, err := uuid.FromString(projectIDParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	memberIDParam, ok := mux.Vars(r)["memberID"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing member id route param"))
		return
	}

	memberID, err := uuid.FromString(memberIDParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	member, err := p.service.GetProjectMember(ctx, memberID, publicID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	var returnedMember struct {
		ID              uuid.UUID                 `json:"id"`
		PublicProjectID uuid.UUID                 `json:"projectID"`
		Role            console.ProjectMemberRole `json:"role"`
		JoinedAt        time.Time                 `json:"joinedAt"`
	}

	returnedMember.ID = member.MemberID
	returnedMember.PublicProjectID = publicID
	returnedMember.Role = member.Role
	returnedMember.JoinedAt = member.CreatedAt

	err = json.NewEncoder(w).Encode(returnedMember)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetSalt returns the project's salt.
//
// @Summary      Get project encryption salt
// @Description  **Full route:** `GET /api/v0/projects/{id}/salt`
//
// Returns the project salt as a base64-encoded string (used for access grant / encryption setup).
// @Tags         projects
// @Produce      json
// @Param        id  path  string  true  "Project public UUID"
// @Success      200  {string}  string  "Base64-encoded salt"
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/salt [get]
func (p *Projects) GetSalt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	salt, err := p.service.GetSalt(ctx, id)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	b64SaltString := base64.StdEncoding.EncodeToString(salt)

	err = json.NewEncoder(w).Encode(b64SaltString)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetEmissionImpact returns CO2 emission impact.
func (p *Projects) GetEmissionImpact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
	}

	impact, err := p.service.GetEmissionImpact(ctx, id)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(impact)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetConfig returns config specific to a project.
//
// @Summary      Project config for S3 credentials and vault setup
// @Description  **Full route:** `GET /api/v0/projects/{id}/config`
//
// Returns project-scoped settings used by the frontend when creating access grants, S3 credentials, and vault setup flows.
//
// **Response fields:**
// - `salt` — base64-encoded project salt (also available via `GET /projects/{id}/salt`).
// - `passphrase` — managed-encryption passphrase when enabled (empty otherwise).
// - `hasManagedPassphrase`, `encryptPath` — encryption mode flags for the UI.
// - `role` — caller's project role (`0` = admin, `1` = member).
// - `isOwnerPaidTier`, `hasPaidPrivileges` — billing / feature gating for the project owner.
// - `availablePlacements` — placement options for bucket / vault creation.
// - `computeAuthToken` — present for project admins when compute UI is enabled.
// - `eventingEnabled` — whether bucket eventing is enabled for this project.
// @Tags         projects-s3-vault-setup
// @Produce      json
// @Param        id  path  string  true  "Project public UUID"
// @Success      200  {object}  ProjectConfigSwaggerResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/config [get]
func (p *Projects) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	config, err := p.service.GetProjectConfig(ctx, id)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(config)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// MigratePricing migrates classic project to use new storage tiers.
func (p *Projects) MigratePricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
	}

	err = p.service.MigrateProjectPricing(ctx, id)
	if err != nil {
		status := http.StatusInternalServerError

		switch {
		case console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err):
			status = http.StatusUnauthorized
		case console.ErrConflict.Has(err):
			status = http.StatusConflict
		case console.ErrForbidden.Has(err):
			status = http.StatusForbidden
		}
		p.serveJSONError(ctx, w, status, err)
	}
}

// InviteUser sends a project invitation to a user.
//
// @Summary      [4] Invite member (optional folder grants)
// @Description  **Full route:** `POST /api/v0/projects/{id}/invite/{email}`
//
// Invite by email. Optional body `grants`: omit → defaults from optional ACL registry (`{inviteEmail}/` List+Download); empty registry → no defaults; custom grants for any bucket that exists on the project. Only List+Download are honored (Upload/Delete ignored). Creates pending member_bucket_grants. CSRF required when enabled. Flag: `console.member-bucket-grants-enabled`.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id     path  string  true  "Project UUID"
// @Param        email  path  string  true  "Invitee email"
// @Param        body   body  InviteProjectMemberWithGrantsSwaggerRequest  false  "Optional grants (omit for defaults)"
// @Success      200    "OK"
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Failure      402    {object}  SwaggerErrorResponse
// @Failure      403    {object}  SwaggerErrorResponse
// @Failure      500    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/invite/{email} [post]
func (p *Projects) InviteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}
	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
	}

	email, ok := mux.Vars(r)["email"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing email route param"))
		return
	}
	email = strings.TrimSpace(email)

	isValidEmail := utils.ValidateEmail(email)
	if !isValidEmail {
		p.serveJSONError(ctx, w, http.StatusBadRequest, console.ErrValidation.Wrap(errs.New("Invalid email.")))
		return
	}

	var grants []console.MemberBucketGrantInput
	var linkExpiration, vaultExpiration string
	if r.Body != nil && r.ContentLength != 0 {
		var body struct {
			Grants          []console.MemberBucketGrantInput `json:"grants"`
			LinkExpiration  string                           `json:"link_expiration"`
			VaultExpiration string                           `json:"vault_expiration"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			p.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
		// Distinguish omitted grants (nil → defaults) from explicit empty array.
		if body.Grants != nil {
			grants = body.Grants
		}
		linkExpiration = body.LinkExpiration
		vaultExpiration = body.VaultExpiration
	}

	result, err := p.service.InviteNewProjectMemberDetailed(ctx, id, email, console.InviteProjectMemberParams{
		Grants:          grants,
		LinkExpiration:  linkExpiration,
		VaultExpiration: vaultExpiration,
	})
	p.service.RecordUserAudit(ctx, "PROJECT_INVITE", "Project member", "Project member invited", err)
	if err != nil {
		status := http.StatusInternalServerError
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			status = http.StatusUnauthorized
		} else if console.ErrNotPaidTier.Has(err) {
			status = http.StatusPaymentRequired
		} else if console.ErrValidation.Has(err) || console.ErrMemberBucketGrant.Has(err) {
			status = http.StatusBadRequest
		} else if console.ErrForbidden.Has(err) {
			status = http.StatusForbidden
		} else if console.ErrAlreadyInvited.Has(err) || console.ErrAlreadyMember.Has(err) {
			status = http.StatusConflict
		}
		p.serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(result)
	if err != nil {
		p.log.Error("could not write invite response", zap.Error(err))
	}
}

// UpdatePendingInviteAccess updates link expiry and/or vault grants for a pending invite.
//
// @Summary      Update pending invite access
// @Description  **Full route:** `PUT /api/v0/projects/{id}/invite/{email}`
//
// Owner/Admin can change `link_expiration` (24h|3d|7d|30d), `vault_expiration`, and `grants` (nil = leave grants; [] = clear). Optional `resend:true` re-delivers the invite email.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id     path  string  true  "Project UUID"
// @Param        email  path  string  true  "Invitee email"
// @Param        body   body  object  true  "Update fields"
// @Success      200  {object}  console.InviteProjectMemberResult
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      403  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/invite/{email} [put]
func (p *Projects) UpdatePendingInviteAccess(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}
	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	email, ok := mux.Vars(r)["email"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing email route param"))
		return
	}
	email = strings.TrimSpace(email)
	if !utils.ValidateEmail(email) {
		p.serveJSONError(ctx, w, http.StatusBadRequest, console.ErrValidation.Wrap(errs.New("Invalid email.")))
		return
	}

	var body struct {
		Grants          *[]console.MemberBucketGrantInput `json:"grants"`
		LinkExpiration  string                            `json:"link_expiration"`
		VaultExpiration string                            `json:"vault_expiration"`
		Resend          bool                              `json:"resend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	result, err := p.service.UpdatePendingInviteAccess(ctx, id, email, console.UpdatePendingInviteParams{
		LinkExpiration:  body.LinkExpiration,
		VaultExpiration: body.VaultExpiration,
		Grants:          body.Grants,
		Resend:          body.Resend,
	})
	p.service.RecordUserAudit(ctx, "PROJECT_INVITE_UPDATE", "Project member", "Pending invite access updated", err)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err), console.ErrNoMembership.Has(err):
			status = http.StatusUnauthorized
		case console.ErrForbidden.Has(err):
			status = http.StatusForbidden
		case console.ErrValidation.Has(err), console.ErrMemberBucketGrant.Has(err), console.ErrProjectInviteInvalid.Has(err):
			status = http.StatusBadRequest
		}
		p.serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		p.log.Error("could not write update pending invite response", zap.Error(err))
	}
}

// InviteUsers sends project invitations to multiple users one-by-one (same as single invite + vaults).
//
// @Summary      [4] Invite multiple members (one-by-one)
// @Description  **Full route:** `POST /api/v0/projects/{id}/invites`
//
// Body: `{ "invites": [ { "email":"a@x.com", "vaults":["gmail","google-drive"] } ] }`.
// Same as single invite: each email gets List+Download on `{email}/` under the given vault names.
// Vault buckets must exist on the project (no separate ACL registration). Omit `vaults` → optional registry defaults. `vaults:[]` → no folder access. Max 50. Returns per-email ok/error.
// CSRF required when enabled.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project UUID"
// @Param        body  body  BulkInviteProjectMembersSwaggerRequest  true  "Invites with vaults"
// @Success      200   {object}  BulkInviteProjectMembersSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      403   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/invites [post]
func (p *Projects) InviteUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}
	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var body struct {
		Invites []struct {
			Email  string    `json:"email"`
			Vaults *[]string `json:"vaults"`
		} `json:"invites"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	requests := make([]console.ProjectMemberInviteRequest, 0, len(body.Invites))
	for _, item := range body.Invites {
		email := strings.TrimSpace(item.Email)
		if email == "" {
			continue
		}
		if !utils.ValidateEmail(email) {
			p.serveJSONError(ctx, w, http.StatusBadRequest, console.ErrValidation.Wrap(errs.New("Invalid email: %s", email)))
			return
		}
		requests = append(requests, console.ProjectMemberInviteRequest{
			Email:  email,
			Vaults: item.Vaults,
		})
	}

	results, err := p.service.InviteNewProjectMembers(ctx, id, requests)
	p.service.RecordUserAudit(ctx, "PROJECT_INVITE_BULK", "Project member", "Project members invited", err)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err), console.ErrNoMembership.Has(err):
			status = http.StatusUnauthorized
		case console.ErrForbidden.Has(err):
			status = http.StatusForbidden
		case console.ErrValidation.Has(err), console.ErrMemberBucketGrant.Has(err):
			status = http.StatusBadRequest
		case console.ErrNotPaidTier.Has(err):
			status = http.StatusPaymentRequired
		}
		p.serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"results": results}); err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// ReinviteUsers resends expired project invitations.
//
// @Summary      [8] Reinvite expired members
// @Description  **Full route:** `POST /api/v0/projects/{id}/reinvite`
//
// Resend invites for emails. Does not overwrite Admin-customized pending folder grants. CSRF required when enabled.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project UUID"
// @Param        body  body  ReinviteProjectMembersSwaggerRequest  true  "Emails to reinvite"
// @Success      200   "OK"
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      402   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/reinvite [post]
func (p *Projects) ReinviteUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}
	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
	}

	var data struct {
		Emails         []string `json:"emails"`
		LinkExpiration string   `json:"link_expiration"`
	}

	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	for i, email := range data.Emails {
		data.Emails[i] = strings.TrimSpace(email)
	}

	_, err = p.service.ReinviteProjectMembersDetailed(ctx, id, console.ReinviteProjectMembersParams{
		Emails:         data.Emails,
		LinkExpiration: data.LinkExpiration,
	})
	p.service.RecordUserAudit(ctx, "PROJECT_REINVITE", "Project member", "Project members reinvited", err)
	if err != nil {
		status := http.StatusInternalServerError
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			status = http.StatusUnauthorized
		} else if console.ErrNotPaidTier.Has(err) {
			status = http.StatusPaymentRequired
		} else if console.ErrValidation.Has(err) {
			status = http.StatusBadRequest
		}
		p.serveJSONError(ctx, w, status, err)
	}
}

// GetInviteLink returns a link to an invitation given project ID and invitee's email.
//
// @Summary      [8] Get invite link
// @Description  **Full route:** `GET /api/v0/projects/{id}/invite-link?email=`
//
// Returns invite URL JSON string for sharing / checking an invitation.
// @Tags         member-bucket-restriction
// @Produce      json
// @Param        id     path   string  true  "Project UUID"
// @Param        email  query  string  true  "Invitee email"
// @Success      200    {string}  string  "Invite URL"
// @Failure      400    {object}  SwaggerErrorResponse
// @Failure      401    {object}  SwaggerErrorResponse
// @Failure      403    {object}  SwaggerErrorResponse
// @Failure      500    {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/{id}/invite-link [get]
func (p *Projects) GetInviteLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	idParam, ok := mux.Vars(r)["id"]
	if !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}
	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing email query param"))
		return
	}

	link, err := p.service.GetInviteLink(ctx, id, email)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		if console.ErrForbidden.Has(err) {
			p.serveJSONError(ctx, w, http.StatusForbidden, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}

	err = json.NewEncoder(w).Encode(link)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetUserInvitations returns the user's pending project member invitations.
//
// @Summary      [6] List my pending invitations (invitee)
// @Description  **Full route:** `GET /api/v0/projects/invitations`
//
// Call as the invitee user. Returns pending invites (project name, inviter email, createdAt). Then accept via respond.
// @Tags         member-bucket-restriction
// @Produce      json
// @Success      200  {array}   UserProjectInvitationSwaggerItem
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /projects/invitations [get]
func (p *Projects) GetUserInvitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	invites, err := p.service.GetUserProjectInvitations(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	type jsonInvite struct {
		ProjectID          uuid.UUID  `json:"projectID"`
		ProjectName        string     `json:"projectName"`
		ProjectDescription string     `json:"projectDescription"`
		InviterEmail       string     `json:"inviterEmail"`
		CreatedAt          time.Time  `json:"createdAt"`
		LinkExpiresAt      time.Time  `json:"linkExpiresAt"`
		VaultExpiresAt     *time.Time `json:"vaultExpiresAt,omitempty"`
		Vaults             []string   `json:"vaults,omitempty"`
	}

	response := []jsonInvite{}

	for _, invite := range invites {
		proj, err := p.service.GetProjectNoAuth(ctx, invite.ProjectID)
		if err != nil {
			p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
			return
		}

		respInvite := jsonInvite{
			ProjectID:          proj.PublicID,
			ProjectName:        proj.Name,
			ProjectDescription: proj.Description,
			CreatedAt:          invite.CreatedAt,
			LinkExpiresAt:      p.service.InviteLinkExpiresAt(&invite),
		}

		if invite.InviterID != nil {
			inviter, err := p.service.GetUser(ctx, *invite.InviterID)
			if err != nil {
				p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
				return
			}
			respInvite.InviterEmail = inviter.Email
		}

		if grants, gErr := p.service.GetPendingInviteBucketGrants(ctx, invite.ProjectID, invite.Email); gErr == nil {
			respInvite.Vaults, respInvite.VaultExpiresAt = console.SummarizeVaultGrants(grants)
		}

		response = append(response, respInvite)
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// RespondToInvitation handles accepting or declining a user's project member invitation.
//
// @Summary      [6] Accept or decline invitation (invitee)
// @Description  **Full route:** `POST /api/v0/projects/invitations/{id}/respond`
//
// Path `id` = project public UUID. Body `response`: `0`=decline, `1`=accept. Accept binds pending folder grants to member_id and invalidates member API keys. Decline deletes pending grants. CSRF required when enabled.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project public UUID"
// @Param        body  body  RespondToProjectInvitationSwaggerRequest  true  "Accept or decline"
// @Success      200   "OK"
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      403   {object}  SwaggerErrorResponse
// @Failure      404   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/invitations/{id}/respond [post]
func (p *Projects) RespondToInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["id"]; !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var payload struct {
		Response console.ProjectInvitationResponse `json:"response"`
	}

	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	err = p.service.RespondToProjectInvitation(ctx, id, payload.Response)
	p.service.RecordUserAudit(ctx, "PROJECT_INVITATION_RESPOND", "Project invitation", "Project invitation responded", err)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case console.ErrUnauthorized.Has(err):
			status = http.StatusUnauthorized
		case console.ErrAlreadyMember.Has(err):
			status = http.StatusConflict
		case console.ErrProjectInviteInvalid.Has(err):
			status = http.StatusNotFound
		case console.ErrValidation.Has(err):
			status = http.StatusBadRequest
		case console.ErrBotUser.Has(err):
			status = http.StatusForbidden
		}
		p.serveJSONError(ctx, w, status, err)
	}
}

// DeleteMembersAndInvitations deletes members and invitations from a project.
//
// @Summary      [8] Remove members / cancel invites
// @Description  **Full route:** `DELETE /api/v0/projects/{id}/members`
//
// Body: emails + optional removeAccesses. Removes members and/or pending invites; cleans ACL rows; can revoke member API keys. CSRF required when enabled.
// @Tags         member-bucket-restriction
// @Accept       json
// @Produce      json
// @Param        id    path  string  true  "Project UUID"
// @Param        body  body  DeleteMembersAndInvitationsSwaggerRequest  true  "Emails to remove"
// @Success      200   "OK"
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Security     CSRFAuth
// @Router       /projects/{id}/members [delete]
func (p *Projects) DeleteMembersAndInvitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["id"]; !ok {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing project id route param"))
		return
	}

	id, err := uuid.FromString(idParam)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
	}

	var payload console.DeleteMembersAndInvitationsRequest
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	err = p.service.DeleteProjectMembersAndInvitations(ctx, id, payload)
	p.service.RecordUserAudit(ctx, "PROJECT_MEMBERS_DELETE", "Project members", "Project members removed", err)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetProjectIDFromAccessGrant returns project_id from access grant.
// This endpoint is used by Backup-Tools to identify the project associated with an access grant.
// It accepts an access grant in the request body and returns the project's public ID.
func (p *Projects) GetProjectIDFromAccessGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	// Parse request body
	var request struct {
		AccessGrant string `json:"access_grant"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	if request.AccessGrant == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("access_grant is required"))
		return
	}

	// Parse access grant
	access, err := grant.ParseAccess(request.AccessGrant)
	if err != nil {
		p.log.Info("Failed to parse access grant", zap.Error(err))
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid access grant format"))
		return
	}

	apiKeyHead := access.APIKey.Head()

	apiKeyInfo, err := p.service.GetAPIKeysStore().GetByHead(ctx, apiKeyHead)
	if err != nil {
		p.log.Info("Failed to get API key info", zap.Error(err))
		p.serveJSONError(ctx, w, http.StatusUnauthorized, errs.New("invalid access grant or API key not found"))
		return
	}

	project, err := p.service.GetProjectNoAuth(ctx, apiKeyInfo.ProjectID)
	if err != nil {
		p.log.Info("Failed to resolve project for access grant", zap.Error(err))
		p.serveJSONError(ctx, w, http.StatusUnauthorized, errs.New("invalid access grant or API key not found"))
		return
	}

	response := struct {
		ProjectID string `json:"project_id"`
	}{
		ProjectID: project.PublicID.String(),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

func parseProjectMemberRoleQuery(roleStr string) (console.ProjectMemberRole, error) {
	switch strings.ToLower(strings.TrimSpace(roleStr)) {
	case "0", "admin":
		return console.RoleAdmin, nil
	case "1", "member":
		return console.RoleMember, nil
	default:
		return 0, errs.New("invalid role parameter: %s", roleStr)
	}
}

// serveJSONError writes JSON error to response output stream.
func (p *Projects) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, p.log, w, status, err)
}
