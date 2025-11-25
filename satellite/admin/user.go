// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/uuid"
	"storj.io/storj/private/post"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/payments"
)

func (server *Server) addUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input console.CreateUser

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	user := console.CreateUser{
		Email:           input.Email,
		FullName:        input.FullName,
		Password:        input.Password,
		SignupPromoCode: input.SignupPromoCode,
	}

	err = user.IsValid(false)
	if err != nil {
		sendJSONError(w, "user data is not valid",
			err.Error(), http.StatusBadRequest)
		return
	}

	existingUser, err := server.db.Console().Users().GetByEmail(ctx, input.Email)
	if err != nil && !errors.Is(sql.ErrNoRows, err) {
		sendJSONError(w, "failed to check for user email",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		sendJSONError(w, fmt.Sprintf("user with email already exists %s", input.Email),
			"", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), 0)
	if err != nil {
		sendJSONError(w, "unable to save password hash",
			"", http.StatusInternalServerError)
		return
	}

	userID, err := uuid.New()
	if err != nil {
		sendJSONError(w, "unable to create UUID",
			"", http.StatusInternalServerError)
		return
	}

	newUser, err := server.db.Console().Users().Insert(ctx, &console.User{
		ID:                    userID,
		FullName:              user.FullName,
		ShortName:             user.ShortName,
		Email:                 user.Email,
		PasswordHash:          hash,
		ProjectLimit:          server.console.DefaultProjectLimit,
		ProjectStorageLimit:   server.console.UsageLimits.Storage.Free.Int64(),
		ProjectBandwidthLimit: server.console.UsageLimits.Bandwidth.Free.Int64(),
		SignupPromoCode:       user.SignupPromoCode,
	})
	if err != nil {
		sendJSONError(w, "failed to insert user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// _, err = server.payments.Setup(ctx, newUser.ID, newUser.Email, newUser.SignupPromoCode)
	// if err != nil {
	// 	sendJSONError(w, "failed to create payment account for user",
	// 		err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// Set User Status to be activated, as we manually created it
	newUser.Status = console.Active
	err = server.db.Console().Users().Update(ctx, userID, console.UpdateUserRequest{
		Status: &newUser.Status,
	})
	if err != nil {
		sendJSONError(w, "failed to activate user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(newUser)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) userInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	// Use GetByEmailWithUnverified to get users regardless of status (including inactive)
	// This allows admin to access inactive users, but we'll still block deleted users
	verified, unverified, err := server.db.Console().Users().GetByEmailWithUnverified(ctx, userEmail)
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the user - could be in verified (active) or unverified (inactive, etc.)
	var user *console.User
	if verified != nil {
		user = verified
	} else if len(unverified) > 0 {
		// Use the first unverified user (should only be one per email)
		user = &unverified[0]
	} else {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}

	// Prevent access to deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot access deleted user",
			"user has been deleted and cannot be accessed", http.StatusForbidden)
		return
	}

	user.PasswordHash = nil

	projects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user projects",
			err.Error(), http.StatusInternalServerError)
		return
	}

	type User struct {
		ID           uuid.UUID                 `json:"id"`
		FullName     string                    `json:"fullName"`
		Email        string                    `json:"email"`
		ProjectLimit int                       `json:"projectLimit"`
		Placement    storj.PlacementConstraint `json:"placement"`
		PaidTier     bool                      `json:"paidTier"`
		Status       int                       `json:"status"`
	}
	type Project struct {
		ID                    uuid.UUID `json:"id"`
		PublicID              uuid.UUID `json:"publicId"`
		Name                  string    `json:"name"`
		Description           string    `json:"description"`
		OwnerID               uuid.UUID `json:"ownerId"`
		CreatedAt             time.Time `json:"createdAt"`
		StorageLimit          *int64    `json:"storageLimit"`
		BandwidthLimit        *int64    `json:"bandwidthLimit"`
		SegmentLimit          *int64    `json:"segmentLimit"`
		StorageUsed           int64     `json:"storageUsed"`
		BandwidthUsed         int64     `json:"bandwidthUsed"`
		SegmentUsed           int64     `json:"segmentUsed"`
		StorageUsedPercentage float64   `json:"storageUsedPercentage"`
		DefaultPlacement      int       `json:"defaultPlacement"`
	}

	var output struct {
		User     User      `json:"user"`
		Projects []Project `json:"projects"`
	}

	output.User = User{
		ID:           user.ID,
		FullName:     user.FullName,
		Email:        user.Email,
		ProjectLimit: user.ProjectLimit,
		Placement:    user.DefaultPlacement,
		PaidTier:     user.PaidTier,
		Status:       int(user.Status),
	}
	for _, p := range projects {
		var storageLimit *int64
		if p.StorageLimit != nil {
			limit := int64(*p.StorageLimit)
			storageLimit = &limit
		}

		var bandwidthLimit *int64
		if p.BandwidthLimit != nil {
			limit := int64(*p.BandwidthLimit)
			bandwidthLimit = &limit
		}

		storageUsed, bandwidthUsed, segmentUsed := server.getProjectUsageData(ctx, p.ID)

		output.Projects = append(output.Projects, Project{
			ID:                    p.ID,
			PublicID:              p.PublicID,
			Name:                  p.Name,
			Description:           p.Description,
			OwnerID:               p.OwnerID,
			CreatedAt:             p.CreatedAt,
			StorageLimit:          storageLimit,
			BandwidthLimit:        bandwidthLimit,
			SegmentLimit:          p.SegmentLimit,
			StorageUsed:           storageUsed,
			BandwidthUsed:         bandwidthUsed,
			SegmentUsed:           segmentUsed,
			StorageUsedPercentage: p.StorageUsedPercentage,
			DefaultPlacement:      int(p.DefaultPlacement),
		})
	}

	data, err := json.Marshal(output)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) usersPendingDeletion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	type User struct {
		ID       uuid.UUID `json:"id"`
		FullName string    `json:"fullName"`
		Email    string    `json:"email"`
	}

	query := r.URL.Query()

	limitParam := query.Get("limit")
	if limitParam == "" {
		sendJSONError(w, "Bad request", "parameter 'limit' can't be empty", http.StatusBadRequest)
		return
	}

	limit, err := strconv.ParseUint(limitParam, 10, 32)
	if err != nil {
		sendJSONError(w, "Bad request", err.Error(), http.StatusBadRequest)
		return
	}

	pageParam := query.Get("page")
	if pageParam == "" {
		sendJSONError(w, "Bad request", "parameter 'page' can't be empty", http.StatusBadRequest)
		return
	}

	page, err := strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		sendJSONError(w, "Bad request", err.Error(), http.StatusBadRequest)
		return
	}

	var sendingPage struct {
		Users       []User `json:"users"`
		PageCount   uint   `json:"pageCount"`
		CurrentPage uint   `json:"currentPage"`
		TotalCount  uint64 `json:"totalCount"`
		HasMore     bool   `json:"hasMore"`
	}
	usersPage, err := server.db.Console().Users().GetByStatus(
		ctx, console.PendingDeletion, console.UserCursor{
			Limit: uint(limit),
			Page:  uint(page),
		},
	)
	if err != nil {
		sendJSONError(w, "failed retrieving a usersPage of users", err.Error(), http.StatusInternalServerError)
		return
	}

	sendingPage.PageCount = usersPage.PageCount
	sendingPage.CurrentPage = usersPage.CurrentPage
	sendingPage.TotalCount = usersPage.TotalCount
	sendingPage.Users = make([]User, 0, len(usersPage.Users))

	if sendingPage.PageCount > sendingPage.CurrentPage {
		sendingPage.HasMore = true
	}

	for _, user := range usersPage.Users {
		invoices, err := server.payments.Invoices().ListFailed(ctx, &user.ID)
		if err != nil {
			sendJSONError(w, "getting invoices failed",
				err.Error(), http.StatusInternalServerError)
			return
		}
		if len(invoices) != 0 {
			sendingPage.TotalCount--
			continue
		}
		sendingPage.Users = append(sendingPage.Users, User{
			ID:       user.ID,
			FullName: user.FullName,
			Email:    user.Email,
		})
	}

	data, err := json.Marshal(sendingPage)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) userLimits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}
	user.PasswordHash = nil

	var limits struct {
		Storage   int64 `json:"storage"`
		Bandwidth int64 `json:"bandwidth"`
		Segment   int64 `json:"segment"`
	}

	limits.Storage = user.ProjectStorageLimit
	limits.Bandwidth = user.ProjectBandwidthLimit
	limits.Segment = user.ProjectSegmentLimit

	data, err := json.Marshal(limits)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Prevent modifications on deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot update deleted user",
			"user has been deleted and cannot be modified", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	type UserWithPaidTier struct {
		console.User
		PaidTierStr string `json:"paidTierStr"`
		Status      *int   `json:"status"` // Add status field for admin status updates
	}

	var input UserWithPaidTier

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	updateRequest := console.UpdateUserRequest{}

	if input.FullName != "" {
		updateRequest.FullName = &input.FullName
	}
	if input.ShortName != "" {
		shortNamePtr := &input.ShortName
		updateRequest.ShortName = &shortNamePtr
	}
	if input.Email != "" {
		existingUser, err := server.db.Console().Users().GetByEmail(ctx, input.Email)
		if err != nil && !errors.Is(sql.ErrNoRows, err) {
			sendJSONError(w, "failed to check for user email",
				err.Error(), http.StatusInternalServerError)
			return
		}
		if existingUser != nil {
			sendJSONError(w, fmt.Sprintf("user with email already exists %s", input.Email),
				"", http.StatusConflict)
			return
		}
		updateRequest.Email = &input.Email
	}
	if len(input.PasswordHash) > 0 {
		updateRequest.PasswordHash = input.PasswordHash
	}
	if input.ProjectLimit > 0 {
		updateRequest.ProjectLimit = &input.ProjectLimit
	}
	if input.ProjectStorageLimit > 0 {
		updateRequest.ProjectStorageLimit = &input.ProjectStorageLimit
	}
	if input.ProjectBandwidthLimit > 0 {
		updateRequest.ProjectBandwidthLimit = &input.ProjectBandwidthLimit
	}
	if input.ProjectSegmentLimit > 0 {
		updateRequest.ProjectSegmentLimit = &input.ProjectSegmentLimit
	}
	if input.PaidTierStr != "" {
		status, err := strconv.ParseBool(input.PaidTierStr)
		if err != nil {
			sendJSONError(w, "failed to parse paid tier status",
				err.Error(), http.StatusBadRequest)
			return
		}

		updateRequest.PaidTier = &status

		if status {
			now := server.nowFn()
			updateRequest.UpgradeTime = &now
		}
	}
	// Allow admin to update user status
	if input.Status != nil {
		statusValue := console.UserStatus(*input.Status)
		// Validate status value (0-5 are valid statuses)
		if statusValue < 0 || statusValue > 5 {
			sendJSONError(w, "invalid status value",
				"status must be between 0 (Inactive) and 5 (Pending Bot Verification)", http.StatusBadRequest)
			return
		}
		updateRequest.Status = &statusValue
	}

	err = server.db.Console().Users().Update(ctx, user.ID, updateRequest)
	if err != nil {
		sendJSONError(w, "failed to update user",
			err.Error(), http.StatusInternalServerError)
		return
	}
}

func (server *Server) updateUsersUserAgent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	creationDatePlusMonth := user.CreatedAt.AddDate(0, 1, 0)
	if time.Now().After(creationDatePlusMonth) {
		sendJSONError(w, "this user was created more than a month ago",
			"we should update user agent only for recently created users", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		UserAgent string `json:"userAgent"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	if input.UserAgent == "" {
		sendJSONError(w, "UserAgent was not provided",
			"", http.StatusBadRequest)
		return
	}

	newUserAgent := []byte(input.UserAgent)

	if bytes.Equal(user.UserAgent, newUserAgent) {
		sendJSONError(w, "new UserAgent is equal to existing users UserAgent",
			"", http.StatusBadRequest)
		return
	}

	err = server.db.Console().Users().UpdateUserAgent(ctx, user.ID, newUserAgent)
	if err != nil {
		sendJSONError(w, "failed to update user's user agent",
			err.Error(), http.StatusInternalServerError)
		return
	}

	projects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get users projects",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var errList errs.Group
	for _, project := range projects {
		if bytes.Equal(project.UserAgent, newUserAgent) {
			errList.Add(errs.New("projectID: %s. New UserAgent is equal to existing users UserAgent", project.ID))
			continue
		}

		err = server._updateProjectsUserAgent(ctx, project.ID, newUserAgent)
		if err != nil {
			errList.Add(errs.New("projectID: %s. Failed to update projects user agent: %s", project.ID, err))
		}
	}

	if errList.Err() != nil {
		sendJSONError(w, "failed to update projects user agent",
			errList.Err().Error(), http.StatusInternalServerError)
	}
}

// updateLimits updates user limits and all project limits for that user (future and existing).
func (server *Server) updateLimits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Prevent modifications on deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot update limits for deleted user",
			"user has been deleted and cannot be modified", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Storage   memory.Size `json:"storage"`
		Bandwidth memory.Size `json:"bandwidth"`
		Segment   int64       `json:"segment"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	newLimits := console.UsageLimits{
		Storage:   user.ProjectStorageLimit,
		Bandwidth: user.ProjectBandwidthLimit,
		Segment:   user.ProjectSegmentLimit,
	}

	if input.Storage > 0 {
		newLimits.Storage = input.Storage.Int64()
	}
	if input.Bandwidth > 0 {
		newLimits.Bandwidth = input.Bandwidth.Int64()
	}
	if input.Segment > 0 {
		newLimits.Segment = input.Segment
	}

	if newLimits.Storage == user.ProjectStorageLimit &&
		newLimits.Bandwidth == user.ProjectBandwidthLimit &&
		newLimits.Segment == user.ProjectSegmentLimit {
		sendJSONError(w, "no limits to update",
			"new values are equal to old ones", http.StatusBadRequest)
		return
	}

	err = server.db.Console().Users().UpdateUserProjectLimits(ctx, user.ID, newLimits)
	if err != nil {
		sendJSONError(w, "failed to update user limits",
			err.Error(), http.StatusInternalServerError)
		return
	}

	userProjects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user's projects",
			err.Error(), http.StatusInternalServerError)
		return
	}

	for _, p := range userProjects {
		err = server.db.Console().Projects().UpdateUsageLimits(ctx, p.ID, newLimits)
		if err != nil {
			sendJSONError(w, "failed to update project limits",
				err.Error(), http.StatusInternalServerError)
		}
	}
}

// getUpgradeAccountInfo returns current account upgrade information for the UI form.
func (server *Server) getUpgradeAccountInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail), "", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user", err.Error(), http.StatusInternalServerError)
		return
	}

	// Prevent modifications on deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot get upgrade info for deleted user",
			"user has been deleted and cannot be modified", http.StatusForbidden)
		return
	}

	// Get all user's projects to get current limits
	userProjects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user's projects", err.Error(), http.StatusInternalServerError)
		return
	}

	// Build response with current values
	response := struct {
		UserEmail                   string `json:"userEmail"`
		PaidTier                    bool   `json:"paidTier"`
		StorageLimit                *int64 `json:"storageLimit,omitempty"`                // from first project or user-level
		BandwidthLimit              *int64 `json:"bandwidthLimit,omitempty"`              // from first project or user-level
		UserSpecifiedStorageLimit   *int64 `json:"userSpecifiedStorageLimit,omitempty"`   // from first project
		UserSpecifiedBandwidthLimit *int64 `json:"userSpecifiedBandwidthLimit,omitempty"` // from first project
		ProjectsCount               int    `json:"projectsCount"`
		PrevDaysUntilExpiration     int    `json:"prevDaysUntilExpiration"`
	}{
		UserEmail:     userEmail,
		PaidTier:      user.PaidTier,
		ProjectsCount: len(userProjects),
	}

	// Get limits from first project if available, otherwise use user-level limits
	if len(userProjects) > 0 {
		firstProject := userProjects[0]
		if firstProject.StorageLimit != nil {
			limit := int64(*firstProject.StorageLimit)
			response.StorageLimit = &limit
		}
		if firstProject.BandwidthLimit != nil {
			limit := int64(*firstProject.BandwidthLimit)
			response.BandwidthLimit = &limit
		}
		if firstProject.UserSpecifiedStorageLimit != nil {
			limit := int64(*firstProject.UserSpecifiedStorageLimit)
			response.UserSpecifiedStorageLimit = &limit
		}
		if firstProject.UserSpecifiedBandwidthLimit != nil {
			limit := int64(*firstProject.UserSpecifiedBandwidthLimit)
			response.UserSpecifiedBandwidthLimit = &limit
		}
		// Get PrevDaysUntilExpiration from first project
		response.PrevDaysUntilExpiration = firstProject.PrevDaysUntilExpiration
	} else {
		// No projects, use user-level limits
		if user.ProjectStorageLimit > 0 {
			response.StorageLimit = &user.ProjectStorageLimit
		}
		if user.ProjectBandwidthLimit > 0 {
			response.BandwidthLimit = &user.ProjectBandwidthLimit
		}
		// No projects, so PrevDaysUntilExpiration is 0
		response.PrevDaysUntilExpiration = 0
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// upgradeUserAccount upgrades a user to paid tier, updates project limits, and resets expiration.
// This is an atomic operation that handles all upgrade-related changes in one transaction.
func (server *Server) upgradeUserAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Get admin user from context for audit logging
	adminUser, err := GetAdminUser(ctx)
	if err != nil {
		sendJSONError(w, "unauthorized", "admin user not found in context", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail), "", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user", err.Error(), http.StatusInternalServerError)
		return
	}

	// Prevent modifications on deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot upgrade deleted user account",
			"user has been deleted and cannot be modified", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body", err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		StorageLimit                int64  `json:"storageLimit"`                // in bytes (usage_limit)
		BandwidthLimit              int64  `json:"bandwidthLimit"`              // in bytes (bandwidth_limit)
		UserSpecifiedStorageLimit   *int64 `json:"userSpecifiedStorageLimit"`   // optional: user_specified_usage_limit
		UserSpecifiedBandwidthLimit *int64 `json:"userSpecifiedBandwidthLimit"` // optional: user_specified_bandwidth_limit
		UpgradeToPaid               bool   `json:"upgradeToPaid"`               // whether to upgrade to paid tier
		ResetExpiration             bool   `json:"resetExpiration"`             // whether to reset expiration tracking
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request", err.Error(), http.StatusBadRequest)
		return
	}

	// Validate limits
	if input.StorageLimit <= 0 || input.BandwidthLimit <= 0 {
		sendJSONError(w, "invalid limits", "storage and bandwidth limits must be greater than 0", http.StatusBadRequest)
		return
	}

	// Step 1: Update paid tier status (matches: UPDATE users SET paid_tier = true/false)
	paidTier := input.UpgradeToPaid
	upgradeTime := server.nowFn()
	updateRequest := console.UpdateUserRequest{
		PaidTier:    &paidTier,
		UpgradeTime: &upgradeTime,
	}
	err = server.db.Console().Users().Update(ctx, user.ID, updateRequest)
	if err != nil {
		sendJSONError(w, "failed to update user paid tier", err.Error(), http.StatusInternalServerError)
		return
	}
	if input.UpgradeToPaid {
		server.log.Info("User upgraded to paid tier",
			zap.String("user_email", userEmail),
			zap.String("admin_email", adminUser.Email))
	} else {
		server.log.Info("User downgraded from paid tier",
			zap.String("user_email", userEmail),
			zap.String("admin_email", adminUser.Email))
	}

	// Step 2: Get all user's projects
	userProjects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user's projects", err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 3: Update all projects
	now := time.Now().UTC()
	for _, project := range userProjects {
		// Always update usage_limit and bandwidth_limit (storage and bandwidth limits)
		storageLimit := memory.Size(input.StorageLimit)
		bandwidthLimit := memory.Size(input.BandwidthLimit)
		project.StorageLimit = &storageLimit
		project.BandwidthLimit = &bandwidthLimit

		// Always set user_specified_usage_limit to match usage_limit when admin upgrades
		// If explicitly provided, use that value; otherwise use the same as usage_limit
		if input.UserSpecifiedStorageLimit != nil {
			userSpecStorage := memory.Size(*input.UserSpecifiedStorageLimit)
			project.UserSpecifiedStorageLimit = &userSpecStorage
		} else {
			// Set user_specified_usage_limit = usage_limit (e.g., 10000000000 = 10000000000)
			project.UserSpecifiedStorageLimit = &storageLimit
		}

		// Always set user_specified_bandwidth_limit to match bandwidth_limit when admin upgrades
		// If explicitly provided, use that value; otherwise use the same as bandwidth_limit
		if input.UserSpecifiedBandwidthLimit != nil {
			userSpecBandwidth := memory.Size(*input.UserSpecifiedBandwidthLimit)
			project.UserSpecifiedBandwidthLimit = &userSpecBandwidth
		} else {
			// Set user_specified_bandwidth_limit = bandwidth_limit (e.g., 50000000000 = 50000000000)
			project.UserSpecifiedBandwidthLimit = &bandwidthLimit
		}

		// Reset expiration tracking if requested
		if input.ResetExpiration {
			project.CreatedAt = now
			project.PrevDaysUntilExpiration = 0
		}

		// Update project in database
		err = server.db.Console().Projects().Update(ctx, &project)
		if err != nil {
			sendJSONError(w, fmt.Sprintf("failed to update project %s", project.ID.String()),
				err.Error(), http.StatusInternalServerError)
			return
		}
	}

	server.log.Info("User account upgraded successfully",
		zap.String("user_email", userEmail),
		zap.String("admin_email", adminUser.Email),
		zap.Int64("storage_limit", input.StorageLimit),
		zap.Int64("bandwidth_limit", input.BandwidthLimit),
		zap.Bool("upgraded_to_paid", input.UpgradeToPaid),
		zap.Bool("expiration_reset", input.ResetExpiration),
		zap.Int("projects_updated", len(userProjects)))

	// Build full response
	response := struct {
		Message                     string   `json:"message"`
		UserEmail                   string   `json:"userEmail"`
		StorageLimit                int64    `json:"storageLimit"`
		BandwidthLimit              int64    `json:"bandwidthLimit"`
		UserSpecifiedStorageLimit   *int64   `json:"userSpecifiedStorageLimit,omitempty"`
		UserSpecifiedBandwidthLimit *int64   `json:"userSpecifiedBandwidthLimit,omitempty"`
		UpgradedToPaid              bool     `json:"upgradedToPaid"`
		ResetExpiration             bool     `json:"resetExpiration"`
		ProjectsUpdated             int      `json:"projectsUpdated"`
		ProjectIDs                  []string `json:"projectIds"`
	}{
		Message:         "user account upgraded successfully",
		UserEmail:       userEmail,
		StorageLimit:    input.StorageLimit,
		BandwidthLimit:  input.BandwidthLimit,
		UpgradedToPaid:  input.UpgradeToPaid,
		ResetExpiration: input.ResetExpiration,
		ProjectsUpdated: len(userProjects),
		ProjectIDs:      make([]string, 0, len(userProjects)),
	}

	if input.UserSpecifiedStorageLimit != nil {
		response.UserSpecifiedStorageLimit = input.UserSpecifiedStorageLimit
	}
	if input.UserSpecifiedBandwidthLimit != nil {
		response.UserSpecifiedBandwidthLimit = input.UserSpecifiedBandwidthLimit
	}

	for _, project := range userProjects {
		response.ProjectIDs = append(response.ProjectIDs, project.ID.String())
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) disableUserMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	user.MFAEnabled = false
	user.MFASecretKey = ""
	mfaSecretKeyPtr := &user.MFASecretKey
	var mfaRecoveryCodes []string

	err = server.db.Console().Users().Update(ctx, user.ID, console.UpdateUserRequest{
		MFAEnabled:       &user.MFAEnabled,
		MFASecretKey:     &mfaSecretKeyPtr,
		MFARecoveryCodes: &mfaRecoveryCodes,
	})
	if err != nil {
		sendJSONError(w, "failed to disable mfa",
			err.Error(), http.StatusInternalServerError)
		return
	}
}

func (server *Server) billingFreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.BillingFreezeUser(ctx, u.ID)
	if err != nil {
		sendJSONError(w, "failed to billing freeze user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Send push notification for account frozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure

		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_frozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) billingUnfreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.BillingUnfreezeUser(ctx, u.ID)
	if err != nil {
		status := http.StatusInternalServerError
		if errs.Is(err, console.ErrNoFreezeStatus) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to billing unfreeze user",
			err.Error(), status)
		return
	}

	// Send push notification for account unfrozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure

		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_unfrozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) billingUnWarnUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	if err = server.freezeAccounts.BillingUnWarnUser(ctx, u.ID); err != nil {
		status := http.StatusInternalServerError
		if errs.Is(err, console.ErrNoFreezeStatus) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to billing unwarn user",
			err.Error(), status)
		return
	}

	// Send push notification for account unwarned
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure
		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_unwarned", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account unwarned",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account unwarned",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) violationFreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.ViolationFreezeUser(ctx, u.ID)
	if err != nil {
		sendJSONError(w, "failed to violation freeze user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	invoices, err := server.payments.Invoices().List(ctx, u.ID)
	if err != nil {
		server.log.Error("failed to get invoices for violation frozen user", zap.Error(err))
		return
	}

	for _, invoice := range invoices {
		if invoice.Status == payments.InvoiceStatusOpen {
			server.analytics.TrackViolationFrozenUnpaidInvoice(invoice.ID, u.ID, u.Email)
		}
	}

	// Send push notification for account frozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure

		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_frozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) violationUnfreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.ViolationUnfreezeUser(ctx, u.ID)
	if err != nil {
		status := http.StatusInternalServerError
		if errs.Is(err, console.ErrNoFreezeStatus) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to violation unfreeze user",
			err.Error(), status)
		return
	}

	// Send push notification for account unfrozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure

		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_unfrozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) legalFreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.LegalFreezeUser(ctx, u.ID)
	if err != nil {
		sendJSONError(w, "failed to legal freeze user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	invoices, err := server.payments.Invoices().List(ctx, u.ID)
	if err != nil {
		server.log.Error("failed to get invoices for legal frozen user", zap.Error(err))
		return
	}

	for _, invoice := range invoices {
		if invoice.Status == payments.InvoiceStatusOpen {
			server.analytics.TrackLegalHoldUnpaidInvoice(invoice.ID, u.ID, u.Email)
		}
	}

	// Send push notification for account frozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure

		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_frozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) legalUnfreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.LegalUnfreezeUser(ctx, u.ID)
	if err != nil {
		status := http.StatusInternalServerError
		if errs.Is(err, console.ErrNoFreezeStatus) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to legal unfreeze user",
			err.Error(), status)
		return
	}

	// Send push notification for account unfrozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure
		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_unfrozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) trialExpirationFreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.TrialExpirationFreezeUser(ctx, u.ID)
	if err != nil {
		sendJSONError(w, "failed to trial expiration freeze user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Send push notification for account frozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure

		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_frozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account frozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) trialExpirationUnfreezeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	u, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.freezeAccounts.TrialExpirationUnfreezeUser(ctx, u.ID)
	if err != nil {
		status := http.StatusInternalServerError
		if errs.Is(err, console.ErrNoFreezeStatus) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to legal unfreeze user",
			err.Error(), status)
		return
	}

	// Send push notification for account unfrozen
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure
		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_unfrozen", "account", nil); err != nil {
			server.log.Warn("Failed to send push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account unfrozen",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()
}

func (server *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Parse request body to get email and password
	var requestData struct {
		Email string `json:"email"`
		// Password string `json:"password"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.Unmarshal(body, &requestData)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if requestData.Email == "" {
		sendJSONError(w, "email is required",
			"", http.StatusBadRequest)
		return
	}

	// Call delete account function with the provided email
	verified, unverified, err := server.db.Console().Users().GetByEmailWithUnverified(ctx, requestData.Email)
	if err != nil {
		sendJSONError(w, "failed to get user by email",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var user *console.User
	if verified != nil {
		user = verified
	} else if len(unverified) > 0 {
		user = &unverified[0]
	} else {
		sendJSONError(w, "user not found with email",
			"", http.StatusNotFound)
		return
	}

	projects, err := server.db.Console().Projects().GetByUserID(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user projects",
			err.Error(), http.StatusInternalServerError)
		return
	}

	if len(projects) > 0 {
		for _, project := range projects {
			if err := server.buckets.DeleteAllBucketsByProjectID(ctx, project.ID); err != nil {
				sendJSONError(w, "failed to delete buckets",
					err.Error(), http.StatusInternalServerError)
				return
			}

			if err := server.db.Console().APIKeys().DeleteByProjectID(ctx, project.ID); err != nil {
				sendJSONError(w, "failed to delete API keys",
					err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if err := server.db.Console().Projects().DeleteByUserID(ctx, user.ID); err != nil {
			sendJSONError(w, "failed to delete project",
				err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := server.db.Console().Users().Delete(ctx, user.ID); err != nil {
		sendJSONError(w, "failed to delete user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Account deleted successfully",
	})
}

func (server *Server) createGeofenceForAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Region string `json:"region"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	if input.Region == "" {
		sendJSONError(w, "region was not provided",
			"", http.StatusBadRequest)
		return
	}

	placement, err := parsePlacementConstraint(input.Region)
	if err != nil {
		sendJSONError(w, err.Error(), "available: EU, EEA, US, DE, NR", http.StatusBadRequest)
		return
	}

	server.setGeofenceForUser(w, r, placement)
}

func (server *Server) disableBotRestriction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	if user.Status != console.PendingBotVerification {
		sendJSONError(w, fmt.Sprintf("user with email %q must have PendingBotVerification status to disable bot restriction", userEmail),
			"", http.StatusBadRequest)
		return
	}

	err = server.freezeAccounts.BotUnfreezeUser(ctx, user.ID)
	if err != nil {
		status := http.StatusInternalServerError
		if errs.Is(err, console.ErrNoFreezeStatus) {
			status = http.StatusConflict
		}
		sendJSONError(w, "failed to unfreeze bot user", err.Error(), status)
	}
}

func (server *Server) deleteGeofenceForAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	server.setGeofenceForUser(w, r, storj.DefaultPlacement)
}

func (server *Server) setGeofenceForUser(w http.ResponseWriter, r *http.Request, placement storj.PlacementConstraint) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user details",
			err.Error(), http.StatusInternalServerError)
		return
	}

	if user.DefaultPlacement == placement {
		sendJSONError(w, "new placement is equal to user's current placement",
			"", http.StatusBadRequest)
		return
	}

	if err = server.db.Console().Users().UpdateDefaultPlacement(ctx, user.ID, placement); err != nil {
		sendJSONError(w, "unable to set geofence for user",
			err.Error(), http.StatusInternalServerError)
		return
	}
}

func (server *Server) updateFreeTrialExpiration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		TrialExpiration *time.Time `json:"trialExpiration"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	expirationPtr := input.TrialExpiration
	err = server.db.Console().Users().Update(ctx, user.ID, console.UpdateUserRequest{TrialExpiration: &expirationPtr})
	if err != nil {
		sendJSONError(w, "failed to update user",
			err.Error(), http.StatusInternalServerError)
		return
	}
}

// User struct for response (matching dashboard requirements)
type User struct {
	ID                    uuid.UUID  `json:"id"`
	FullName              string     `json:"fullName"`
	Email                 string     `json:"email"`
	Status                int        `json:"status"`
	CreatedAt             time.Time  `json:"createdAt"`
	PaidTier              bool       `json:"paidTier"`
	ProjectStorageLimit   int64      `json:"projectStorageLimit"`
	ProjectBandwidthLimit int64      `json:"projectBandwidthLimit"`
	Source                string     `json:"source"`
	UtmSource             string     `json:"utmSource"`
	UtmMedium             string     `json:"utmMedium"`
	UtmCampaign           string     `json:"utmCampaign"`
	UtmTerm               string     `json:"utmTerm"`
	UtmContent            string     `json:"utmContent"`
	LastSessionExpiry     *time.Time `json:"lastSessionExpiry"`
	FirstSessionExpiry    *time.Time `json:"firstSessionExpiry"`
	TotalSessionCount     int        `json:"totalSessionCount"`

	ProjectCount int    `json:"projectCount"`
	Action       string `json:"action"` // "Activate" or "Deactivate" based on status
}

// UserListFilters holds all filter parameters for user listing
type UserListFilters struct {
	// Pagination
	Limit    uint64
	Page     uint64
	FetchAll bool

	// Sorting
	SortColumn string // Column name to sort by
	SortOrder  string // "asc" or "desc"

	// Basic filters
	Search       string
	StatusFilter *int
	PaidTier     *bool
	SourceFilter string

	// Date range filters
	CreatedAfter  *time.Time
	CreatedBefore *time.Time

	// Session filters
	HasActiveSession  *bool
	LastSessionAfter  *time.Time
	LastSessionBefore *time.Time
	SessionCountMin   *int
	SessionCountMax   *int
}

// parseUserListFilters parses and validates all query parameters for user listing
func parseUserListFilters(r *http.Request) (*UserListFilters, error) {
	query := r.URL.Query()
	filters := &UserListFilters{}

	// Parse pagination
	limitParam := query.Get("limit")
	if limitParam == "" {
		limitParam = "50" // Default limit
	}

	if limitParam == "-1" || limitParam == "0" {
		filters.FetchAll = true
	} else {
		var err error
		filters.Limit, err = strconv.ParseUint(limitParam, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parameter 'limit' must be a valid number: %w", err)
		}
	}

	pageParam := query.Get("page")
	if pageParam == "" {
		pageParam = "1"
	}
	var err error
	filters.Page, err = strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parameter 'page' must be a valid number: %w", err)
	}

	// Parse basic filters
	filters.Search = query.Get("search")
	filters.SourceFilter = query.Get("source")

	// Parse status filter
	statusFilter := parseStatusParam(query.Get("status"))
	if statusFilter == nil && query.Get("status") != "" {
		return nil, fmt.Errorf("parameter 'status' must be a valid number")
	}
	if statusFilter != nil {
		statusInt := int(*statusFilter)
		filters.StatusFilter = &statusInt
	}

	// Parse tier filter
	tierFilter := query.Get("tier")
	if tierFilter == "paid" {
		paidTier := true
		filters.PaidTier = &paidTier
	} else if tierFilter == "free" {
		paidTier := false
		filters.PaidTier = &paidTier
	}

	// Parse date range filters
	createdAfter, createdBefore, err := parseDateRange(
		query.Get("created_range"),
		query.Get("created_after"),
		query.Get("created_before"),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid date range: %w", err)
	}
	filters.CreatedAfter = createdAfter
	filters.CreatedBefore = createdBefore

	// Parse session filters
	hasActiveSessionFilter := query.Get("has_active_session")
	if hasActiveSessionFilter == "true" {
		val := true
		filters.HasActiveSession = &val
	} else if hasActiveSessionFilter == "false" {
		val := false
		filters.HasActiveSession = &val
	}

	// Parse session date range
	lastSessionAfter, lastSessionBefore, err := parseSessionDateRange(
		query.Get("last_session_after"),
		query.Get("last_session_before"),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid session date range: %w", err)
	}
	filters.LastSessionAfter = lastSessionAfter
	filters.LastSessionBefore = lastSessionBefore

	// Parse session count filters
	if sessionCountMinParam := query.Get("session_count_min"); sessionCountMinParam != "" {
		sessionCountMin, err := strconv.Atoi(sessionCountMinParam)
		if err != nil {
			return nil, fmt.Errorf("parameter 'session_count_min' must be a valid number: %w", err)
		}
		filters.SessionCountMin = &sessionCountMin
	}

	if sessionCountMaxParam := query.Get("session_count_max"); sessionCountMaxParam != "" {
		sessionCountMax, err := strconv.Atoi(sessionCountMaxParam)
		if err != nil {
			return nil, fmt.Errorf("parameter 'session_count_max' must be a valid number: %w", err)
		}
		filters.SessionCountMax = &sessionCountMax
	}

	// Parse sorting parameters
	filters.SortColumn = query.Get("sort_column")
	filters.SortOrder = query.Get("sort_order")

	// Validate and normalize sort order
	if filters.SortOrder != "" {
		filters.SortOrder = strings.ToLower(filters.SortOrder)
		if filters.SortOrder != "asc" && filters.SortOrder != "desc" {
			return nil, fmt.Errorf("parameter 'sort_order' must be 'asc' or 'desc'")
		}
	} else {
		// Default to descending if column is specified but order is not
		if filters.SortColumn != "" {
			filters.SortOrder = "desc"
		}
	}

	return filters, nil
}

// parseSessionDateRange parses session date range parameters
func parseSessionDateRange(afterParam, beforeParam string) (*time.Time, *time.Time, error) {
	var lastSessionAfter, lastSessionBefore *time.Time

	if afterParam != "" {
		parsedTime, err := time.Parse("2006-01-02", afterParam)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid 'last_session_after' date format: %w", err)
		}
		lastSessionAfter = &parsedTime
	}

	if beforeParam != "" {
		parsedTime, err := time.Parse("2006-01-02", beforeParam)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid 'last_session_before' date format: %w", err)
		}
		// Set to end of day for inclusive filtering
		endOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 23, 59, 59, 999999999, parsedTime.Location())
		lastSessionBefore = &endOfDay
	}

	return lastSessionAfter, lastSessionBefore, nil
}

func (server *Server) getAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Check if this is an export request first
	queryParams := r.URL.Query()
	format := queryParams.Get("format")
	isExport := format == "csv" || format == "json"

	// Parse all filters from query parameters
	filters, err := parseUserListFilters(r)
	if err != nil {
		sendJSONError(w, "Bad request", err.Error(), http.StatusBadRequest)
		return
	}

	// For export requests, ignore pagination and fetch all matching records
	if isExport {
		filters.FetchAll = true
		filters.Limit = 0
		filters.Page = 1
	}

	// Calculate pagination parameters
	var actualLimit, actualOffset int
	if filters.FetchAll {
		// For "All", pass 0 as limit to skip LIMIT clause in SQL query
		// This allows fetching all records without hardcoded limits
		actualLimit = 0
		actualOffset = 0
	} else {
		actualLimit = int(filters.Limit)
		actualOffset = int((filters.Page - 1) * filters.Limit)
	}

	// Single optimized query with all filters and pagination applied in SQL
	allUsers, lastSessionExpiry, firstSessionExpiry, totalSessionCounts, projectCounts, totalCount, err := server.db.Console().Users().GetAllUsersOptimized(
		ctx,
		actualLimit,
		actualOffset,
		filters.StatusFilter,
		filters.CreatedAfter,
		filters.CreatedBefore,
		filters.Search,
		filters.PaidTier,
		filters.SourceFilter,
		filters.HasActiveSession,
		filters.LastSessionAfter,
		filters.LastSessionBefore,
		filters.SessionCountMin,
		filters.SessionCountMax,
		filters.SortColumn,
		filters.SortOrder,
	)
	if err != nil {
		sendJSONError(w, "failed to get users",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format
	// Calculate storage only for returned users (optimized) - COMMENTED OUT
	users := make([]User, 0, len(allUsers))
	for i, user := range allUsers {
		user.PasswordHash = nil

		// Get session data from query results (already fetched in SQL)
		var lastExp, firstExp *time.Time
		var sessionCount, projectCount int
		if i < len(lastSessionExpiry) {
			lastExp = lastSessionExpiry[i]
		}
		if i < len(firstSessionExpiry) {
			firstExp = firstSessionExpiry[i]
		}
		if i < len(totalSessionCounts) {
			sessionCount = totalSessionCounts[i]
		}
		if i < len(projectCounts) {
			projectCount = projectCounts[i]
		}

		// Determine action based on status: Inactive (0) = "Activate", Active (1) = "Deactivate"
		action := "Deactivate"
		if user.Status == console.Inactive {
			action = "Activate"
		}

		users = append(users, User{
			ID:                    user.ID,
			FullName:              user.FullName,
			Email:                 user.Email,
			Status:                int(user.Status),
			CreatedAt:             user.CreatedAt,
			PaidTier:              user.PaidTier,
			ProjectStorageLimit:   user.ProjectStorageLimit,
			ProjectBandwidthLimit: user.ProjectBandwidthLimit,
			Source:                user.Source,
			UtmSource:             user.UtmSource,
			UtmMedium:             user.UtmMedium,
			UtmCampaign:           user.UtmCampaign,
			UtmTerm:               user.UtmTerm,
			UtmContent:            user.UtmContent,
			LastSessionExpiry:     lastExp,
			FirstSessionExpiry:    firstExp,
			TotalSessionCount:     sessionCount,

			ProjectCount: projectCount,
			Action:       action,
		})
	}

	// For export requests, export all matching users and return early
	if isExport {
		server.exportUsersData(w, users, filters.Search, queryParams.Get("status"), format)
		return
	}

	// Calculate pagination metadata (only for regular listing, not export)
	var paginatedUsers []User
	var totalPages uint64
	var finalTotalCount uint64

	// No storage filtering, use the SQL count
	finalTotalCount = uint64(totalCount)

	if filters.FetchAll {
		// For "All", return all users
		paginatedUsers = users
		totalPages = 1
	} else {
		// Users are already paginated from SQL query
		paginatedUsers = users
		if filters.Limit > 0 {
			totalPages = (finalTotalCount + filters.Limit - 1) / filters.Limit
		} else {
			totalPages = 1
		}
	}

	// Regular JSON response for UI
	response := struct {
		Users       []User `json:"users"`
		PageCount   uint   `json:"pageCount"`
		CurrentPage uint   `json:"currentPage"`
		TotalCount  uint64 `json:"totalCount"`
		HasMore     bool   `json:"hasMore"`
		Limit       uint   `json:"limit"`
		Offset      uint64 `json:"offset"`
		dummy       string `json:"dummy"`
	}{
		Users:       paginatedUsers,
		PageCount:   uint(totalPages),
		CurrentPage: uint(filters.Page),
		TotalCount:  finalTotalCount,
		HasMore:     !filters.FetchAll && filters.Page < totalPages,
		Limit:       uint(actualLimit),
		Offset:      uint64(actualOffset),
		dummy:       "dummy",
	}

	// Stream JSON response directly
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// formatTime formats a time pointer for CSV export
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// exportUsersData exports user data in CSV or JSON format
func (server *Server) exportUsersData(w http.ResponseWriter, users []User, search, status, format string) {
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=users_export.csv")

		// Write CSV header
		csvWriter := csv.NewWriter(w)
		defer csvWriter.Flush()

		// Write header row
		headers := []string{
			"ID", "Full Name", "Email", "Status", "Created At", "Paid Tier",
			"Project Storage Limit", "Project Bandwidth Limit",
			// "Storage Used",
			// "Bandwidth Used", "Segment Used",
			"Project Count", "Source",
			"UTM Source", "UTM Medium", "UTM Campaign", "UTM Term", "UTM Content",
			"Last Session Expiry", "First Session Expiry", "Total Sessions",
		}
		csvWriter.Write(headers)

		// Write data rows
		for _, user := range users {
			row := []string{
				user.ID.String(),
				user.FullName,
				user.Email,
				fmt.Sprintf("%d", user.Status),
				user.CreatedAt.Format("2006-01-02 15:04:05"),
				fmt.Sprintf("%t", user.PaidTier),
				fmt.Sprintf("%d", user.ProjectStorageLimit),
				fmt.Sprintf("%d", user.ProjectBandwidthLimit),

				fmt.Sprintf("%d", user.ProjectCount),
				user.Source,
				user.UtmSource,
				user.UtmMedium,
				user.UtmCampaign,
				user.UtmTerm,
				user.UtmContent,
				formatTime(user.LastSessionExpiry),
				formatTime(user.FirstSessionExpiry),
				fmt.Sprintf("%d", user.TotalSessionCount),
			}
			csvWriter.Write(row)
		}
	} else {
		// JSON format
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=users_export.json")

		response := struct {
			TotalUsers int               `json:"totalUsers"`
			Filters    map[string]string `json:"filters"`
			Users      []User            `json:"users"`
		}{
			TotalUsers: len(users),
			Filters: map[string]string{
				"search": search,
				"status": status,
			},
			Users: users,
		}

		json.NewEncoder(w).Encode(response)
	}
}

// parseStatusParam parses status parameter and returns UserStatus or nil
func parseStatusParam(param string) *console.UserStatus {
	if param == "" {
		return nil
	}
	statusInt, err := strconv.Atoi(param)
	if err != nil {
		return nil
	}
	status := console.UserStatus(statusInt)
	return &status
}

// getProjectUsageData gets storage, bandwidth, and segment usage for a project
func (server *Server) getProjectUsageData(ctx context.Context, projectID uuid.UUID) (storageUsed, bandwidthUsed, segmentUsed int64) {
	// Get storage usage from live accounting
	storageUsed, err := server.liveAccounting.GetProjectStorageUsage(ctx, projectID)
	if err != nil {
		server.log.Warn("Failed to get project storage usage",
			zap.String("project_id", projectID.String()),
			zap.Error(err))
		storageUsed = 0
	}

	// Get bandwidth usage - try cache first, then database fallback
	bandwidthUsed, err = server.liveAccounting.GetProjectBandwidthUsage(ctx, projectID, time.Now())
	if err != nil {
		// Fallback to database if cache fails
		bandwidthUsed, err = server.db.ProjectAccounting().GetProjectBandwidth(ctx, projectID, time.Now().Year(), time.Now().Month(), time.Now().Day(), 0)
		if err != nil {
			server.log.Warn("Failed to get project bandwidth usage",
				zap.String("project_id", projectID.String()),
				zap.Error(err))
			bandwidthUsed = 0
		}
	}

	// Get segment usage from live accounting
	segmentUsed, err = server.liveAccounting.GetProjectSegmentUsage(ctx, projectID)
	if err != nil {
		server.log.Warn("Failed to get project segment usage",
			zap.String("project_id", projectID.String()),
			zap.Error(err))
		segmentUsed = 0
	}

	return storageUsed, bandwidthUsed, segmentUsed
}

func (server *Server) getUserLoginHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing", "", http.StatusBadRequest)
		return
	}

	// Use GetByEmailWithUnverified to get users regardless of status (including inactive)
	// This allows admin to access inactive users, but we'll still block deleted users
	verified, unverified, err := server.db.Console().Users().GetByEmailWithUnverified(ctx, userEmail)
	if err != nil {
		sendJSONError(w, "failed to get user", err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the user - could be in verified (active) or unverified (inactive, etc.)
	var user *console.User
	if verified != nil {
		user = verified
	} else if len(unverified) > 0 {
		// Use the first unverified user (should only be one per email)
		user = &unverified[0]
	} else {
		sendJSONError(w, "user not found", "", http.StatusNotFound)
		return
	}

	// Prevent access to deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot access deleted user",
			"user has been deleted and cannot be accessed", http.StatusForbidden)
		return
	}

	// Get all webapp sessions for this user
	sessions, err := server.db.Console().WebappSessions().GetAllByUserID(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user login history", err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert sessions to response format
	type LoginHistoryEntry struct {
		ID        string    `json:"id"`
		IPAddress string    `json:"ipAddress"`
		UserAgent string    `json:"userAgent"`
		Status    int       `json:"status"`
		LoginTime time.Time `json:"loginTime"`
		ExpiresAt time.Time `json:"expiresAt"`
		IsActive  bool      `json:"isActive"`
	}

	entries := make([]LoginHistoryEntry, 0, len(sessions))
	now := time.Now()

	for _, session := range sessions {
		entries = append(entries, LoginHistoryEntry{
			ID:        session.ID.String(),
			IPAddress: session.Address,
			UserAgent: session.UserAgent,
			Status:    session.Status,
			LoginTime: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			IsActive:  session.ExpiresAt.After(now),
		})
	}

	// Sort by login time (most recent first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LoginTime.After(entries[j].LoginTime)
	})

	// Create response
	response := struct {
		UserEmail string              `json:"userEmail"`
		Total     int                 `json:"total"`
		Sessions  []LoginHistoryEntry `json:"sessions"`
	}{
		UserEmail: userEmail,
		Total:     len(entries),
		Sessions:  entries,
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) deactivateUserAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
			"", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Prevent modifications on deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot deactivate deleted user",
			"user has been deleted and cannot be modified", http.StatusForbidden)
		return
	}

	// Deactivate account by setting status to Inactive (0)
	userStatus := console.Inactive
	updateRequest := console.UpdateUserRequest{
		Status: &userStatus,
	}

	err = server.db.Console().Users().Update(ctx, user.ID, updateRequest)
	if err != nil {
		sendJSONError(w, "failed to deactivate user account",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete all sessions for the user to log them out
	_, err = server.db.Console().WebappSessions().DeleteAllByUserID(ctx, user.ID)
	if err != nil {
		// Log the error but don't fail the deactivation
		server.log.Warn("Failed to delete user sessions during account deactivation",
			zap.Stringer("user_id", user.ID),
			zap.String("email", user.Email),
			zap.Error(err))
	}

	// Send push notification for account deactivated
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID   // Capture user ID before closure
		notifyEmail := user.Email // Capture email before closure
		variables := map[string]interface{}{
			"email": notifyEmail,
		}
		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_deactivated", "account", variables); err != nil {
			server.log.Warn("Failed to send push notification for account deactivated",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account deactivated",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	// Send email notification for account deactivated
	if server.mailService != nil {
		go func() {
			// Use background context to avoid cancellation when HTTP request completes
			emailCtx := context.Background()
			emailUserID := user.ID       // Capture user ID before closure
			emailUserEmail := user.Email // Capture email before closure
			emailUserName := user.ShortName
			if emailUserName == "" {
				emailUserName = user.FullName
			}

			origin := server.console.ExternalAddress
			if origin == "" {
				origin = "https://storx.io/"
			}
			if !strings.HasSuffix(origin, "/") {
				origin += "/"
			}

			contactInfoURL := server.console.ContactInfoURL
			if contactInfoURL == "" {
				contactInfoURL = "https://forum.storx.io"
			}
			termsAndConditionsURL := server.console.TermsAndConditionsURL
			if termsAndConditionsURL == "" {
				termsAndConditionsURL = "https://www.storj.io/terms-of-service/"
			}
			supportURL := server.console.GeneralRequestURL
			if supportURL == "" {
				supportURL = "https://supportdcs.storj.io/hc/en-us/requests/new?ticket_form_id=360000379291"
			}

			server.mailService.SendRenderedAsync(
				emailCtx,
				[]post.Address{{Address: emailUserEmail, Name: emailUserName}},
				&console.AccountDeactivatedEmail{
					Username:              emailUserName,
					Origin:                origin,
					ContactInfoURL:        contactInfoURL,
					TermsAndConditionsURL: termsAndConditionsURL,
					SupportURL:            supportURL,
				},
			)
			server.log.Debug("Sent account deactivated email",
				zap.Stringer("user_id", emailUserID),
				zap.String("email", emailUserEmail))
		}()
	}

	// Return updated user info
	updatedUser, err := server.db.Console().Users().Get(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get updated user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(updatedUser)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) activateUserAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	userEmail, ok := vars["useremail"]
	if !ok {
		sendJSONError(w, "user-email missing",
			"", http.StatusBadRequest)
		return
	}

	// Use GetByEmailWithUnverified to also get inactive users
	user, unverified, err := server.db.Console().Users().GetByEmailWithUnverified(ctx, userEmail)
	if err != nil {
		sendJSONError(w, "failed to get user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// If user is nil, check unverified users (which includes inactive users)
	if user == nil {
		if len(unverified) > 0 {
			user = &unverified[0]
		} else {
			sendJSONError(w, fmt.Sprintf("user with email %q does not exist", userEmail),
				"", http.StatusNotFound)
			return
		}
	}

	// Prevent modifications on deleted users
	if user.Status == console.Deleted {
		sendJSONError(w, "cannot activate deleted user",
			"user has been deleted and cannot be modified", http.StatusForbidden)
		return
	}

	// Activate account by setting status to Active (1)
	userStatus := console.Active
	updateRequest := console.UpdateUserRequest{
		Status: &userStatus,
	}

	err = server.db.Console().Users().Update(ctx, user.ID, updateRequest)
	if err != nil {
		sendJSONError(w, "failed to activate user account",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Send push notification for account activated
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID   // Capture user ID before closure
		notifyEmail := user.Email // Capture email before closure
		variables := map[string]interface{}{
			"email": notifyEmail,
		}
		if err := server.sendPushNotificationByEventName(notifyCtx, notifyUserID, "account_activated", "account", variables); err != nil {
			server.log.Warn("Failed to send push notification for account activated",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			server.log.Debug("Successfully sent push notification for account activated",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	// Send email notification for account activated
	if server.mailService != nil {
		go func() {
			// Use background context to avoid cancellation when HTTP request completes
			emailCtx := context.Background()
			emailUserID := user.ID       // Capture user ID before closure
			emailUserEmail := user.Email // Capture email before closure
			emailUserName := user.ShortName
			if emailUserName == "" {
				emailUserName = user.FullName
			}

			origin := server.console.ExternalAddress
			if origin == "" {
				origin = "https://storx.io/"
			}
			if !strings.HasSuffix(origin, "/") {
				origin += "/"
			}

			signInLink := origin + "login"
			contactInfoURL := server.console.ContactInfoURL
			if contactInfoURL == "" {
				contactInfoURL = "https://forum.storx.io"
			}
			termsAndConditionsURL := server.console.TermsAndConditionsURL
			if termsAndConditionsURL == "" {
				termsAndConditionsURL = "https://www.storj.io/terms-of-service/"
			}

			server.mailService.SendRenderedAsync(
				emailCtx,
				[]post.Address{{Address: emailUserEmail, Name: emailUserName}},
				&console.AccountActivatedEmail{
					Username:              emailUserName,
					Origin:                origin,
					SignInLink:            signInLink,
					ContactInfoURL:        contactInfoURL,
					TermsAndConditionsURL: termsAndConditionsURL,
				},
			)
			server.log.Debug("Sent account activated email",
				zap.Stringer("user_id", emailUserID),
				zap.String("email", emailUserEmail))
		}()
	}

	// Return updated user info
	updatedUser, err := server.db.Console().Users().Get(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get updated user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(updatedUser)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// getUserStats returns aggregated statistics about all users
// This endpoint uses database aggregations for efficient counting
func (server *Server) getUserStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Use SQL aggregations to count users efficiently
	// This is much faster than fetching all users and counting in memory
	stats := struct {
		TotalAccounts          uint64 `json:"totalAccounts"`
		Active                 uint64 `json:"active"`
		Inactive               uint64 `json:"inactive"`
		Deleted                uint64 `json:"deleted"`
		PendingDeletion        uint64 `json:"pendingDeletion"`
		LegalHold              uint64 `json:"legalHold"`
		PendingBotVerification uint64 `json:"pendingBotVerification"`
		Pro                    uint64 `json:"pro"`
		Free                   uint64 `json:"free"`
	}{}

	total, active, inactive, deleted, pendingDeletion, legalHold, pendingBotVerification, pro, free, err := server.db.Console().Users().GetUserStats(ctx)
	if err != nil {
		sendJSONError(w, "failed to get users for statistics",
			err.Error(), http.StatusInternalServerError)
		return
	}

	stats = struct {
		TotalAccounts          uint64 `json:"totalAccounts"`
		Active                 uint64 `json:"active"`
		Inactive               uint64 `json:"inactive"`
		Deleted                uint64 `json:"deleted"`
		PendingDeletion        uint64 `json:"pendingDeletion"`
		LegalHold              uint64 `json:"legalHold"`
		PendingBotVerification uint64 `json:"pendingBotVerification"`
		Pro                    uint64 `json:"pro"`
		Free                   uint64 `json:"free"`
	}{
		TotalAccounts:          uint64(total),
		Active:                 uint64(active),
		Inactive:               uint64(inactive),
		Deleted:                uint64(deleted),
		PendingDeletion:        uint64(pendingDeletion),
		LegalHold:              uint64(legalHold),
		PendingBotVerification: uint64(pendingBotVerification),
		Pro:                    uint64(pro),
		Free:                   uint64(free),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
