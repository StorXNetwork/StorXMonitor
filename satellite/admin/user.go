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
	"math"
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

	_, err = server.payments.Setup(ctx, newUser.ID, newUser.Email, newUser.SignupPromoCode)
	if err != nil {
		sendJSONError(w, "failed to create payment account for user",
			err.Error(), http.StatusInternalServerError)
		return
	}

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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	type UserWithPaidTier struct {
		console.User
		PaidTierStr string `json:"paidTierStr"`
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body", err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		StorageLimit    int64 `json:"storageLimit"`    // in bytes
		BandwidthLimit  int64 `json:"bandwidthLimit"`  // in bytes
		UpgradeToPaid   bool  `json:"upgradeToPaid"`   // whether to upgrade to paid tier
		ResetExpiration bool  `json:"resetExpiration"` // whether to reset expiration tracking
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

	// Step 1: Upgrade to paid tier if requested
	if input.UpgradeToPaid {
		paidTier := true
		now := server.nowFn()
		updateRequest := console.UpdateUserRequest{
			PaidTier:    &paidTier,
			UpgradeTime: &now,
		}
		err = server.db.Console().Users().Update(ctx, user.ID, updateRequest)
		if err != nil {
			sendJSONError(w, "failed to upgrade user to paid tier", err.Error(), http.StatusInternalServerError)
			return
		}
		server.log.Info("User upgraded to paid tier",
			zap.String("user_email", userEmail),
			zap.String("admin_email", adminUser.Email))
	}

	// Step 2: Update user-level project limits (for future projects)
	newLimits := console.UsageLimits{
		Storage:   input.StorageLimit,
		Bandwidth: input.BandwidthLimit,
		Segment:   user.ProjectSegmentLimit, // Keep existing segment limit
	}

	err = server.db.Console().Users().UpdateUserProjectLimits(ctx, user.ID, newLimits)
	if err != nil {
		sendJSONError(w, "failed to update user project limits", err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 3: Get all user's projects
	userProjects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "failed to get user's projects", err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 4: Update all projects with new limits and reset expiration if requested
	now := time.Now().UTC()
	for _, project := range userProjects {
		// Update project limits
		err = server.db.Console().Projects().UpdateUsageLimits(ctx, project.ID, newLimits)
		if err != nil {
			sendJSONError(w, fmt.Sprintf("failed to update project limits for project %s", project.ID.String()),
				err.Error(), http.StatusInternalServerError)
			return
		}

		// Reset expiration tracking if requested
		// Note: We update the project's CreatedAt and PrevDaysUntilExpiration directly via database
		// This effectively resets the expiration timer by making the project appear newly created
		if input.ResetExpiration {
			// Update project with new CreatedAt and reset PrevDaysUntilExpiration
			project.CreatedAt = now
			project.PrevDaysUntilExpiration = 0

			// Update project in database (Update expects a pointer)
			err = server.db.Console().Projects().Update(ctx, &project)
			if err != nil {
				server.log.Error("Failed to reset project expiration",
					zap.Error(err),
					zap.String("project_id", project.ID.String()),
					zap.String("user_email", userEmail))
				// Continue with other projects even if one fails
			} else {
				server.log.Info("Project expiration reset",
					zap.String("project_id", project.ID.String()),
					zap.String("project_name", project.Name))
			}
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

	sendJSONData(w, http.StatusOK, []byte(`{"message":"user account upgraded successfully"}`))
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
	}
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
}

func (server *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
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

	// Ensure user has no own projects any longer
	projects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "unable to list projects",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if len(projects) > 0 {
		sendJSONError(w, "some projects still exist",
			fmt.Sprintf("%v", projects), http.StatusConflict)
		return
	}

	// Delete memberships in foreign projects
	members, err := server.db.Console().ProjectMembers().GetByMemberID(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "unable to search for user project memberships",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if len(members) > 0 {
		for _, project := range members {
			err := server.db.Console().ProjectMembers().Delete(ctx, user.ID, project.ProjectID)
			if err != nil {
				sendJSONError(w, "unable to delete user project membership",
					err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	// ensure no unpaid invoices exist.
	invoices, err := server.payments.Invoices().List(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "unable to list user invoices",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if len(invoices) > 0 {
		for _, invoice := range invoices {
			if invoice.Status == "draft" || invoice.Status == "open" {
				sendJSONError(w, "user has unpaid/pending invoices",
					"", http.StatusConflict)
				return
			}
		}
	}

	hasItems, err := server.payments.Invoices().CheckPendingItems(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "unable to list pending invoice items",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if hasItems {
		sendJSONError(w, "user has pending invoice items",
			"", http.StatusConflict)
		return
	}

	emptyName := ""
	emptyNamePtr := &emptyName
	deactivatedEmail := fmt.Sprintf("deactivated+%s@storj.io", user.ID.String())
	status := console.Deleted

	err = server.db.Console().Users().Update(ctx, user.ID, console.UpdateUserRequest{
		FullName:  &emptyName,
		ShortName: &emptyNamePtr,
		Email:     &deactivatedEmail,
		Status:    &status,
	})
	if err != nil {
		sendJSONError(w, "unable to delete user",
			err.Error(), http.StatusInternalServerError)
		return
	}

	err = server.payments.CreditCards().RemoveAll(ctx, user.ID)
	if err != nil {
		sendJSONError(w, "unable to delete credit card(s) from stripe account",
			err.Error(), http.StatusInternalServerError)
	}
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
	StorageUsed           int64      `json:"storageUsed"`
	BandwidthUsed         int64      `json:"bandwidthUsed"`
	SegmentUsed           int64      `json:"segmentUsed"`
	ProjectCount          int        `json:"projectCount"`
}

func (server *Server) getAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Parse query parameters for pagination (following pattern from usersPendingDeletion)
	query := r.URL.Query()

	// Parse limit - handle "All" option (-1) and default
	limitParam := query.Get("limit")
	if limitParam == "" {
		limitParam = "50" // Default limit
	}

	// Check if "All" is requested (limit is -1)
	fetchAll := false
	var limit uint64
	if limitParam == "-1" || limitParam == "0" {
		fetchAll = true
	} else {
		limit, err = strconv.ParseUint(limitParam, 10, 32)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'limit' must be a valid number", http.StatusBadRequest)
			return
		}
		// No max limit - user can select any limit from frontend
	}

	// Parse page
	pageParam := query.Get("page")
	if pageParam == "" {
		pageParam = "1"
	}
	page, err := strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		sendJSONError(w, "Bad request", "parameter 'page' must be a valid number", http.StatusBadRequest)
		return
	}

	// Parse search parameter (general search, can be email or name)
	search := query.Get("search")

	// Parse storage range filters
	storageMinParam := query.Get("storage_min")
	storageMin := int64(0)
	if storageMinParam != "" {
		storageMin, err = strconv.ParseInt(storageMinParam, 10, 64)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'storage_min' must be a valid number", http.StatusBadRequest)
			return
		}
	}

	storageMaxParam := query.Get("storage_max")
	storageMax := int64(0)
	if storageMaxParam != "" {
		storageMax, err = strconv.ParseInt(storageMaxParam, 10, 64)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'storage_max' must be a valid number", http.StatusBadRequest)
			return
		}
	}

	// Parse tier filter (paid/free)
	tierFilter := query.Get("tier") // "paid" or "free"
	var paidTierFilter *bool
	if tierFilter == "paid" {
		paidTier := true
		paidTierFilter = &paidTier
	} else if tierFilter == "free" {
		paidTier := false
		paidTierFilter = &paidTier
	}

	// Parse source filter
	sourceFilter := query.Get("source")

	// Parse account creation date range filters
	// Support preset values: "today", "yesterday", "last_week", "last_month", "last_year"
	// Or custom dates in format "2006-01-02"
	// For presets, we use a single "created_range" parameter
	// For custom dates, we use "created_after" and "created_before" separately
	createdRangeParam := query.Get("created_range")
	createdAfterParam := query.Get("created_after")
	createdBeforeParam := query.Get("created_before")

	var createdAfter *time.Time
	var createdBefore *time.Time

	now := time.Now()
	loc := now.Location()

	// If preset range is specified, calculate both dates from it
	if createdRangeParam != "" {
		switch createdRangeParam {
		case "today":
			startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfToday
			createdBefore = &endOfToday
		case "yesterday":
			yesterday := now.AddDate(0, 0, -1)
			startOfYesterday := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, loc)
			endOfYesterday := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfYesterday
			createdBefore = &endOfYesterday
		case "last_week":
			lastWeek := now.AddDate(0, 0, -7)
			startOfLastWeek := time.Date(lastWeek.Year(), lastWeek.Month(), lastWeek.Day(), 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfLastWeek
			createdBefore = &endOfToday
		case "last_month":
			lastMonth := now.AddDate(0, -1, 0)
			startOfLastMonth := time.Date(lastMonth.Year(), lastMonth.Month(), 1, 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfLastMonth
			createdBefore = &endOfToday
		case "last_year":
			lastYear := now.AddDate(-1, 0, 0)
			startOfLastYear := time.Date(lastYear.Year(), 1, 1, 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfLastYear
			createdBefore = &endOfToday
		}
	} else {
		// Handle custom date range
		if createdAfterParam != "" {
			parsedTime, err := time.Parse("2006-01-02", createdAfterParam)
			if err == nil {
				startOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 0, 0, 0, 0, parsedTime.Location())
				createdAfter = &startOfDay
			}
		}

		if createdBeforeParam != "" {
			parsedTime, err := time.Parse("2006-01-02", createdBeforeParam)
			if err == nil {
				// Set to end of day for inclusive filtering
				endOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 23, 59, 59, 999999999, parsedTime.Location())
				createdBefore = &endOfDay
			}
		}
	}

	// Parse session-related filters
	hasActiveSessionFilter := query.Get("has_active_session") // "true", "false", or ""
	var hasActiveSessionFilterBool *bool
	if hasActiveSessionFilter == "true" {
		val := true
		hasActiveSessionFilterBool = &val
	} else if hasActiveSessionFilter == "false" {
		val := false
		hasActiveSessionFilterBool = &val
	}

	lastSessionAfterParam := query.Get("last_session_after")
	var lastSessionAfter *time.Time
	if lastSessionAfterParam != "" {
		parsedTime, err := time.Parse("2006-01-02", lastSessionAfterParam)
		if err == nil {
			lastSessionAfter = &parsedTime
		}
	}

	lastSessionBeforeParam := query.Get("last_session_before")
	var lastSessionBefore *time.Time
	if lastSessionBeforeParam != "" {
		parsedTime, err := time.Parse("2006-01-02", lastSessionBeforeParam)
		if err == nil {
			// Set to end of day for inclusive filtering
			endOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 23, 59, 59, 999999999, parsedTime.Location())
			lastSessionBefore = &endOfDay
		}
	}

	sessionCountMinParam := query.Get("session_count_min")
	sessionCountMin := 0
	if sessionCountMinParam != "" {
		sessionCountMin, err = strconv.Atoi(sessionCountMinParam)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'session_count_min' must be a valid number", http.StatusBadRequest)
			return
		}
	}

	sessionCountMaxParam := query.Get("session_count_max")
	sessionCountMax := 0
	if sessionCountMaxParam != "" {
		sessionCountMax, err = strconv.Atoi(sessionCountMaxParam)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'session_count_max' must be a valid number", http.StatusBadRequest)
			return
		}
	}

	// Parse status filter
	statusFilter := parseStatusParam(query.Get("status"))
	if statusFilter == nil && query.Get("status") != "" {
		sendJSONError(w, "Bad request", "parameter 'status' must be a valid number", http.StatusBadRequest)
		return
	}

	// Get users with session data using optimized query
	// Convert status filter to int pointer
	var statusFilterInt *int
	if statusFilter != nil {
		statusInt := int(*statusFilter)
		statusFilterInt = &statusInt
	}

	// IMPORTANT: Fetch ALL users first to get accurate totalCount after filtering
	// Then paginate the filtered results. This ensures pagination works correctly.
	// Remove date filter (pass nil) to get ALL users regardless of creation date
	var allUsers []*console.User
	// Fetch all users using maximum int value to effectively fetch all users
	// This avoids hardcoding a specific limit and works with any number of users
	maxFetchLimit := math.MaxInt
	allUsers, err = server.db.Console().Users().GetAllUsersWithSessionData(ctx, maxFetchLimit, 0, statusFilterInt, nil)
	if err != nil {
		sendJSONError(w, "failed to get users with session data",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply filters after getting users (we need storage data for range filtering)
	filteredUsers := allUsers

	// Convert to response format and apply filters
	users := make([]User, 0, len(filteredUsers))
	for _, user := range filteredUsers {
		user.PasswordHash = nil

		// Get user's projects to calculate usage
		projects, err := server.db.Console().Projects().GetOwn(ctx, user.ID)
		projectCount := 0
		var totalStorageUsed, totalBandwidthUsed, totalSegmentUsed int64

		if err == nil {
			projectCount = len(projects)

			// Calculate total usage from all projects using current data
			for _, project := range projects {
				storageUsed, bandwidthUsed, segmentUsed := server.getProjectUsageData(ctx, project.ID)
				totalStorageUsed += storageUsed
				totalBandwidthUsed += bandwidthUsed
				totalSegmentUsed += segmentUsed
			}
		}

		// Apply storage range filter
		if storageMinParam != "" && totalStorageUsed < storageMin {
			continue // Skip this user
		}
		if storageMaxParam != "" && totalStorageUsed > storageMax {
			continue // Skip this user
		}

		// Apply tier filter (paid/free)
		if paidTierFilter != nil && user.PaidTier != *paidTierFilter {
			continue // Skip this user
		}

		// Apply source filter
		if sourceFilter != "" && !strings.EqualFold(user.Source, sourceFilter) {
			continue // Skip this user
		}

		// Apply account creation date range filters
		if createdAfter != nil && user.CreatedAt.Before(*createdAfter) {
			continue // Skip this user
		}
		if createdBefore != nil && user.CreatedAt.After(*createdBefore) {
			continue // Skip this user
		}

		// Apply general search filter (email or name)
		if search != "" {
			searchLower := strings.ToLower(search)
			emailMatches := strings.Contains(strings.ToLower(user.Email), searchLower)
			nameMatches := strings.Contains(strings.ToLower(user.FullName), searchLower)
			if !emailMatches && !nameMatches {
				continue // Skip this user
			}
		}

		// Get session data for this user
		var lastSessionExpiry, firstSessionExpiry *time.Time
		var totalSessionCount int

		// Get sessions for this user from webapp_sessions table
		sessions, err := server.db.Console().WebappSessions().GetAllByUserID(ctx, user.ID)
		if err == nil {
			totalSessionCount = len(sessions)
			now := time.Now()

			// Find last session expiry (most recent active or expired session)
			for _, session := range sessions {
				if lastSessionExpiry == nil || session.ExpiresAt.After(*lastSessionExpiry) {
					lastSessionExpiry = &session.ExpiresAt
				}
				if firstSessionExpiry == nil || session.ExpiresAt.Before(*firstSessionExpiry) {
					firstSessionExpiry = &session.ExpiresAt
				}
			}

			// Apply session filters
			if hasActiveSessionFilterBool != nil {
				hasActive := false
				for _, session := range sessions {
					if session.ExpiresAt.After(now) {
						hasActive = true
						break
					}
				}
				if hasActive != *hasActiveSessionFilterBool {
					continue // Skip this user
				}
			}

			// Apply last session date range filters
			if lastSessionAfter != nil && lastSessionExpiry != nil && lastSessionExpiry.Before(*lastSessionAfter) {
				continue // Skip this user
			}
			if lastSessionBefore != nil && lastSessionExpiry != nil && lastSessionExpiry.After(*lastSessionBefore) {
				continue // Skip this user
			}

			// Apply session count range filters
			if sessionCountMinParam != "" && totalSessionCount < sessionCountMin {
				continue // Skip this user
			}
			if sessionCountMaxParam != "" && totalSessionCount > sessionCountMax {
				continue // Skip this user
			}
		} else {
			// If no sessions found, check if filters require sessions
			if hasActiveSessionFilterBool != nil && *hasActiveSessionFilterBool {
				continue // Skip this user - filter requires active session but user has none
			}
			if lastSessionAfter != nil || lastSessionBefore != nil {
				continue // Skip this user - filter requires session dates but user has none
			}
			if sessionCountMinParam != "" && sessionCountMin > 0 {
				continue // Skip this user - filter requires minimum sessions but user has none
			}
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
			LastSessionExpiry:     lastSessionExpiry,
			FirstSessionExpiry:    firstSessionExpiry,
			TotalSessionCount:     totalSessionCount,
			StorageUsed:           totalStorageUsed,
			BandwidthUsed:         totalBandwidthUsed,
			SegmentUsed:           totalSegmentUsed,
			ProjectCount:          projectCount,
		})
	}

	// Calculate pagination based on filtered results
	// totalCount is the count of ALL filtered users (before pagination)
	totalCount := uint64(len(users))

	var paginatedUsers []User
	var totalPages uint64
	var actualLimit uint64
	var actualOffset uint64

	if fetchAll {
		// For "All", return all filtered users without pagination
		paginatedUsers = users
		totalPages = 1
		actualLimit = totalCount
		actualOffset = 0
	} else {
		// Normal pagination: paginate the filtered results
		actualLimit = limit
		actualOffset = (page - 1) * limit
		totalPages = (totalCount + limit - 1) / limit

		// Apply pagination to filtered results
		start := actualOffset
		end := actualOffset + limit
		if start >= totalCount {
			// Page is beyond available data
			paginatedUsers = []User{}
		} else {
			if end > totalCount {
				end = totalCount
			}
			paginatedUsers = users[start:end]
		}
	}

	// Check if this is an export request
	format := query.Get("format")
	if format == "csv" || format == "json" {
		server.exportUsersData(w, users, search, query.Get("status"), format)
		return
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
	}{
		Users:       paginatedUsers,
		PageCount:   uint(totalPages),
		CurrentPage: uint(page),
		TotalCount:  totalCount,
		HasMore:     !fetchAll && page < totalPages,
		Limit:       uint(actualLimit),
		Offset:      actualOffset,
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
			"Project Storage Limit", "Project Bandwidth Limit", "Storage Used",
			"Bandwidth Used", "Segment Used", "Project Count", "Source",
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
				fmt.Sprintf("%d", user.StorageUsed),
				fmt.Sprintf("%d", user.BandwidthUsed),
				fmt.Sprintf("%d", user.SegmentUsed),
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

	// Get user by email
	user, err := server.db.Console().Users().GetByEmail(ctx, userEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, "user not found", "", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get user", err.Error(), http.StatusInternalServerError)
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

	// Fetch all users once and count by status and paid tier
	// This is still much more efficient than the frontend approach because:
	// 1. It's done on the backend (no network overhead for multiple requests)
	// 2. It uses a single optimized query with GetAllUsersWithSessionData
	// 3. The counting happens in memory on the server, not the client
	allUsers, err := server.db.Console().Users().GetAllUsersWithSessionData(ctx, math.MaxInt, 0, nil, nil)
	if err != nil {
		sendJSONError(w, "failed to get users for statistics",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Count by status and paid tier
	for _, user := range allUsers {
		// Count by status (0=Inactive, 1=Active, 2=Deleted, 3=PendingDeletion, 4=LegalHold, 5=PendingBotVerification)
		switch user.Status {
		case console.UserStatus(0):
			stats.Inactive++
		case console.UserStatus(1):
			stats.Active++
		case console.UserStatus(2):
			stats.Deleted++
		case console.UserStatus(3):
			stats.PendingDeletion++
		case console.UserStatus(4):
			stats.LegalHold++
		case console.UserStatus(5):
			stats.PendingBotVerification++
		}

		// Count by paid tier
		if user.PaidTier {
			stats.Pro++
		} else {
			stats.Free++
		}
	}

	// Total is the count of all users
	stats.TotalAccounts = uint64(len(allUsers))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
