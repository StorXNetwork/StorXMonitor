// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// loginHandler handles admin login requests using email and password.
func (server *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		server.log.Error("Failed to decode login request", zap.Error(err))
		sendJSONError(w, "invalid request body", err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if loginRequest.Email == "" || loginRequest.Password == "" {
		server.log.Warn("Login attempt with missing email or password")
		sendJSONError(w, "email and password are required", "", http.StatusBadRequest)
		return
	}

	adminDB := server.db.AdminUsers()
	server.log.Info("Admin login attempt", zap.String("email", loginRequest.Email))

	// Get admin by email (check any status, not just active)
	adminUser, err := adminDB.GetByEmailAnyStatus(ctx, loginRequest.Email)
	if err != nil {
		if errs.Is(err, ErrNotFound) {
			server.log.Warn("Admin user not found", zap.String("email", loginRequest.Email))
			sendJSONError(w, "invalid credentials", "", http.StatusUnauthorized)
			return
		}
		server.log.Error("Failed to get admin user", zap.Error(err), zap.String("email", loginRequest.Email))
		sendJSONError(w, "login failed", err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if password hash is empty
	if len(adminUser.PasswordHash) == 0 {
		server.log.Error("Admin password hash is empty", zap.String("email", adminUser.Email))
		sendJSONError(w, "admin account not properly configured", "", http.StatusInternalServerError)
		return
	}

	// Check if admin is active - only active admins can login
	if adminUser.Status != AdminActive {
		server.log.Warn("Admin account is not active",
			zap.String("email", adminUser.Email),
			zap.Int("status", int(adminUser.Status)))
		sendJSONError(w, "account is not active", "", http.StatusUnauthorized)
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword(adminUser.PasswordHash, []byte(loginRequest.Password))
	if err != nil {
		server.log.Warn("Password verification failed", zap.String("email", loginRequest.Email))
		sendJSONError(w, "invalid credentials", "", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	jwtToken, err := server.auth.GenerateToken(ctx, adminUser.Email, func() string {
		if adminUser.Roles != nil {
			return *adminUser.Roles
		}
		return "admin"
	}())
	if err != nil {
		server.log.Error("failed to generate JWT token", zap.Error(err))
		sendJSONError(w, "failed to generate token", err.Error(), http.StatusInternalServerError)
		return
	}

	// Set token in cookie (following console pattern)
	expiresAt := time.Now().Add(server.auth.expiration)
	server.cookieAuth.SetTokenCookie(w, AdminTokenInfo{
		Token:     jwtToken,
		ExpiresAt: expiresAt,
	})

	// Return success response (following console pattern)
	response := struct {
		Token string `json:"token"` // Token also returned in JSON for backward compatibility
		User  struct {
			Email string `json:"email"`
			Role  string `json:"role,omitempty"`
		} `json:"user"`
	}{
		Token: jwtToken,
	}
	response.User.Email = adminUser.Email
	if adminUser.Roles != nil {
		response.User.Role = *adminUser.Roles
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
	server.log.Info("Admin login successful", zap.String("email", adminUser.Email))
}

// logoutHandler handles admin logout requests.
func (server *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	// Remove auth cookie (following console pattern)
	server.cookieAuth.RemoveTokenCookie(w)

	sendJSONData(w, http.StatusOK, []byte(`{"message":"logged out successfully"}`))
}

// getCurrentAdminHandler returns the current authenticated admin user information.
func (server *Server) getCurrentAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Get admin user from context (set by withAuth middleware)
	adminUser, err := GetAdminUser(ctx)
	if err != nil {
		sendJSONError(w, "unauthorized", "admin user not found in context", http.StatusUnauthorized)
		return
	}

	// Return admin user info (without password hash)
	response := struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		Role      string    `json:"role"`
		Status    int       `json:"status"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
	}{
		ID:        adminUser.ID.String(),
		Email:     adminUser.Email,
		Role:      "admin",
		Status:    int(adminUser.Status),
		CreatedAt: adminUser.CreatedAt,
		UpdatedAt: adminUser.UpdatedAt,
	}

	if adminUser.Roles != nil && *adminUser.Roles != "" {
		response.Role = *adminUser.Roles
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// updateCurrentAdminHandler updates the current authenticated admin user information.
func (server *Server) updateCurrentAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Get admin user from context
	adminUser, err := GetAdminUser(ctx)
	if err != nil {
		sendJSONError(w, "unauthorized", "admin user not found in context", http.StatusUnauthorized)
		return
	}

	var updateRequest struct {
		Email    *string `json:"email,omitempty"`
		Password *string `json:"password,omitempty"`
		// Role cannot be updated by self - only by other admins for security
	}

	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		sendJSONError(w, "invalid request body", err.Error(), http.StatusBadRequest)
		return
	}

	updateReq := UpdateAdminUserRequest{}

	// Update email if provided
	if updateRequest.Email != nil {
		// Check if email is already taken by another admin
		existingAdmin, err := server.db.AdminUsers().GetByEmail(ctx, *updateRequest.Email)
		if err == nil && existingAdmin.ID != adminUser.ID {
			sendJSONError(w, "email already used", "", http.StatusConflict)
			return
		}
		updateReq.Email = updateRequest.Email
	}

	// Update password if provided
	if updateRequest.Password != nil {
		password := strings.TrimSpace(*updateRequest.Password)
		if password == "" {
			sendJSONError(w, "password cannot be empty", "password must not be empty or whitespace only", http.StatusBadRequest)
			return
		}
		if len(password) < 8 {
			sendJSONError(w, "password too short", "password must be at least 8 characters", http.StatusBadRequest)
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			server.log.Error("Failed to hash password", zap.Error(err), zap.String("email", adminUser.Email))
			sendJSONError(w, "failed to hash password", err.Error(), http.StatusInternalServerError)
			return
		}
		updateReq.PasswordHash = hashedPassword
		server.log.Info("Password update initiated", zap.String("email", adminUser.Email))
	}

	// Note: Role cannot be updated by self for security reasons
	// Only super admins can change roles via separate admin management endpoints

	// Update admin user
	updatedAdmin, err := server.db.AdminUsers().Update(ctx, adminUser.ID, updateReq)
	if err != nil {
		sendJSONError(w, "failed to update admin user", err.Error(), http.StatusInternalServerError)
		return
	}

	// Return updated admin user info
	response := struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		Role      string    `json:"role"`
		Status    int       `json:"status"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
	}{
		ID:        updatedAdmin.ID.String(),
		Email:     updatedAdmin.Email,
		Role:      "admin",
		Status:    int(updatedAdmin.Status),
		CreatedAt: updatedAdmin.CreatedAt,
		UpdatedAt: updatedAdmin.UpdatedAt,
	}

	if updatedAdmin.Roles != nil && *updatedAdmin.Roles != "" {
		response.Role = *updatedAdmin.Roles
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}
