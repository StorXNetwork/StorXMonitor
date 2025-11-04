// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/json"
	"net/http"
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
