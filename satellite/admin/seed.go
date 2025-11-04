// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"storj.io/common/uuid"
)

// Constants for super admin configuration
const (
	superAdminEmail = "admin@storj.io"
	defaultPassword = "admin123"
	superAdminRole  = "super_admin"
)

// seedSuperAdmin creates a super admin user if one doesn't exist.
// This is called during server startup to ensure there's always at least one admin.
func seedSuperAdmin(log *zap.Logger, db DB, _ string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adminDB := db.AdminUsers()

	// Quick existence check first
	if adminExists(ctx, log, adminDB) {
		return
	}

	createSuperAdmin(ctx, log, adminDB)
}

// adminExists checks if admin already exists and handles errors
func adminExists(ctx context.Context, log *zap.Logger, adminDB Users) bool {
	_, err := adminDB.GetByEmailAnyStatus(ctx, superAdminEmail)
	switch {
	case err == nil:
		log.Info("Super admin already exists", zap.String("email", superAdminEmail))
		return true
	case errs.Is(err, ErrNotFound):
		return false
	default:
		log.Error("Failed to check for existing super admin",
			zap.Error(err),
			zap.String("email", superAdminEmail))
		// On error, assume it doesn't exist to allow creation attempt
		return false
	}
}

// createSuperAdmin handles the creation of a new super admin
func createSuperAdmin(ctx context.Context, log *zap.Logger, adminDB Users) {
	log.Info("Creating super admin", zap.String("email", superAdminEmail))

	adminUser, err := prepareAdminUser()
	if err != nil {
		log.Error("Failed to prepare super admin", zap.Error(err))
		return
	}

	createdAdmin, err := adminDB.Insert(ctx, adminUser)
	if err != nil {
		handleInsertError(log, err)
		return
	}

	// Ensure admin is active (workaround for dbx hardcoded status)
	if err := ensureAdminActive(ctx, log, adminDB, createdAdmin); err != nil {
		return
	}

	logSuperAdminSuccess(log, createdAdmin.ID)
}

// prepareAdminUser creates and configures the admin user object
func prepareAdminUser() (*AdminUser, error) {
	adminID, err := uuid.New()
	if err != nil {
		return nil, errs.New("failed to generate admin UUID: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errs.New("failed to hash password: %w", err)
	}

	now := time.Now()
	role := superAdminRole // Need variable to take address of constant
	return &AdminUser{
		ID:           adminID,
		Email:        superAdminEmail,
		PasswordHash: passwordHash,
		Status:       AdminActive,
		Roles:        &role,
		CreatedAt:    now,
		UpdatedAt:    now,
		DeletedAt:    nil,
	}, nil
}

// handleInsertError processes insertion errors
func handleInsertError(log *zap.Logger, err error) {
	if isDuplicateError(err) {
		log.Info("Super admin already exists (detected during insert)",
			zap.String("email", superAdminEmail))
		return
	}

	log.Error("Failed to create super admin",
		zap.Error(err),
		zap.String("email", superAdminEmail))
}

// isDuplicateError checks if the error indicates a duplicate entry
func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "duplicate") ||
		strings.Contains(errStr, "unique") ||
		strings.Contains(errStr, "already exists")
}

// ensureAdminActive ensures the admin has active status
func ensureAdminActive(ctx context.Context, log *zap.Logger, adminDB Users, admin *AdminUser) error {
	if admin.Status == AdminActive {
		return nil
	}

	log.Info("Activating super admin after creation",
		zap.String("email", admin.Email),
		zap.String("id", admin.ID.String()),
		zap.Int("current_status", int(admin.Status)))

	activeStatus := AdminActive
	updatedAdmin, err := adminDB.Update(ctx, admin.ID, UpdateAdminUserRequest{
		Status: &activeStatus,
	})
	if err != nil {
		log.Error("Failed to activate super admin after creation",
			zap.Error(err),
			zap.String("email", admin.Email),
			zap.String("id", admin.ID.String()))
		return err
	}

	log.Info("Super admin activated successfully",
		zap.String("email", updatedAdmin.Email),
		zap.Int("status", int(updatedAdmin.Status)))
	return nil
}

// logSuperAdminSuccess logs successful admin creation (without password in production)
func logSuperAdminSuccess(log *zap.Logger, adminID uuid.UUID) {
	// In production, you might want to omit the password from logs
	if log.Core().Enabled(zap.DebugLevel) {
		log.Debug("Super admin seeded successfully",
			zap.String("email", superAdminEmail),
			zap.String("id", adminID.String()),
			zap.String("password", defaultPassword))
	} else {
		log.Info("Super admin seeded successfully",
			zap.String("email", superAdminEmail),
			zap.String("id", adminID.String()))
	}
}
