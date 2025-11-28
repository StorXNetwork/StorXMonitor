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
	superAdminEmail = "superadmin@storx.io"
	defaultPassword = "Superadmin@2025!"
	superAdminRole  = "super_admin"
)

// seedSuperAdmin creates a super admin user if one doesn't exist.
// This is called during server startup to ensure there's always at least one admin.
// It checks for any admin with super_admin role, not just a specific email,
// so it works even if the super admin changes their email.
func seedSuperAdmin(log *zap.Logger, db DB, _ string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adminDB := db.AdminUsers()

	// Check if any super_admin exists (by role, not email)
	if superAdminExists(ctx, log, adminDB) {
		return
	}

	createSuperAdmin(ctx, log, adminDB)
}

// superAdminExists checks if any admin with super_admin role exists.
// This is more robust than checking by email, as admins can change their email.
func superAdminExists(ctx context.Context, log *zap.Logger, adminDB Users) bool {
	// Get all admins (active, inactive, and deleted) to check for super_admin role
	allAdmins, err := adminDB.ListAll(ctx)
	if err != nil {
		log.Error("Failed to list all admins for super admin check",
			zap.Error(err))
		// On error, try fallback check by email
		return fallbackCheckByEmail(ctx, log, adminDB)
	}

	// Check if any admin has super_admin role (regardless of status)
	for _, admin := range allAdmins {
		if admin.Roles != nil && *admin.Roles == superAdminRole {
			log.Info("Super admin already exists",
				zap.String("email", admin.Email),
				zap.String("role", *admin.Roles),
				zap.String("id", admin.ID.String()),
				zap.Int("status", int(admin.Status)))
			return true
		}
	}

	// No super_admin found by role, try fallback check by email
	// This handles edge cases where the role might not be set correctly
	return fallbackCheckByEmail(ctx, log, adminDB)
}

// fallbackCheckByEmail is a fallback method to check for super admin by email.
// This is used when List() fails or to catch edge cases.
func fallbackCheckByEmail(ctx context.Context, log *zap.Logger, adminDB Users) bool {
	_, err := adminDB.GetByEmailAnyStatus(ctx, superAdminEmail)
	switch {
	case err == nil:
		log.Info("Super admin found by email fallback", zap.String("email", superAdminEmail))
		return true
	case errs.Is(err, ErrNotFound):
		return false
	default:
		log.Error("Failed to check for existing super admin by email",
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
