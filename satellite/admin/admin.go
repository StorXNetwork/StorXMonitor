// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"time"

	"storj.io/common/uuid"
)

// Users exposes methods to manage Admin table in database.
//
// architecture: Database
type Users interface {
	// Get is a method for querying admin from the database by id.
	Get(ctx context.Context, id uuid.UUID) (*AdminUser, error)
	// GetByEmail is a method for querying admin by email from the database (active only).
	GetByEmail(ctx context.Context, email string) (*AdminUser, error)
	// GetByEmailAnyStatus returns admin by email regardless of status (used for activation).
	GetByEmailAnyStatus(ctx context.Context, email string) (*AdminUser, error)
	// Insert is a method for inserting admin into the database.
	Insert(ctx context.Context, user *AdminUser) (*AdminUser, error)
	// Update is a method for updating admin entity.
	Update(ctx context.Context, userID uuid.UUID, request UpdateAdminUserRequest) (*AdminUser, error)
	// Delete is a method for deleting admin by ID from the database (soft delete).
	Delete(ctx context.Context, id uuid.UUID) error
	// List returns all active admin users.
	List(ctx context.Context) ([]AdminUser, error)
}

// AdminUserStatus indicates the status of an admin user.
type AdminUserStatus int

const (
	// AdminInactive is a status that admin receives after creation but before activation.
	AdminInactive AdminUserStatus = 0
	// AdminActive is a status that admin receives when account is active.
	AdminActive AdminUserStatus = 1
	// AdminDeleted is a status that admin receives after deleting account (soft delete).
	AdminDeleted AdminUserStatus = 2
)

// String returns a string representation of the admin user status.
func (s AdminUserStatus) String() string {
	switch s {
	case AdminInactive:
		return "Inactive"
	case AdminActive:
		return "Active"
	case AdminDeleted:
		return "Deleted"
	default:
		return ""
	}
}

// AdminUser is a database object that describes Admin entity.
type AdminUser struct {
	ID uuid.UUID `json:"id"`

	Email        string          `json:"email"`
	PasswordHash []byte          `json:"password_hash"`
	Status       AdminUserStatus `json:"status"`
	Roles        *string         `json:"roles,omitempty"` // nullable, comma-separated or JSON format

	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"` // nullable, for soft delete
}

// UpdateAdminUserRequest contains all columns which are optionally updatable by Users.Update.
type UpdateAdminUserRequest struct {
	Email        *string
	PasswordHash []byte
	Status       *AdminUserStatus
	Roles        **string // double pointer for nullable field
}

// contextKey is the type of the key used to store admin user in context.
type contextKey int

const (
	adminUserKey contextKey = iota
)

// WithAdminUser creates new context with AdminUser.
func WithAdminUser(ctx context.Context, user *AdminUser) context.Context {
	return context.WithValue(ctx, adminUserKey, user)
}

// GetAdminUser gets AdminUser from context.
func GetAdminUser(ctx context.Context) (*AdminUser, error) {
	if user, ok := ctx.Value(adminUserKey).(*AdminUser); ok {
		return user, nil
	}

	return nil, Error.New("admin user is not in context")
}

// Error classes for admin users.
var (
	// ErrNotFound is error class used when admin user is not found.
	ErrNotFound = Error.New("admin user not found")
	// ErrEmailUsed is error class used when email is already taken.
	ErrEmailUsed = Error.New("email already used")
	// ErrLoginCredentials is error class used when login credentials are invalid.
	ErrLoginCredentials = Error.New("invalid login credentials")
)
