// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"net/mail"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
)

// Developers exposes methods to manage Developers table in database.
//
// architecture: Database
type Developers interface {
	// Get is a method for querying developer from the database by id.
	Get(ctx context.Context, id uuid.UUID) (*Developer, error)
	// UpdateFailedLoginCountAndExpiration increments failed_login_count and sets login_lockout_expiration appropriately.
	UpdateFailedLoginCountAndExpiration(ctx context.Context, failedLoginPenalty *float64, id uuid.UUID) error
	// GetByEmailWithUnverified is a method for querying developers by email from the database.
	GetByEmailWithUnverified(ctx context.Context, email string) (verified *Developer, unverified []Developer, err error)
	GetByStatus(ctx context.Context, status UserStatus, cursor DeveloperCursor) (*DeveloperPage, error)
	// GetAllDevelopersWithStats retrieves developers with session, OAuth client, and user count statistics using optimized JOINs.
	// This method handles filtering, pagination, and sorting at the database level for better performance.
	// Returns developers with stats and total count for pagination.
	// Results can be sorted by any column using sortColumn and sortOrder parameters.
	GetAllDevelopersWithStats(ctx context.Context, limit, offset int, statusFilter *int, createdAfter, createdBefore *time.Time, search string, hasActiveSession *bool, lastSessionAfter, lastSessionBefore *time.Time, sessionCountMin, sessionCountMax *int, sortColumn, sortOrder string) (developers []*Developer, lastSessionExpiry, firstSessionExpiry []*time.Time, totalSessionCounts, oauthClientCounts, totalUserCounts, activeUserCounts []int, totalCount int, err error)
	// GetDeveloperStats returns counts of developers grouped by status using optimized SQL aggregation
	GetDeveloperStats(ctx context.Context) (total, active, inactive, deleted, pendingDeletion, legalHold, pendingBotVerification int, err error)
	// GetByEmail is a method for querying developers by verified email from the database.
	GetByEmail(ctx context.Context, email string) (*Developer, error)

	// Insert is a method for inserting developers into the database.
	Insert(ctx context.Context, dev *Developer) (*Developer, error)
	// Delete is a method for deleting developer by ID from the database.
	Delete(ctx context.Context, id uuid.UUID) error
	// DeleteUnverifiedBefore deletes unverified developers created prior to some time from the database.
	// DeleteUnverifiedBefore(ctx context.Context, before time.Time, asOfSystemTimeInterval time.Duration, pageSize int) error
	// Update is a method for updating developers entity.
	Update(ctx context.Context, developersID uuid.UUID, request UpdateDeveloperRequest) error

	// Add DeveloperUserMapping is a method for inserting developer user mapping into the database.
	AddDeveloperUserMapping(ctx context.Context, developerID, userID uuid.UUID) error
}

// DeveloperInfo holds Developer updatable data.
type DeveloperInfo struct {
	FullName string `json:"fullName"`
}

// DeveloperCursor holds info for developer info cursor pagination.
type DeveloperCursor struct {
	Limit uint `json:"limit"`
	Page  uint `json:"page"`
}

// DeveloperPage represent developer info page result.
type DeveloperPage struct {
	Developer []Developer `json:"users"`

	Limit  uint   `json:"limit"`
	Offset uint64 `json:"offset"`

	PageCount   uint   `json:"pageCount"`
	CurrentPage uint   `json:"currentPage"`
	TotalCount  uint64 `json:"totalCount"`
}

// IsValid checks UserInfo validity and returns error describing whats wrong.
// The returned error has the class ErrValidation.
func (developer *DeveloperInfo) IsValid() error {
	// validate fullName
	if err := ValidateFullName(developer.FullName); err != nil {
		return ErrValidation.Wrap(err)
	}

	return nil
}

// CreateDeveloper struct holds info for developer creation.
type CreateDeveloper struct {
	FullName       string `json:"fullName"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	Status         int    `json:"status"`
	CompanyName    string `json:"companyName"`
	ActivationCode string `json:"-"`
	SignupId       string `json:"-"`
}

// IsValid checks CreateDeveloper validity and returns error describing whats wrong.
// The returned error has the class ErrValiation.
func (dev *CreateDeveloper) IsValid(allowNoName bool) error {
	errgrp := errs.Group{}

	errgrp.Add(
		ValidateNewPassword(dev.Password),
	)

	if !allowNoName {
		errgrp.Add(
			ValidateFullName(dev.FullName),
		)
	}

	// validate email
	_, err := mail.ParseAddress(dev.Email)
	errgrp.Add(err)

	return ErrValidation.Wrap(errgrp.Err())
}

// AuthDeveloper holds info for developer authentication token requests.
type AuthDeveloper struct {
	Email              string `json:"email"`
	Password           string `json:"password"`
	RememberForOneWeek bool   `json:"rememberForOneWeek"`

	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

// Developer is a database object that describes Developer entity.
type Developer struct {
	ID uuid.UUID `json:"id"`

	FullName string `json:"fullName"`

	Email        string `json:"email"`
	PasswordHash []byte `json:"-"`

	Status UserStatus `json:"status"`

	CreatedAt time.Time `json:"createdAt"`

	CompanyName string `json:"companyName"`

	FailedLoginCount       int       `json:"failedLoginCount"`
	LoginLockoutExpiration time.Time `json:"loginLockoutExpiration"`

	ActivationCode string `json:"-"`
	SignupId       string `json:"-"`
}

// ResponseDeveloper is an entity which describes db Developer and can be sent in response.
type ResponseDeveloper struct {
	ID          uuid.UUID `json:"id"`
	FullName    string    `json:"fullName"`
	Email       string    `json:"email"`
	CompanyName string    `json:"companyName"`
}

// developerKey is context key for Developer.
const developerKey key = 100

// WithDeveloper creates new context with Developer.
func WithDeveloper(ctx context.Context, developer *Developer) context.Context {
	return context.WithValue(ctx, developerKey, developer)
}

// GetDeveloper gets Developer from context.
func GetDeveloper(ctx context.Context) (*Developer, error) {
	if developer, ok := ctx.Value(developerKey).(*Developer); ok {
		return developer, nil
	}

	return nil, Error.New("developer is not in context")
}

// UpdateDeveloperRequest contains all columns which are optionally updatable by developer.Update.
type UpdateDeveloperRequest struct {
	FullName *string

	CompanyName *string

	Email        *string
	PasswordHash []byte

	Status *UserStatus

	// failed_login_count is nullable, but we don't really have a reason
	// to set it to NULL, so it doesn't need to be a double pointer here.
	FailedLoginCount       *int
	LoginLockoutExpiration **time.Time

	ActivationCode *string
	SignupId       *string
}
