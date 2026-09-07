// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

var (
	// ErrNotFound is returned when a reseller entity is not found.
	ErrNotFound = errs.Class("reseller not found")
)

// ResellerStatus mirrors console user status values for resellers.
type ResellerStatus int

const (
	// ResellerInactive indicates the reseller account is inactive.
	ResellerInactive ResellerStatus = 0
	// ResellerActive indicates the reseller account is active.
	ResellerActive ResellerStatus = 1
	// ResellerDeleted indicates the reseller account is deleted.
	ResellerDeleted ResellerStatus = 2
)

// DomainType values for reseller_domains.domain_type.
const (
	DomainTypeSubdomain = "subdomain"
	DomainTypeCustom    = "custom"
)

// DomainStatus values for reseller_domains.status.
const (
	DomainStatusPending  = "pending"
	DomainStatusActive   = "active"
	DomainStatusFailed   = "failed"
	DomainStatusDisabled = "disabled"
)

// VerificationMethod values for reseller_domains.verification_method.
const (
	VerificationMethodCNAME   = "CNAME"
	VerificationMethodARecord = "A_RECORD"
	VerificationMethodTXT     = "TXT"
)

// VerificationStatus values for reseller_domains.verification_status.
const (
	VerificationStatusPending  = "pending"
	VerificationStatusVerified = "verified"
	VerificationStatusFailed   = "failed"
)

// SSLStatus values for reseller_domains.ssl_status.
const (
	SSLStatusPending = "pending"
	SSLStatusIssued  = "issued"
	SSLStatusFailed  = "failed"
	SSLStatusExpired = "expired"
)

// Reseller represents a reseller account.
type Reseller struct {
	ID           uuid.UUID
	Name         string
	Email        string
	PasswordHash []byte
	CompanyName  *string
	Status       ResellerStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time

	FailedLoginCount       int
	LoginLockoutExpiration time.Time
	ActivationCode         string
	SignupID               string

	NewUnverifiedEmail          *string
	EmailChangeVerificationStep int
	MFAEnabled                  bool
	MFASecretKey                string
	MFARecoveryCodes            []string
}

// AuthReseller holds info for reseller authentication token requests.
type AuthReseller struct {
	Email              string `json:"email"`
	Password           string `json:"password"`
	CaptchaResponse    string `json:"captchaResponse"`
	RememberForOneWeek bool   `json:"rememberForOneWeek"`
	MFAPasscode        string `json:"mfaPasscode"`
	MFARecoveryCode    string `json:"mfaRecoveryCode"`
	IP                 string `json:"-"`
	UserAgent          string `json:"-"`
}

// CreateResellerRequest holds info for creating a reseller via email registration.
type CreateResellerRequest struct {
	FullName    string
	Email       string
	Password    string
	CompanyName string
}

// WebappSessionReseller represents a session on the seller web app.
type WebappSessionReseller struct {
	ID                        uuid.UUID
	ResellerID                uuid.UUID
	IP                        string
	Status                    int
	ExpiresAt                 time.Time
	IsRequesterCurrentSession bool
}

// ResellerWebappSessionsPage represents a page of reseller webapp sessions.
type ResellerWebappSessionsPage struct {
	Sessions []WebappSessionReseller `json:"sessions"`

	Limit          uint   `json:"limit"`
	Order          int8   `json:"order"`
	OrderDirection uint8  `json:"orderDirection"`
	Offset         uint64 `json:"offset"`
	PageCount      uint   `json:"pageCount"`
	CurrentPage    uint   `json:"currentPage"`
	TotalCount     uint64 `json:"totalCount"`
}

// ResellerWebappSessionsCursor holds info for reseller webapp sessions cursor pagination.
type ResellerWebappSessionsCursor struct {
	Limit          uint
	Page           uint
	Order          int8
	OrderDirection uint8
}

// ResellerConfig stores branding/profile settings for a reseller.
type ResellerConfig struct {
	ID              uuid.UUID
	ResellerID      uuid.UUID
	Config          json.RawMessage
	ActiveThemeType string
	ActiveThemeID   *uuid.UUID
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ResellerDomain stores the single active domain for a reseller.
type ResellerDomain struct {
	ID                 uuid.UUID
	ResellerID         uuid.UUID
	Domain             string
	DomainType         string
	Status             string
	VerificationMethod *string
	VerificationStatus string
	SSLStatus          string
	DNSTarget          *string
	VerifiedAt         *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          *time.Time
}

// UpdateResellerRequest contains updatable reseller fields.
type UpdateResellerRequest struct {
	Name         *string
	Email        *string
	PasswordHash []byte
	CompanyName  *string
	Status       *ResellerStatus
	DeletedAt    *time.Time
	UpdatedAt    time.Time

	FailedLoginCount       *int
	LoginLockoutExpiration **time.Time
	ActivationCode         *string
	SignupID               *string

	NewUnverifiedEmail          **string
	EmailChangeVerificationStep *int
	MFAEnabled                  *bool
	MFASecretKey                **string
	MFARecoveryCodes            *[]string
}

// UpdateResellerConfigRequest contains updatable config fields.
type UpdateResellerConfigRequest struct {
	Config          json.RawMessage
	ActiveThemeType *string
	ActiveThemeID   **uuid.UUID
	UpdatedAt       time.Time
}

// UpdateResellerDomainRequest contains updatable domain fields.
type UpdateResellerDomainRequest struct {
	Domain             *string
	DomainType         *string
	Status             *string
	VerificationMethod *string
	VerificationStatus *string
	SSLStatus          *string
	DNSTarget          *string
	VerifiedAt         *time.Time
	DeletedAt          *time.Time
	UpdatedAt          time.Time
}

// DB exposes reseller database tables.
//
// architecture: Database
type DB interface {
	Resellers() Resellers
	ResellerConfigs() ResellerConfigs
	ResellerDomains() ResellerDomains
	ThemePresets() ThemePresets
	ResellerThemes() ResellerThemes
	WebappSessionResellers() WebappSessionResellers
	ResetPasswordTokens() ResellerResetPasswordTokens
	ResellerDeleteRequests() ResellerDeleteRequests
}

// Resellers exposes methods to manage resellers table in database.
//
// architecture: Database
type Resellers interface {
	Get(ctx context.Context, id uuid.UUID) (*Reseller, error)
	GetByEmail(ctx context.Context, email string) (*Reseller, error)
	GetByEmailAnyStatus(ctx context.Context, email string) (*Reseller, error)
	GetByEmailWithUnverified(ctx context.Context, email string) (verified *Reseller, unverified []Reseller, err error)
	Insert(ctx context.Context, reseller *Reseller) (*Reseller, error)
	Update(ctx context.Context, id uuid.UUID, update UpdateResellerRequest) (*Reseller, error)
}

// ResellerConfigs exposes methods to manage reseller_configs table in database.
//
// architecture: Database
type ResellerConfigs interface {
	Get(ctx context.Context, id uuid.UUID) (*ResellerConfig, error)
	GetByResellerID(ctx context.Context, resellerID uuid.UUID) (*ResellerConfig, error)
	Insert(ctx context.Context, config *ResellerConfig) (*ResellerConfig, error)
	Update(ctx context.Context, resellerID uuid.UUID, update UpdateResellerConfigRequest) (*ResellerConfig, error)
	DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) error
}

// ResellerDomains exposes methods to manage reseller_domains table in database.
//
// architecture: Database
type ResellerDomains interface {
	Get(ctx context.Context, id uuid.UUID) (*ResellerDomain, error)
	GetByResellerID(ctx context.Context, resellerID uuid.UUID) (*ResellerDomain, error)
	GetByDomain(ctx context.Context, domain string) (*ResellerDomain, error)
	Insert(ctx context.Context, domain *ResellerDomain) (*ResellerDomain, error)
	Update(ctx context.Context, resellerID uuid.UUID, update UpdateResellerDomainRequest) (*ResellerDomain, error)
}

// ThemePresets exposes system theme presets.
type ThemePresets interface {
	List(ctx context.Context) ([]ThemePreset, error)
	Get(ctx context.Context, id uuid.UUID) (*ThemePreset, error)
	GetBySlug(ctx context.Context, slug string) (*ThemePreset, error)
	GetByName(ctx context.Context, name string) (*ThemePreset, error)
	GetDefault(ctx context.Context) (*ThemePreset, error)
	Insert(ctx context.Context, preset *ThemePreset) (*ThemePreset, error)
}

// ResellerThemes exposes per-reseller custom themes.
type ResellerThemes interface {
	ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]ResellerCustomTheme, error)
	CountByResellerID(ctx context.Context, resellerID uuid.UUID) (int, error)
	Get(ctx context.Context, id uuid.UUID) (*ResellerCustomTheme, error)
	GetByResellerID(ctx context.Context, resellerID, id uuid.UUID) (*ResellerCustomTheme, error)
	GetByResellerIDAndName(ctx context.Context, resellerID uuid.UUID, name string) (*ResellerCustomTheme, error)
	Insert(ctx context.Context, theme *ResellerCustomTheme) (*ResellerCustomTheme, error)
	Update(ctx context.Context, id uuid.UUID, name string, colors ResellerBrandingTheme, updatedAt time.Time) (*ResellerCustomTheme, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) error
}

// WebappSessionResellers exposes methods to manage webapp_session_resellers table.
type WebappSessionResellers interface {
	Create(ctx context.Context, id, resellerID uuid.UUID, ip string, expiresAt time.Time) (WebappSessionReseller, error)
	GetBySessionID(ctx context.Context, sessionID uuid.UUID) (WebappSessionReseller, error)
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
	DeleteAllByResellerID(ctx context.Context, resellerID uuid.UUID) (int64, error)
	DeleteAllByResellerIDExcept(ctx context.Context, resellerID uuid.UUID, sessionID uuid.UUID) (int64, error)
	GetPagedActiveByResellerID(ctx context.Context, resellerID uuid.UUID, expiresAt time.Time, cursor ResellerWebappSessionsCursor) (*ResellerWebappSessionsPage, error)
	UpdateExpiration(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) error
}

// ResellerResetPasswordTokens exposes methods to manage reset_password_token_resellers table.
type ResellerResetPasswordTokens interface {
	Create(ctx context.Context, ownerID uuid.UUID) (secret string, err error)
	GetBySecret(ctx context.Context, secret string) (ownerID uuid.UUID, createdAt time.Time, err error)
	GetByOwnerID(ctx context.Context, ownerID uuid.UUID) (secret string, createdAt time.Time, err error)
	Delete(ctx context.Context, secret string) error
}

// ResellerDeleteRequests exposes methods to manage reseller_delete_requests table.
type ResellerDeleteRequests interface {
	CreateDeleteRequest(ctx context.Context, resellerID uuid.UUID, deleteAt time.Time) error
}
