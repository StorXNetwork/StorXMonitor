package console

import (
	"context"
	"time"

	"storj.io/common/uuid"
)

// OAuth2RequestStatus represents the status of an OAuth2 request
const (
	OAuth2RequestStatusPending  = 0 // Request is pending approval
	OAuth2RequestStatusApproved = 1 // Request has been approved
	OAuth2RequestStatusRejected = 2 // Request has been rejected
	OAuth2RequestStatusUsed     = 2 // Code has been used (same as rejected for now)
)

type OAuth2Request struct {
	ID               uuid.UUID `json:"id"`
	ClientID         string    `json:"client_id"`
	UserID           uuid.UUID `json:"user_id"`
	RedirectURI      string    `json:"redirect_uri"`
	Scopes           string    `json:"scopes"`
	Status           int       `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	ConsentExpiresAt time.Time `json:"consent_expires_at"`
	Code             string    `json:"code"`
	CodeExpiresAt    time.Time `json:"code_expires_at"`
	ApprovedScopes   string    `json:"approved_scopes"`
	RejectedScopes   string    `json:"rejected_scopes"`
}

// UserStatistics contains user access statistics for a developer
type UserStatistics struct {
	TotalUsers       int `json:"total_users"`
	ActiveUsers      int `json:"active_users"` // Users with requests in last 30 days
	TotalRequests    int `json:"total_requests"`
	ApprovedRequests int `json:"approved_requests"`
	PendingRequests  int `json:"pending_requests"`
	RejectedRequests int `json:"rejected_requests"`
}

// UserAccessTrend represents user access over time
type UserAccessTrend struct {
	Date         time.Time `json:"date"`
	UserCount    int       `json:"user_count"`
	RequestCount int       `json:"request_count"`
}

// ApplicationUserStats represents user access breakdown by OAuth client
type ApplicationUserStats struct {
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
	TotalUsers    int    `json:"total_users"`
	ActiveUsers   int    `json:"active_users"`
	TotalRequests int    `json:"total_requests"`
}

type OAuth2Requests interface {
	Insert(ctx context.Context, req *OAuth2Request) (*OAuth2Request, error)
	Get(ctx context.Context, id uuid.UUID) (*OAuth2Request, error)
	GetByCode(ctx context.Context, code string) (*OAuth2Request, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status int, code string) error
	UpdateConsent(ctx context.Context, id uuid.UUID, status int, code, approvedScopes, rejectedScopes string, codeExpiresAt time.Time) error
	UpdateConsentExpiry(ctx context.Context, id uuid.UUID, consentExpiresAt time.Time) error
	UpdateCodeAndExpiry(ctx context.Context, id uuid.UUID, code string, codeExpiresAt time.Time) error
	MarkCodeUsed(ctx context.Context, id uuid.UUID) error
	// Access logs methods
	ListByDeveloperID(ctx context.Context, developerID uuid.UUID, limit, offset int, startDate, endDate *time.Time, status *int, clientID, userID, ipAddress string) ([]OAuth2Request, error)
	CountByDeveloperID(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time, status *int, clientID, userID, ipAddress string) (int, error)
	GetStatisticsByDeveloperID(ctx context.Context, developerID uuid.UUID, clientID string) (total, approved, pending, rejected int, err error)
	// User statistics methods for admin
	GetUserStatisticsByDeveloperID(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time) (*UserStatistics, error)
	GetUserAccessTrendsByDeveloperID(ctx context.Context, developerID uuid.UUID, period string, startDate, endDate *time.Time) ([]UserAccessTrend, error)
	GetUserAccessByApplication(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time) ([]ApplicationUserStats, error)
}
