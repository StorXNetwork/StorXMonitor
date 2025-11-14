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
}
