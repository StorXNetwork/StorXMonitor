package console

import (
	"context"
	"time"

	"storj.io/common/uuid"
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
}
