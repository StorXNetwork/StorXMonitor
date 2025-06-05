package console

import (
	"context"
	"time"

	"storj.io/common/uuid"
)

type OAuth2Request struct {
	ID             uuid.UUID
	ClientID       string
	UserID         uuid.UUID
	RedirectURI    string
	Scopes         string
	Status         int
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Code           string
	ApprovedScopes string
	RejectedScopes string
}

type OAuth2Requests interface {
	Insert(ctx context.Context, req *OAuth2Request) (*OAuth2Request, error)
	Get(ctx context.Context, id uuid.UUID) (*OAuth2Request, error)
	GetByCode(ctx context.Context, code string) (*OAuth2Request, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status int, code string) error
	UpdateConsent(ctx context.Context, id uuid.UUID, status int, code, approvedScopes, rejectedScopes string) error
	MarkCodeUsed(ctx context.Context, id uuid.UUID) error
}
