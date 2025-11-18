package console

import (
	"context"
	"time"

	"storj.io/common/uuid"
)

// DeveloperOAuthClient represents the OAuth client entity for a developer.
type DeveloperOAuthClient struct {
	ID           uuid.UUID `json:"id"`
	DeveloperID  uuid.UUID `json:"developer_id"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	RedirectURIs []string  `json:"redirect_uris"`
	Scopes       []string  `json:"scopes"`
	Status       int       `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// DeveloperOAuthClients exposes methods to manage developer_oauth_clients table in database.
type DeveloperOAuthClients interface {
	// GetByID fetches an OAuth client by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*DeveloperOAuthClient, error)
	// GetByClientID fetches an OAuth client by its client_id.
	GetByClientID(ctx context.Context, clientID string) (*DeveloperOAuthClient, error)
	// ListByDeveloperID lists all OAuth clients for a developer.
	ListByDeveloperID(ctx context.Context, developerID uuid.UUID) ([]DeveloperOAuthClient, error)
	// Insert creates a new OAuth client.
	Insert(ctx context.Context, client *DeveloperOAuthClient) (*DeveloperOAuthClient, error)
	// StatusUpdate updates the status of an existing OAuth client.
	StatusUpdate(ctx context.Context, id uuid.UUID, status int, updatedAt time.Time) error
	// Update updates an existing OAuth client.
	Update(ctx context.Context, id uuid.UUID, client *DeveloperOAuthClient) error
	// Delete deletes an OAuth client by its ID.
	Delete(ctx context.Context, id uuid.UUID) error
	// DeleteByDeveloperID deletes all OAuth clients for a developer.
	DeleteByDeveloperID(ctx context.Context, developerID uuid.UUID) error
}
