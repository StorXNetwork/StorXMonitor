package satellitedb

import (
	"context"
	"strings"
	"time"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/satellitedb/dbx"
)

type developerOAuthClients struct {
	db *satelliteDB
}

var _ console.DeveloperOAuthClients = (*developerOAuthClients)(nil)

func (repo *developerOAuthClients) GetByID(ctx context.Context, id uuid.UUID) (*console.DeveloperOAuthClient, error) {
	dbxClient, err := repo.db.Get_DeveloperOauthClient_By_Id(ctx, dbx.DeveloperOauthClient_Id(id[:]))
	if err != nil {
		return nil, err
	}
	return toConsoleOAuthClient(dbxClient), nil
}

func (repo *developerOAuthClients) GetByClientID(ctx context.Context, clientID string) (*console.DeveloperOAuthClient, error) {
	dbxClient, err := repo.db.Get_DeveloperOauthClient_By_ClientId(ctx, dbx.DeveloperOauthClient_ClientId(clientID))
	if err != nil {
		return nil, err
	}
	return toConsoleOAuthClient(dbxClient), nil
}

func (repo *developerOAuthClients) ListByDeveloperID(ctx context.Context, developerID uuid.UUID) ([]console.DeveloperOAuthClient, error) {
	dbxClients, err := repo.db.All_DeveloperOauthClient_By_DeveloperId(ctx, dbx.DeveloperOauthClient_DeveloperId(developerID[:]))
	if err != nil {
		return nil, err
	}
	clients := make([]console.DeveloperOAuthClient, len(dbxClients))
	for i, dbxClient := range dbxClients {
		clients[i] = *toConsoleOAuthClient(dbxClient)
	}
	return clients, nil
}

func (repo *developerOAuthClients) Insert(ctx context.Context, client *console.DeveloperOAuthClient) (*console.DeveloperOAuthClient, error) {
	dbxClient, err := repo.db.Create_DeveloperOauthClient(
		ctx,
		dbx.DeveloperOauthClient_Id(client.ID[:]),
		dbx.DeveloperOauthClient_DeveloperId(client.DeveloperID[:]),
		dbx.DeveloperOauthClient_ClientId(client.ClientID),
		dbx.DeveloperOauthClient_ClientSecret(client.ClientSecret),
		dbx.DeveloperOauthClient_Name(client.Name),
		dbx.DeveloperOauthClient_RedirectUris(strings.Join(client.RedirectURIs, ",")),
		dbx.DeveloperOauthClient_Status(client.Status),
		dbx.DeveloperOauthClient_UpdatedAt(client.UpdatedAt),
	)
	if err != nil {
		return nil, err
	}
	return toConsoleOAuthClient(dbxClient), nil
}

func (repo *developerOAuthClients) StatusUpdate(ctx context.Context, id uuid.UUID, status int, updatedAt time.Time) error {
	fields := dbx.DeveloperOauthClient_Update_Fields{
		Status:    dbx.DeveloperOauthClient_Status(status),
		UpdatedAt: dbx.DeveloperOauthClient_UpdatedAt(updatedAt),
	}
	_, err := repo.db.Update_DeveloperOauthClient_By_Id(
		ctx,
		dbx.DeveloperOauthClient_Id(id[:]),
		fields,
	)
	return err
}

func (repo *developerOAuthClients) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := repo.db.Delete_DeveloperOauthClient_By_Id(ctx, dbx.DeveloperOauthClient_Id(id[:]))
	return err
}

func (repo *developerOAuthClients) DeleteByDeveloperID(ctx context.Context, developerID uuid.UUID) error {
	_, err := repo.db.Delete_DeveloperOauthClient_By_DeveloperId(ctx, dbx.DeveloperOauthClient_DeveloperId(developerID[:]))
	return err
}

// Helper to convert DBX to console struct
func toConsoleOAuthClient(dbxClient *dbx.DeveloperOauthClient) *console.DeveloperOAuthClient {
	id, _ := uuid.FromBytes(dbxClient.Id)
	developerID, _ := uuid.FromBytes(dbxClient.DeveloperId)
	return &console.DeveloperOAuthClient{
		ID:           id,
		DeveloperID:  developerID,
		ClientID:     dbxClient.ClientId,
		ClientSecret: dbxClient.ClientSecret,
		Name:         dbxClient.Name,
		RedirectURIs: strings.Split(dbxClient.RedirectUris, ","),
		Status:       dbxClient.Status,
		CreatedAt:    dbxClient.CreatedAt,
		UpdatedAt:    dbxClient.UpdatedAt,
	}
}
