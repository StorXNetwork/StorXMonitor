package satellitedb

import (
	"context"
	"time"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/satellitedb/dbx"
)

type oauth2Requests struct {
	db *satelliteDB
}

var _ console.OAuth2Requests = (*oauth2Requests)(nil)

func (repo *oauth2Requests) Insert(ctx context.Context, req *console.OAuth2Request) (*console.OAuth2Request, error) {
	dbxReq, err := repo.db.Create_Oauth2Request(
		ctx,
		dbx.Oauth2Request_Id(req.ID[:]),
		dbx.Oauth2Request_ClientId(req.ClientID),
		dbx.Oauth2Request_UserId(req.UserID[:]),
		dbx.Oauth2Request_RedirectUri(req.RedirectURI),
		dbx.Oauth2Request_Scopes(req.Scopes),
		dbx.Oauth2Request_Status(req.Status),
		dbx.Oauth2Request_ConsentExpiresAt(req.ConsentExpiresAt),
		dbx.Oauth2Request_Code(req.Code),
		dbx.Oauth2Request_CodeExpiresAt(req.CodeExpiresAt),
		dbx.Oauth2Request_ApprovedScopes(req.ApprovedScopes),
		dbx.Oauth2Request_RejectedScopes(req.RejectedScopes),
	)
	if err != nil {
		return nil, err
	}
	return toConsoleOAuth2Request(dbxReq), nil
}

func (repo *oauth2Requests) Get(ctx context.Context, id uuid.UUID) (*console.OAuth2Request, error) {
	dbxReq, err := repo.db.Get_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]))
	if err != nil {
		return nil, err
	}
	return toConsoleOAuth2Request(dbxReq), nil
}

func (repo *oauth2Requests) UpdateStatus(ctx context.Context, id uuid.UUID, status int, code string) error {
	fields := dbx.Oauth2Request_Update_Fields{
		Status: dbx.Oauth2Request_Status(status),
		Code:   dbx.Oauth2Request_Code(code),
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

func (repo *oauth2Requests) UpdateConsent(ctx context.Context, id uuid.UUID, status int, code, approvedScopes, rejectedScopes string, codeExpiresAt time.Time) error {
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx,
		dbx.Oauth2Request_Id(id[:]),
		dbx.Oauth2Request_Update_Fields{
			Status:         dbx.Oauth2Request_Status(status),
			Code:           dbx.Oauth2Request_Code(code),
			ApprovedScopes: dbx.Oauth2Request_ApprovedScopes(approvedScopes),
			RejectedScopes: dbx.Oauth2Request_RejectedScopes(rejectedScopes),
			CodeExpiresAt:  dbx.Oauth2Request_CodeExpiresAt(codeExpiresAt),
		},
	)
	return err
}

func (repo *oauth2Requests) UpdateConsentExpiry(ctx context.Context, id uuid.UUID, consentExpiresAt time.Time) error {
	fields := dbx.Oauth2Request_Update_Fields{
		ConsentExpiresAt: dbx.Oauth2Request_ConsentExpiresAt(consentExpiresAt),
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

func (repo *oauth2Requests) UpdateCodeAndExpiry(ctx context.Context, id uuid.UUID, code string, codeExpiresAt time.Time) error {
	fields := dbx.Oauth2Request_Update_Fields{
		Code:          dbx.Oauth2Request_Code(code),
		CodeExpiresAt: dbx.Oauth2Request_CodeExpiresAt(codeExpiresAt),
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

func (repo *oauth2Requests) GetByCode(ctx context.Context, code string) (*console.OAuth2Request, error) {
	dbxReq, err := repo.db.Get_Oauth2Request_By_Code(ctx, dbx.Oauth2Request_Code(code))
	if err != nil {
		return nil, err
	}
	return toConsoleOAuth2Request(dbxReq), nil
}

func (repo *oauth2Requests) MarkCodeUsed(ctx context.Context, id uuid.UUID) error {
	fields := dbx.Oauth2Request_Update_Fields{
		Status: dbx.Oauth2Request_Status(2), // 2 = used
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

// Conversion helper
func toConsoleOAuth2Request(d *dbx.Oauth2Request) *console.OAuth2Request {
	id, _ := uuid.FromBytes(d.Id)
	userID, _ := uuid.FromBytes(d.UserId)
	return &console.OAuth2Request{
		ID:               id,
		ClientID:         d.ClientId,
		UserID:           userID,
		RedirectURI:      d.RedirectUri,
		Scopes:           d.Scopes,
		Status:           d.Status,
		CreatedAt:        d.CreatedAt,
		ConsentExpiresAt: d.ConsentExpiresAt,
		Code:             d.Code,
		CodeExpiresAt:    d.CodeExpiresAt,
		ApprovedScopes:   d.ApprovedScopes,
		RejectedScopes:   d.RejectedScopes,
	}
}
