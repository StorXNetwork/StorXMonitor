// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "time"

// Swagger models and documentation stubs for the access tag.

// V1AccessCreateSwaggerRequest is the body for POST /v1/access (StorX auth service).
type V1AccessCreateSwaggerRequest struct {
	AccessGrant string `json:"access_grant" example:"serialized-access-grant"`
	Public      bool   `json:"public" example:"false"`
}

// V1AccessCreateSwaggerResponse is returned by POST /v1/access.
type V1AccessCreateSwaggerResponse struct {
	AccessKeyID string `json:"access_key_id" example:"AKIA..."`
	SecretKey   string `json:"secret_key" example:"..."`
	Endpoint    string `json:"endpoint" example:"https://storx.io"`
}

// APIKeyListItemSwagger is one API key in GET /api/v0/api-keys/list-paged.
type APIKeyListItemSwagger struct {
	ID           string    `json:"id" example:"00000000-0000-0000-0000-000000000000"`
	ProjectID    string    `json:"projectId" example:"00000000-0000-0000-0000-000000000000"`
	CreatorEmail string    `json:"creatorEmail" example:"user@example.com"`
	Name         string    `json:"name" example:"my-key"`
	CreatedAt    time.Time `json:"createdAt"`
	Version      int       `json:"version" example:"2"`
}

// APIKeysListPagedSwaggerResponse is returned by GET /api/v0/api-keys/list-paged.
type APIKeysListPagedSwaggerResponse struct {
	APIKeys        []APIKeyListItemSwagger `json:"apiKeys"`
	Search         string                  `json:"search" example:""`
	Limit          uint                    `json:"limit" example:"10"`
	Order          uint                    `json:"order" example:"1"`
	OrderDirection uint                    `json:"orderDirection" example:"1"`
	Offset         uint64                  `json:"offset" example:"0"`
	PageCount      uint                    `json:"pageCount" example:"1"`
	CurrentPage    uint                    `json:"currentPage" example:"1"`
	TotalCount     uint64                  `json:"totalCount" example:"3"`
}

// CreateV1AccessDoc documents POST /v1/access (implemented on the StorX auth host, not the console /api/v0 router).
//
// @Summary      Exchange access grant for S3 credentials
// @Description  **Full route:** `POST /v1/access` (server root on the StorX auth host, e.g. `https://storx.io/v1/access`).
//
// Exchanges a serialized access grant for S3-compatible credentials (`access_key_id`, `secret_key`, `endpoint`). Not served under `/api/v0`.
// @Tags         access
// @Accept       json
// @Produce      json
// @Param        body  body  V1AccessCreateSwaggerRequest  true  "Access grant and visibility"
// @Success      200   {object}  V1AccessCreateSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Router       /v1/access [post]
func CreateV1AccessDoc() {}
