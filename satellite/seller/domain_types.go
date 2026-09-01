// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import "time"

// ConnectDomainRequest is the body for POST /seller/domain/connect.
type ConnectDomainRequest struct {
	Domain string `json:"domain" example:"portal.acme.com"`
}

// UpdateDomainRequest is the body for PUT /seller/domain/update.
type UpdateDomainRequest struct {
	Domain string `json:"domain" example:"portal.acme.com"`
}

// ResellerDomainResponse is returned from seller domain routes.
type ResellerDomainResponse struct {
	ID                 string     `json:"id"`
	Domain             string     `json:"domain"`
	DomainType         string     `json:"domainType"`
	Status             string     `json:"status"`
	VerificationStatus string     `json:"verificationStatus"`
	SSLStatus          string     `json:"sslStatus"`
	VerifiedAt         *time.Time `json:"verifiedAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}

func domainToResponse(domain *ResellerDomain) ResellerDomainResponse {
	if domain == nil {
		return ResellerDomainResponse{}
	}
	return ResellerDomainResponse{
		ID:                 domain.ID.String(),
		Domain:             domain.Domain,
		DomainType:         domain.DomainType,
		Status:             domain.Status,
		VerificationStatus: domain.VerificationStatus,
		SSLStatus:          domain.SSLStatus,
		VerifiedAt:         domain.VerifiedAt,
		CreatedAt:          domain.CreatedAt,
		UpdatedAt:          domain.UpdatedAt,
	}
}
