// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// SellerDomain exposes reseller custom domain endpoints.
type SellerDomain struct {
	log     *zap.Logger
	service *Service
}

// NewSellerDomain creates a seller domain HTTP handler.
func NewSellerDomain(log *zap.Logger, service *Service) *SellerDomain {
	if log == nil {
		log = zap.NewNop()
	}
	return &SellerDomain{
		log:     log,
		service: service,
	}
}

// GetDomain returns the custom domain for the authenticated reseller.
//
// @Summary      Get reseller domain
// @Description  **Route:** `GET /api/v0/seller/domain`. Returns 404 if no domain is connected yet.
// @Tags         reseller-domain
// @Produce      json
// @Success      200  {object}  ResellerDomainResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      404  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/domain [get]
func (d *SellerDomain) GetDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	domain, err := d.service.GetDomainForCurrentReseller(ctx)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrDomainNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(domainToResponse(domain))
}

// ConnectDomain creates a custom domain row for the authenticated reseller.
//
// @Summary      Connect custom domain
// @Description  **Route:** `POST /api/v0/seller/domain/connect`. Creates reseller_domains row with status active, verification verified, and SSL issued. No DNS validation (manual ops).
// @Tags         reseller-domain
// @Accept       json
// @Produce      json
// @Param        body  body  ConnectDomainRequest  true  "Custom domain hostname"
// @Success      201   {object}  ResellerDomainResponse
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Failure      409   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/domain/connect [post]
func (d *SellerDomain) ConnectDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body ConnectDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.Wrap(err))
		return
	}

	domain, err := d.service.ConnectCustomDomainForCurrentReseller(ctx, body.Domain)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err):
			status = http.StatusBadRequest
		case ErrDomainAlreadyExists.Has(err):
			status = http.StatusConflict
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(domainToResponse(domain))
}

// UpdateDomain updates the custom domain for the authenticated reseller.
//
// @Summary      Update reseller domain
// @Description  **Route:** `PUT /api/v0/seller/domain/update`. Updates the single custom domain row. Sets status active, verification verified, and SSL issued. No DNS validation (manual ops).
// @Tags         reseller-domain
// @Accept       json
// @Produce      json
// @Param        body  body  UpdateDomainRequest  true  "Custom domain hostname"
// @Success      200   {object}  ResellerDomainResponse
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Failure      404   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/domain/update [put]
func (d *SellerDomain) UpdateDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body UpdateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.Wrap(err))
		return
	}

	domain, err := d.service.UpdateCustomDomainForCurrentReseller(ctx, body.Domain)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err):
			status = http.StatusBadRequest
		case ErrDomainNotFound.Has(err):
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(domainToResponse(domain))
}
