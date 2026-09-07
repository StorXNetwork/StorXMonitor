// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

// SellerBranding exposes reseller branding configuration endpoints.
type SellerBranding struct {
	log     *zap.Logger
	service *Service
	assets  *BrandingAssets
}

// NewSellerBranding creates a seller branding HTTP handler.
func NewSellerBranding(log *zap.Logger, service *Service, assets *BrandingAssets) *SellerBranding {
	if log == nil {
		log = zap.NewNop()
	}
	return &SellerBranding{
		log:     log,
		service: service,
		assets:  assets,
	}
}

// CreateBranding creates branding config for the authenticated reseller.
//
// @Summary      Create reseller branding
// @Description  **Route:** `POST /api/v0/seller/branding/create`. Requires complete SMTP mail settings first (`POST /seller/mail-settings/test` or `PUT /seller/mail-settings`). Multipart: `brandName`, `supportEmail`, `theme` (JSON or individual `themePrimary`, `themeSecondary`, `themeBackground`, `themeSidebar`), files `logoMain`, `logoSmall`, `favicon`. Page title uses `brandName`. Assets stored locally; GET returns public URLs under `/api/v0/seller/branding/assets/{resellerId}/{file}`.
// @Tags         reseller-branding
// @Accept       mpfd
// @Accept       json
// @Produce      json
// @Success      201  {object}  ResellerBrandingConfig
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      409  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/branding/create [post]
func (b *SellerBranding) CreateBranding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	cfg, files, err := b.parseBrandingRequest(r)
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	resellerID, err := b.currentResellerID(r)
	if err != nil {
		serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	if err := b.applyBrandingUploads(resellerID, &cfg, files); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	if err := b.service.CreateBrandingForCurrentReseller(ctx, cfg); err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err), ErrMailNotConfigured.Has(err):
			status = http.StatusBadRequest
		case ErrBrandingAlreadyExists.Has(err):
			status = http.StatusConflict
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(enrichBrandingConfigURLs(cfg, resellerID))
}

// GetBranding returns branding for the authenticated reseller.
//
// @Summary      Get reseller branding
// @Description  **Route:** `GET /api/v0/seller/branding`. Logo/favicon fields are public asset URLs.
// @Tags         reseller-branding
// @Produce      json
// @Success      200  {object}  ResellerBrandingConfig
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      404  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/branding [get]
func (b *SellerBranding) GetBranding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	resellerID, err := b.currentResellerID(r)
	if err != nil {
		serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	cfg, err := b.service.GetBrandingViewForCurrentReseller(ctx)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrBrandingNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	view := enrichBrandingViewURLs(cfg, resellerID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// UpdateBranding updates branding for the authenticated reseller.
//
// @Summary      Update reseller branding
// @Description  **Route:** `PUT /api/v0/seller/branding/update`. Requires complete SMTP mail settings. Same multipart fields as create. Omit file fields to keep existing assets.
// @Tags         reseller-branding
// @Accept       mpfd
// @Accept       json
// @Produce      json
// @Success      200  {object}  ResellerBrandingConfig
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      404  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/branding/update [put]
func (b *SellerBranding) UpdateBranding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	cfg, files, err := b.parseBrandingRequest(r)
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	resellerID, err := b.currentResellerID(r)
	if err != nil {
		serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	existing, err := b.service.GetBrandingForCurrentReseller(ctx)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrBrandingNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	cfg = mergeBrandingConfig(existing, cfg)

	if err := b.applyBrandingUploads(resellerID, &cfg, files); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	if err := b.service.UpdateBrandingForCurrentReseller(ctx, cfg); err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err), ErrMailNotConfigured.Has(err):
			status = http.StatusBadRequest
		case ErrBrandingNotFound.Has(err):
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrichBrandingConfigURLs(cfg, resellerID))
}

// DeleteBranding deletes branding config and uploaded assets for the authenticated reseller.
//
// @Summary      Delete reseller branding
// @Description  **Route:** `DELETE /api/v0/seller/branding/delete`. Removes config and local logo/favicon files.
// @Tags         reseller-branding
// @Produce      json
// @Success      200
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      404  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/branding/delete [delete]
func (b *SellerBranding) DeleteBranding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	resellerID, err := b.currentResellerID(r)
	if err != nil {
		serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	if err := b.service.DeleteBrandingForCurrentReseller(ctx); err != nil {
		status := http.StatusInternalServerError
		if ErrBrandingNotFound.Has(err) || ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	if b.assets != nil {
		if err := b.assets.DeleteResellerAssets(resellerID); err != nil {
			b.log.Warn("failed to delete branding assets", zap.Error(err))
		}
	}
}

// ServeBrandingAsset serves a stored branding asset (public, no auth).
func (b *SellerBranding) ServeBrandingAsset(w http.ResponseWriter, r *http.Request) {
	if b.assets == nil {
		http.NotFound(w, r)
		return
	}

	vars := mux.Vars(r)
	resellerID, err := uuid.FromString(vars["resellerId"])
	if err != nil {
		http.NotFound(w, r)
		return
	}

	b.assets.Serve(w, r, resellerID, vars["filename"])
}

// ListThemePresets returns system theme presets.
//
// @Summary      List system theme presets
// @Description  **Route:** `GET /api/v0/seller/themes/presets`
// @Tags         reseller-branding
// @Produce      json
// @Success      200  {array}   ThemePresetSummary
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/themes/presets [get]
func (b *SellerBranding) ListThemePresets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if _, err := b.currentResellerID(r); err != nil {
		serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	presets, err := b.service.ListThemePresets(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(presets)
}

// ListCustomThemes returns custom themes for the authenticated reseller.
//
// @Summary      List custom themes
// @Description  **Route:** `GET /api/v0/seller/themes/custom`. Max 5 per reseller.
// @Tags         reseller-branding
// @Produce      json
// @Success      200  {array}   CustomThemeSummary
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/themes/custom [get]
func (b *SellerBranding) ListCustomThemes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if _, err := b.currentResellerID(r); err != nil {
		serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	themes, err := b.service.ListCustomThemesForCurrentReseller(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(themes)
}

// CreateCustomTheme creates a custom theme.
//
// @Summary      Create custom theme
// @Description  **Route:** `POST /api/v0/seller/themes/custom`. Body colors: primary, secondary, background, sidebar only. Max 5 custom themes per reseller.
// @Tags         reseller-branding
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCustomThemeRequest  true  "Custom theme"
// @Success      201   {object}  ResellerCustomTheme
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Failure      409   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/themes/custom [post]
func (b *SellerBranding) CreateCustomTheme(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var req CreateCustomThemeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	created, err := b.service.CreateCustomThemeForCurrentReseller(ctx, req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err):
			status = http.StatusBadRequest
		case ErrCustomThemeLimit.Has(err), ErrThemeNameInUse.Has(err):
			status = http.StatusConflict
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

// UpdateCustomTheme updates a custom theme.
//
// @Summary      Update custom theme
// @Description  **Route:** `PUT /api/v0/seller/themes/custom/{id}`
// @Tags         reseller-branding
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Theme ID"
// @Param        body  body      UpdateCustomThemeRequest  true  "Custom theme"
// @Success      200   {object}  ResellerCustomTheme
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Failure      404   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/themes/custom/{id} [put]
func (b *SellerBranding) UpdateCustomTheme(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	themeID, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid theme id"))
		return
	}

	var req UpdateCustomThemeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	updated, err := b.service.UpdateCustomThemeForCurrentReseller(ctx, themeID, req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err):
			status = http.StatusBadRequest
		case ErrThemeNameInUse.Has(err):
			status = http.StatusConflict
		case ErrNotFound.Has(err):
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

// DeleteCustomTheme deletes a custom theme that is not currently active.
//
// @Summary      Delete custom theme
// @Description  **Route:** `DELETE /api/v0/seller/themes/custom/{id}`
// @Tags         reseller-branding
// @Produce      json
// @Param        id  path  string  true  "Theme ID"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      404  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/themes/custom/{id} [delete]
func (b *SellerBranding) DeleteCustomTheme(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	themeID, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid theme id"))
		return
	}

	if err := b.service.DeleteCustomThemeForCurrentReseller(ctx, themeID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err), ErrActiveThemeInUse.Has(err):
			status = http.StatusBadRequest
		case ErrNotFound.Has(err):
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}
}

// SetActiveTheme sets the active theme for the reseller portal.
//
// @Summary      Set active theme
// @Description  **Route:** `PUT /api/v0/seller/branding/active-theme`. Body: `{ "type": "system"|"custom", "id": "uuid" }`
// @Tags         reseller-branding
// @Accept       json
// @Produce      json
// @Param        body  body      SetActiveThemeRequest  true  "Active theme"
// @Success      200
// @Failure      400  {object}  SellerAuthErrorResponse
// @Failure      401  {object}  SellerAuthErrorResponse
// @Failure      404  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/branding/active-theme [put]
func (b *SellerBranding) SetActiveTheme(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var req SetActiveThemeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	if err := b.service.SetActiveThemeForCurrentReseller(ctx, req); err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err):
			status = http.StatusBadRequest
		case ErrBrandingNotFound.Has(err), ErrNotFound.Has(err):
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}
}
