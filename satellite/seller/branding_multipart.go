// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

type brandingUploadFiles struct {
	LogoMain  *multipart.FileHeader
	LogoSmall *multipart.FileHeader
	Favicon   *multipart.FileHeader
}

func parseBrandingMultipart(r *http.Request) (ResellerBrandingConfig, brandingUploadFiles, error) {
	if err := r.ParseMultipartForm(maxBrandingAssetSize * 4); err != nil {
		return ResellerBrandingConfig{}, brandingUploadFiles{}, ErrValidation.New("invalid multipart form data (use FormData for file uploads; do not set Content-Type manually)")
	}

	cfg := ResellerBrandingConfig{
		BrandName:    strings.TrimSpace(r.FormValue("brandName")),
		SupportEmail: strings.TrimSpace(r.FormValue("supportEmail")),
	}

	if err := parseBrandingThemeForm(r, &cfg.Theme); err != nil {
		return ResellerBrandingConfig{}, brandingUploadFiles{}, err
	}

	files := brandingUploadFiles{}
	if f, fh, err := r.FormFile("logoMain"); err == nil {
		f.Close()
		if fh.Size > 0 {
			files.LogoMain = fh
		}
	}
	if f, fh, err := r.FormFile("logoSmall"); err == nil {
		f.Close()
		if fh.Size > 0 {
			files.LogoSmall = fh
		}
	}
	if f, fh, err := r.FormFile("favicon"); err == nil {
		f.Close()
		if fh.Size > 0 {
			files.Favicon = fh
		}
	}

	normalizeBrandingConfig(&cfg)
	return cfg, files, nil
}

func (b *SellerBranding) applyBrandingUploads(resellerID uuid.UUID, cfg *ResellerBrandingConfig, files brandingUploadFiles) error {
	if b.assets == nil {
		return ErrValidation.New("branding asset storage is not configured")
	}

	type logoUploadSpec struct {
		header *multipart.FileHeader
		key    string
		mapKey string
	}

	logoSpecs := []logoUploadSpec{
		{files.LogoMain, "logo_main", brandingLogoMain},
		{files.LogoSmall, "logo_small", brandingLogoSmall},
	}

	for _, spec := range logoSpecs {
		if spec.header == nil {
			continue
		}
		if previous := cfg.Logo[spec.mapKey]; previous != "" {
			if err := b.assets.DeleteFile(resellerID, previous); err != nil {
				b.log.Warn("failed to delete replaced branding asset", zap.String("file", previous), zap.Error(err))
			}
		}
		file, err := spec.header.Open()
		if err != nil {
			return Error.Wrap(err)
		}
		stored, err := b.assets.Save(resellerID, spec.key, spec.header.Filename, spec.header.Header.Get("Content-Type"), file)
		_ = file.Close()
		if err != nil {
			return err
		}
		cfg.Logo[spec.mapKey] = stored
	}

	if files.Favicon != nil {
		if cfg.Favicon != "" {
			if err := b.assets.DeleteFile(resellerID, cfg.Favicon); err != nil {
				b.log.Warn("failed to delete replaced branding asset", zap.String("file", cfg.Favicon), zap.Error(err))
			}
		}
		file, err := files.Favicon.Open()
		if err != nil {
			return Error.Wrap(err)
		}
		stored, err := b.assets.Save(resellerID, brandingFavicon, files.Favicon.Filename, files.Favicon.Header.Get("Content-Type"), file)
		_ = file.Close()
		if err != nil {
			return err
		}
		cfg.Favicon = stored
	}

	return nil
}

func mergeBrandingAssets(existing, incoming ResellerBrandingConfig) ResellerBrandingConfig {
	return mergeBrandingConfig(existing, incoming)
}

func mergeBrandingConfig(existing, incoming ResellerBrandingConfig) ResellerBrandingConfig {
	if len(existing.Logo) > 0 {
		if incoming.Logo == nil {
			incoming.Logo = map[string]string{}
		}
		for k, v := range existing.Logo {
			if incoming.Logo[k] == "" {
				incoming.Logo[k] = v
			}
		}
	}
	if incoming.Favicon == "" {
		incoming.Favicon = existing.Favicon
	}
	if strings.TrimSpace(incoming.SupportEmail) == "" {
		incoming.SupportEmail = existing.SupportEmail
	}
	mergeThemeString := func(dst *string, fallback string) {
		if strings.TrimSpace(*dst) == "" {
			*dst = fallback
		}
	}
	mergeThemeString(&incoming.Theme.Primary, existing.Theme.Primary)
	mergeThemeString(&incoming.Theme.Secondary, existing.Theme.Secondary)
	mergeThemeString(&incoming.Theme.Background, existing.Theme.Background)
	mergeThemeString(&incoming.Theme.Sidebar, existing.Theme.Sidebar)
	return incoming
}

func (b *SellerBranding) parseBrandingRequest(r *http.Request) (ResellerBrandingConfig, brandingUploadFiles, error) {
	if isBrandingMultipartRequest(r) {
		return parseBrandingMultipart(r)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ResellerBrandingConfig{}, brandingUploadFiles{}, Error.Wrap(err)
	}
	cfg, err := parseBrandingConfigJSON(body)
	if err != nil {
		return ResellerBrandingConfig{}, brandingUploadFiles{}, ErrValidation.New(
			"invalid JSON body (for file uploads send multipart/form-data with FormData; do not set Content-Type: application/json)",
		)
	}
	return cfg, brandingUploadFiles{}, nil
}

func isBrandingMultipartRequest(r *http.Request) bool {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		return true
	}
	if err := r.ParseMultipartForm(maxBrandingAssetSize * 4); err != nil {
		return false
	}
	if strings.TrimSpace(r.FormValue("brandName")) != "" {
		return true
	}
	for _, key := range []string{"logoMain", "logoSmall", "favicon"} {
		if _, _, err := r.FormFile(key); err == nil {
			return true
		}
	}
	return false
}

func parseBrandingThemeForm(r *http.Request, theme *ResellerBrandingTheme) error {
	if themeJSON := strings.TrimSpace(r.FormValue("theme")); themeJSON != "" {
		parsed, err := parseResellerBrandingThemeJSON([]byte(themeJSON))
		if err != nil {
			return ErrValidation.New("invalid theme JSON (colors must be quoted strings, e.g. {\"primary\":\"#2563EB\"})")
		}
		*theme = parsed
		return nil
	}

	setIfPresent := func(value *string, keys ...string) {
		for _, key := range keys {
			if v := strings.TrimSpace(r.FormValue(key)); v != "" {
				*value = v
				return
			}
		}
	}
	setIfPresent(&theme.Primary, "themePrimary", "theme.primary")
	setIfPresent(&theme.Secondary, "themeSecondary", "theme.secondary")
	setIfPresent(&theme.Background, "themeBackground", "theme.background")
	setIfPresent(&theme.Sidebar, "themeSidebar", "theme.sidebar")
	return nil
}

func (b *SellerBranding) currentResellerID(r *http.Request) (uuid.UUID, error) {
	reseller, err := GetReseller(r.Context())
	if err != nil {
		return uuid.UUID{}, err
	}
	return reseller.ID, nil
}
