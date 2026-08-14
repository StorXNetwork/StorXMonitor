// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/StorXNetwork/StorXMonitor/satellite/resellerbranding"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

const brandingAssetsURLPath = "/api/v0/seller/branding/assets"

func requestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); host != "" {
		if first, _, _ := strings.Cut(host, ","); first != "" {
			return resellerbranding.NormalizeHost(strings.TrimSpace(first))
		}
	}
	return resellerbranding.NormalizeHost(r.Host)
}

func (server *Server) isMainConsoleHost(host string) bool {
	host = resellerbranding.NormalizeHost(host)
	if host == "" {
		return true
	}

	candidates := []string{
		hostFromAddress(server.config.ExternalAddress),
		hostFromAddress(server.config.FrontendAddress),
		hostFromAddress(server.config.ClientOrigin),
		"localhost",
		"127.0.0.1",
	}
	for _, candidate := range candidates {
		if candidate != "" && host == candidate {
			return true
		}
	}
	return false
}

func hostFromAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return resellerbranding.NormalizeHost(raw)
	}
	if u.Host != "" {
		return resellerbranding.NormalizeHost(u.Host)
	}
	return resellerbranding.NormalizeHost(u.Path)
}

func (server *Server) sellerExternalBaseURL() string {
	base := strings.TrimSpace(server.config.SellerExternalAddress)
	if base == "" {
		base = strings.TrimSpace(server.config.ExternalAddress)
	}
	return strings.TrimRight(base, "/")
}

func (server *Server) resellerBrandingForHost(ctx context.Context, host string) (BrandingConfig, bool, error) {
	if server.sellerDB == nil || host == "" || server.isMainConsoleHost(host) {
		return BrandingConfig{}, false, nil
	}

	domain, err := server.sellerDB.ResellerDomains().GetByDomain(ctx, host)
	if err != nil {
		if seller.ErrNotFound.Has(err) {
			return BrandingConfig{}, false, nil
		}
		return BrandingConfig{}, false, Error.Wrap(err)
	}
	if domain.Status != seller.DomainStatusActive {
		return BrandingConfig{}, false, nil
	}

	dbCfg, err := server.sellerDB.ResellerConfigs().GetByResellerID(ctx, domain.ResellerID)
	if err != nil {
		if seller.ErrNotFound.Has(err) {
			return BrandingConfig{}, false, nil
		}
		return BrandingConfig{}, false, Error.Wrap(err)
	}

	cfg, err := seller.ParseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return BrandingConfig{}, false, Error.Wrap(err)
	}

	branding, err := brandingFromResellerConfig(ctx, server.sellerDB, cfg, dbCfg, domain.ResellerID, server.sellerExternalBaseURL())
	if err != nil {
		return BrandingConfig{}, false, err
	}
	return branding, true, nil
}

func brandingFromResellerConfig(ctx context.Context, store seller.DB, cfg seller.ResellerBrandingConfig, dbCfg *seller.ResellerConfig, resellerID uuid.UUID, sellerBase string) (BrandingConfig, error) {
	branding := BrandingConfig{}
	if name := strings.TrimSpace(cfg.BrandName); name != "" {
		branding.Name = name
	}

	logoMain := resellerBrandingAssetURL(sellerBase, resellerID, cfg.Logo["main"])
	logoSmall := resellerBrandingAssetURL(sellerBase, resellerID, cfg.Logo["small"])
	if logoMain != "" {
		branding.LogoURLs = map[string]string{
			"main":  logoMain,
			"small": logoSmallOr(logoSmall, logoMain),
		}
	}
	if favicon := resellerBrandingAssetURL(sellerBase, resellerID, cfg.Favicon); favicon != "" {
		branding.FaviconURL = favicon
	}

	active, err := seller.ResolveActiveTheme(ctx, store, dbCfg)
	if err != nil {
		return BrandingConfig{}, Error.Wrap(err)
	}
	branding.ThemeMode = active.Type
	branding.ThemeName = active.Name

	colors := map[string]string{}
	addColor := func(key, value string) {
		if v := strings.TrimSpace(value); v != "" {
			colors[key] = v
		}
	}
	addColor("primary", active.Colors.Primary)
	addColor("secondary", active.Colors.Secondary)
	addColor("background", active.Colors.Background)
	addColor("sidebar", active.Colors.Sidebar)
	if len(colors) > 0 {
		branding.Colors = colors
	}

	if email := strings.TrimSpace(cfg.SupportEmail); email != "" {
		branding.SupportURL = "mailto:" + email
	}
	return branding, nil
}

func logoSmallOr(small, main string) string {
	if small != "" {
		return small
	}
	return main
}

func resellerBrandingAssetURL(sellerBase string, resellerID uuid.UUID, storedFilename string) string {
	storedFilename = strings.TrimSpace(storedFilename)
	if storedFilename == "" {
		return ""
	}
	if strings.HasPrefix(storedFilename, "http://") || strings.HasPrefix(storedFilename, "https://") {
		return storedFilename
	}
	if strings.HasPrefix(storedFilename, "/") {
		if sellerBase == "" {
			return storedFilename
		}
		return sellerBase + storedFilename
	}
	if sellerBase == "" {
		return fmt.Sprintf("%s/%s/%s", brandingAssetsURLPath, resellerID.String(), storedFilename)
	}
	return fmt.Sprintf("%s%s/%s/%s", sellerBase, brandingAssetsURLPath, resellerID.String(), storedFilename)
}
