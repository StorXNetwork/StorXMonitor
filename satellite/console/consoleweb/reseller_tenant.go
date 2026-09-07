// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"fmt"
	"strings"

	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

// ResellerTenantResolver implements console.ResellerTenantLookup using seller DB.
type ResellerTenantResolver struct {
	store              seller.DB
	sellerExternalBase string
}

// NewResellerTenantResolver returns a lookup backed by reseller_domains and reseller_configs.
func NewResellerTenantResolver(store seller.DB, sellerExternalBase string) *ResellerTenantResolver {
	return &ResellerTenantResolver{
		store:              store,
		sellerExternalBase: strings.TrimRight(strings.TrimSpace(sellerExternalBase), "/"),
	}
}

// ResellerExternalAddress returns the public URL for a reseller's active domain.
func (r *ResellerTenantResolver) ResellerExternalAddress(ctx context.Context, resellerID uuid.UUID) string {
	if r.store == nil {
		return ""
	}
	domain, err := r.store.ResellerDomains().GetByResellerID(ctx, resellerID)
	if err != nil {
		return ""
	}
	return externalAddressFromDomain(domain.Domain)
}

// ResellerMailBranding loads email branding for a reseller.
func (r *ResellerTenantResolver) ResellerMailBranding(ctx context.Context, resellerID uuid.UUID) (mailservice.WhiteLabelConfig, bool) {
	if r.store == nil {
		return mailservice.WhiteLabelConfig{}, false
	}

	dbCfg, err := r.store.ResellerConfigs().GetByResellerID(ctx, resellerID)
	if err != nil {
		return mailservice.WhiteLabelConfig{}, false
	}

	cfg, err := seller.ParseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return mailservice.WhiteLabelConfig{}, false
	}

	active, err := seller.ResolveActiveTheme(ctx, r.store, dbCfg)
	if err != nil {
		return mailservice.WhiteLabelConfig{}, false
	}

	brandName := strings.TrimSpace(cfg.BrandName)
	if brandName == "" {
		brandName = "CyberLS"
	}

	companyName := brandName
	if reseller, err := r.store.Resellers().Get(ctx, resellerID); err == nil && reseller.CompanyName != nil {
		if name := strings.TrimSpace(*reseller.CompanyName); name != "" {
			companyName = name
		}
	}

	homepage := strings.TrimRight(r.ResellerExternalAddress(ctx, resellerID), "/")
	supportURL := ""
	if email := strings.TrimSpace(cfg.SupportEmail); email != "" {
		supportURL = "mailto:" + email
	}

	logoURL := resellerMailLogoURL(r.sellerExternalBase, resellerID, cfg.Logo["main"])

	return mailservice.WhiteLabelConfig{
		BrandName:    brandName,
		LogoURL:      logoURL,
		HomepageURL:  homepage,
		SupportURL:   supportURL,
		PrimaryColor: active.Colors.Primary,
		CompanyName:  companyName,
	}, true
}

// ResellerMailSMTP returns seller-dashboard SMTP settings when complete for the reseller.
func (r *ResellerTenantResolver) ResellerMailSMTP(ctx context.Context, resellerID uuid.UUID) (mailservice.Config, bool) {
	if r.store == nil || resellerID == (uuid.UUID{}) {
		return mailservice.Config{}, false
	}
	dbCfg, err := r.store.ResellerConfigs().GetByResellerID(ctx, resellerID)
	if err != nil {
		return mailservice.Config{}, false
	}
	cfg, err := seller.ParseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return mailservice.Config{}, false
	}
	return cfg.Mail.ToMailConfig()
}

func externalAddressFromDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	addr := "https://" + domain
	if !strings.HasSuffix(addr, "/") {
		addr += "/"
	}
	return addr
}

func resellerMailLogoURL(sellerBase string, resellerID uuid.UUID, storedFilename string) string {
	storedFilename = strings.TrimSpace(storedFilename)
	if storedFilename == "" {
		return ""
	}
	if strings.HasPrefix(storedFilename, "http://") || strings.HasPrefix(storedFilename, "https://") {
		return storedFilename
	}
	const assetsPath = "/api/v0/seller/branding/assets"
	if strings.HasPrefix(storedFilename, "/") {
		if sellerBase == "" {
			return storedFilename
		}
		return sellerBase + storedFilename
	}
	if sellerBase == "" {
		return fmt.Sprintf("%s/%s/%s", assetsPath, resellerID.String(), storedFilename)
	}
	return fmt.Sprintf("%s%s/%s/%s", sellerBase, assetsPath, resellerID.String(), storedFilename)
}
