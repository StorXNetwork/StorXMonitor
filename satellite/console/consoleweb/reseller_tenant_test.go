// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/StorXMonitor/satellite/tenancy"
	"github.com/StorXNetwork/common/uuid"
)

type stubResellerTenantDB struct {
	seller.DB
	domain   *seller.ResellerDomain
	config   *seller.ResellerConfig
	reseller *seller.Reseller
	theme    stubThemeDB
}

func (s stubResellerTenantDB) ResellerDomains() seller.ResellerDomains {
	return stubResellerTenantDomains{domain: s.domain}
}

func (s stubResellerTenantDB) ResellerConfigs() seller.ResellerConfigs {
	return stubResellerTenantConfigs{config: s.config}
}

func (s stubResellerTenantDB) Resellers() seller.Resellers {
	return stubResellerTenantResellers{reseller: s.reseller}
}

func (s stubResellerTenantDB) ThemePresets() seller.ThemePresets {
	return s.theme.ThemePresets()
}

func (s stubResellerTenantDB) ResellerThemes() seller.ResellerThemes {
	return s.theme.ResellerThemes()
}

type stubResellerTenantDomains struct {
	domain *seller.ResellerDomain
}

func (s stubResellerTenantDomains) Get(ctx context.Context, id uuid.UUID) (*seller.ResellerDomain, error) {
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantDomains) GetByResellerID(ctx context.Context, resellerID uuid.UUID) (*seller.ResellerDomain, error) {
	if s.domain != nil && s.domain.ResellerID == resellerID {
		return s.domain, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantDomains) GetByDomain(ctx context.Context, domain string) (*seller.ResellerDomain, error) {
	if s.domain != nil && s.domain.Domain == domain {
		return s.domain, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantDomains) Insert(ctx context.Context, domain *seller.ResellerDomain) (*seller.ResellerDomain, error) {
	return domain, nil
}

func (s stubResellerTenantDomains) Update(ctx context.Context, resellerID uuid.UUID, update seller.UpdateResellerDomainRequest) (*seller.ResellerDomain, error) {
	return nil, nil
}

type stubResellerTenantConfigs struct {
	config *seller.ResellerConfig
}

func (s stubResellerTenantConfigs) Get(ctx context.Context, id uuid.UUID) (*seller.ResellerConfig, error) {
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantConfigs) GetByResellerID(ctx context.Context, resellerID uuid.UUID) (*seller.ResellerConfig, error) {
	if s.config != nil && s.config.ResellerID == resellerID {
		return s.config, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantConfigs) Insert(ctx context.Context, config *seller.ResellerConfig) (*seller.ResellerConfig, error) {
	return config, nil
}

func (s stubResellerTenantConfigs) Update(ctx context.Context, resellerID uuid.UUID, update seller.UpdateResellerConfigRequest) (*seller.ResellerConfig, error) {
	return nil, nil
}

func (s stubResellerTenantConfigs) DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) error {
	return nil
}

type stubResellerTenantResellers struct {
	reseller *seller.Reseller
}

func (s stubResellerTenantResellers) Get(ctx context.Context, id uuid.UUID) (*seller.Reseller, error) {
	if s.reseller != nil && s.reseller.ID == id {
		return s.reseller, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantResellers) GetByEmail(ctx context.Context, email string) (*seller.Reseller, error) {
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantResellers) GetByEmailAnyStatus(ctx context.Context, email string) (*seller.Reseller, error) {
	return nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantResellers) GetByEmailWithUnverified(ctx context.Context, email string) (verified *seller.Reseller, unverified []seller.Reseller, err error) {
	return nil, nil, seller.ErrNotFound.New("")
}

func (s stubResellerTenantResellers) Insert(ctx context.Context, reseller *seller.Reseller) (*seller.Reseller, error) {
	return reseller, nil
}

func (s stubResellerTenantResellers) Update(ctx context.Context, id uuid.UUID, update seller.UpdateResellerRequest) (*seller.Reseller, error) {
	return nil, nil
}

func TestResellerTenantResolverBranding(t *testing.T) {
	resellerID, err := uuid.FromString("33333333-3333-3333-3333-333333333333")
	require.NoError(t, err)
	presetID, err := uuid.FromString("00000000-0000-4000-8000-000000000001")
	require.NoError(t, err)

	company := "Acme Corp"
	store := stubResellerTenantDB{
		domain: &seller.ResellerDomain{
			ResellerID: resellerID,
			Domain:     "portal.acme.com",
			Status:     seller.DomainStatusActive,
		},
		config: &seller.ResellerConfig{
			ResellerID:      resellerID,
			ActiveThemeType: seller.ActiveThemeTypeSystem,
			ActiveThemeID:   &presetID,
			Config:          []byte(`{"brandName":"Acme Cloud","supportEmail":"support@acme.com","logo":{"main":"logo.svg"}}`),
		},
		reseller: &seller.Reseller{
			ID:          resellerID,
			CompanyName: &company,
		},
		theme: stubThemeDB{
			preset: seller.ThemePreset{
				ID:   presetID,
				Slug: seller.FallbackThemePresetSlug,
				Colors: seller.ResellerBrandingTheme{
					Primary: "#0149FF",
				},
			},
		},
	}

	resolver := NewResellerTenantResolver(store, "http://localhost:10003")
	ctx := context.Background()

	branding, ok := resolver.ResellerMailBranding(ctx, resellerID)
	require.True(t, ok)
	require.Equal(t, "Acme Cloud", branding.BrandName)
	require.Equal(t, "Acme Corp", branding.CompanyName)
	require.Equal(t, "mailto:support@acme.com", branding.SupportURL)
	require.Equal(t, "#0149FF", branding.PrimaryColor)
	require.Equal(t, "http://localhost:10003/api/v0/seller/branding/assets/33333333-3333-3333-3333-333333333333/logo.svg", branding.LogoURL)
	require.Equal(t, "https://portal.acme.com/", resolver.ResellerExternalAddress(ctx, resellerID))

	smtpCfg, ok := resolver.ResellerMailSMTP(ctx, resellerID)
	require.False(t, ok)

	store.config.Config = []byte(`{
		"brandName":"Acme Cloud",
		"supportEmail":"support@acme.com",
		"logo":{"main":"logo.svg"},
		"mail":{
			"from":"Acme <noreply@acme.com>",
			"smtpServerAddress":"smtp.gmail.com:587",
			"authType":"login",
			"login":"noreply@acme.com",
			"password":"app-password"
		}
	}`)
	smtpCfg, ok = resolver.ResellerMailSMTP(ctx, resellerID)
	require.True(t, ok)
	require.Equal(t, "smtp.gmail.com:587", smtpCfg.SMTPServerAddress)
	require.Equal(t, "login", smtpCfg.AuthType)
	require.Equal(t, "noreply@acme.com", smtpCfg.Login)
	require.Equal(t, "app-password", smtpCfg.Password)
}

func TestServiceExternalAddressUsesResolver(t *testing.T) {
	resellerID, err := uuid.FromString("44444444-4444-4444-4444-444444444444")
	require.NoError(t, err)

	resolver := NewResellerTenantResolver(stubResellerTenantDB{
		domain: &seller.ResellerDomain{
			ResellerID: resellerID,
			Domain:     "portal.beta.com",
			Status:     seller.DomainStatusActive,
		},
	}, "")

	svc := &console.Service{}
	svc.SetResellerTenantLookup(resolver)

	ctx := tenancy.WithContext(context.Background(), &tenancy.Context{
		TenantID:   resellerID.String(),
		ResellerID: resellerID,
	})

	require.Equal(t, "https://portal.beta.com/", svc.ExternalAddressForContext(ctx))
}

func TestExternalAddressFromDomain(t *testing.T) {
	require.Equal(t, "https://portal.acme.com/", externalAddressFromDomain("portal.acme.com"))
	require.Equal(t, "", externalAddressFromDomain(""))
}