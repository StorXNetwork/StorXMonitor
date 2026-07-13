// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/resellerbranding"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

type stubThemeDB struct {
	seller.DB
	preset seller.ThemePreset
}

func (s stubThemeDB) ThemePresets() seller.ThemePresets {
	return stubThemePresets{preset: s.preset}
}

func (s stubThemeDB) ResellerThemes() seller.ResellerThemes {
	return stubResellerThemes{}
}

type stubThemePresets struct {
	preset seller.ThemePreset
}

func (s stubThemePresets) List(ctx context.Context) ([]seller.ThemePreset, error) {
	return []seller.ThemePreset{s.preset}, nil
}

func (s stubThemePresets) Get(ctx context.Context, id uuid.UUID) (*seller.ThemePreset, error) {
	if id == s.preset.ID {
		return &s.preset, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubThemePresets) GetBySlug(ctx context.Context, slug string) (*seller.ThemePreset, error) {
	if slug == s.preset.Slug {
		return &s.preset, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubThemePresets) GetByName(ctx context.Context, name string) (*seller.ThemePreset, error) {
	if name == s.preset.Name {
		return &s.preset, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubThemePresets) GetDefault(ctx context.Context) (*seller.ThemePreset, error) {
	return &s.preset, nil
}

func (s stubThemePresets) Insert(ctx context.Context, preset *seller.ThemePreset) (*seller.ThemePreset, error) {
	return preset, nil
}

type stubResellerThemes struct{}

func (stubResellerThemes) ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]seller.ResellerCustomTheme, error) {
	return nil, nil
}

func (stubResellerThemes) CountByResellerID(ctx context.Context, resellerID uuid.UUID) (int, error) {
	return 0, nil
}

func (stubResellerThemes) Get(ctx context.Context, id uuid.UUID) (*seller.ResellerCustomTheme, error) {
	return nil, seller.ErrNotFound.New("")
}

func (stubResellerThemes) GetByResellerID(ctx context.Context, resellerID, id uuid.UUID) (*seller.ResellerCustomTheme, error) {
	return nil, seller.ErrNotFound.New("")
}

func (stubResellerThemes) GetByResellerIDAndName(ctx context.Context, resellerID uuid.UUID, name string) (*seller.ResellerCustomTheme, error) {
	return nil, seller.ErrNotFound.New("")
}

func (stubResellerThemes) Insert(ctx context.Context, theme *seller.ResellerCustomTheme) (*seller.ResellerCustomTheme, error) {
	return nil, nil
}

func (stubResellerThemes) Update(ctx context.Context, id uuid.UUID, name string, colors seller.ResellerBrandingTheme, updatedAt time.Time) (*seller.ResellerCustomTheme, error) {
	return nil, nil
}

func (stubResellerThemes) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (stubResellerThemes) DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) error {
	return nil
}

func TestBrandingFromResellerConfig(t *testing.T) {
	resellerID, err := uuid.FromString("11111111-1111-1111-1111-111111111111")
	require.NoError(t, err)

	presetID, err := uuid.FromString("00000000-0000-4000-8000-000000000001")
	require.NoError(t, err)

	store := stubThemeDB{
		preset: seller.ThemePreset{
			ID:   presetID,
			Slug: seller.FallbackThemePresetSlug,
			Name: "CyberLS Default",
			Colors: seller.ResellerBrandingTheme{
				Primary:    "#0149FF",
				Secondary:  "#06B6D4",
				Background: "#F8FAFC",
				Sidebar:    "#0F172A",
			},
		},
	}

	dbCfg := &seller.ResellerConfig{
		ResellerID:      resellerID,
		ActiveThemeType: seller.ActiveThemeTypeSystem,
		ActiveThemeID:   &presetID,
		Config:          []byte(`{"brandName":"Acme Cloud","supportEmail":"support@acme.com"}`),
	}

	branding, err := brandingFromResellerConfig(context.Background(), store, seller.ResellerBrandingConfig{
		BrandName:    "Acme Cloud",
		SupportEmail: "support@acme.com",
		Logo: map[string]string{
			"main":  "acme_logo_main.svg",
			"small": "acme_logo_small.svg",
		},
		Favicon: "acme_favicon.ico",
	}, dbCfg, resellerID, "http://localhost:10003")
	require.NoError(t, err)

	require.Equal(t, "Acme Cloud", branding.Name)
	require.Equal(t, "mailto:support@acme.com", branding.SupportURL)
	require.Equal(t, "http://localhost:10003/api/v0/seller/branding/assets/11111111-1111-1111-1111-111111111111/acme_logo_main.svg", branding.LogoURLs["main"])
	require.Equal(t, "#0149FF", branding.Colors["primary"])
	require.Equal(t, seller.ActiveThemeTypeSystem, branding.ThemeMode)
	require.Equal(t, "CyberLS Default", branding.ThemeName)
}

func TestHostBrandingCache(t *testing.T) {
	cache := resellerbranding.NewHostCache(time.Minute)
	cache.Set("portal.acme.com", []byte(`{"name":"Acme"}`))

	payload, ok := cache.Get("portal.acme.com")
	require.True(t, ok)
	require.JSONEq(t, `{"name":"Acme"}`, string(payload))

	cache.Delete("portal.acme.com")
	_, ok = cache.Get("portal.acme.com")
	require.False(t, ok)
}

func TestNormalizeHost(t *testing.T) {
	require.Equal(t, "portal.acme.com", resellerbranding.NormalizeHost("Portal.Acme.com:443"))
}
