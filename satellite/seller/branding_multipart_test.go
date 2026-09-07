// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/uuid"
)

func TestValidateThemeColors(t *testing.T) {
	err := validateThemeColors(ResellerBrandingTheme{Primary: "#2563EB"})
	require.NoError(t, err)

	err = validateThemeColors(ResellerBrandingTheme{})
	require.Error(t, err)

	err = validateThemeColors(ResellerBrandingTheme{Primary: "red"})
	require.Error(t, err)
}

func TestResellerBrandingThemeIsEmpty(t *testing.T) {
	require.True(t, ResellerBrandingTheme{}.IsEmpty())
	require.False(t, ResellerBrandingTheme{Primary: "#fff"}.IsEmpty())
}

type themeTestDB struct {
	preset  ThemePreset
	custom  []ResellerCustomTheme
	configs map[uuid.UUID]*ResellerConfig
}

func (d *themeTestDB) Resellers() Resellers                          { return nil }
func (d *themeTestDB) ResellerConfigs() ResellerConfigs              { return nil }
func (d *themeTestDB) ResellerDomains() ResellerDomains              { return nil }
func (d *themeTestDB) WebappSessionResellers() WebappSessionResellers { return nil }
func (d *themeTestDB) ResetPasswordTokens() ResellerResetPasswordTokens { return nil }
func (d *themeTestDB) ResellerDeleteRequests() ResellerDeleteRequests { return nil }

func (d *themeTestDB) ThemePresets() ThemePresets { return &themeTestPresets{preset: d.preset} }
func (d *themeTestDB) ResellerThemes() ResellerThemes {
	return &themeTestCustomThemes{themes: d.custom}
}

type themeTestPresets struct {
	preset ThemePreset
}

func (p *themeTestPresets) List(ctx context.Context) ([]ThemePreset, error) {
	return []ThemePreset{p.preset}, nil
}

func (p *themeTestPresets) Get(ctx context.Context, id uuid.UUID) (*ThemePreset, error) {
	if id == p.preset.ID {
		return &p.preset, nil
	}
	return nil, ErrNotFound.New("")
}

func (p *themeTestPresets) GetBySlug(ctx context.Context, slug string) (*ThemePreset, error) {
	if slug == p.preset.Slug {
		return &p.preset, nil
	}
	return nil, ErrNotFound.New("")
}

func (p *themeTestPresets) GetByName(ctx context.Context, name string) (*ThemePreset, error) {
	if name == p.preset.Name {
		return &p.preset, nil
	}
	return nil, ErrNotFound.New("")
}

func (p *themeTestPresets) GetDefault(ctx context.Context) (*ThemePreset, error) {
	return &p.preset, nil
}

func (p *themeTestPresets) Insert(ctx context.Context, preset *ThemePreset) (*ThemePreset, error) {
	return preset, nil
}

type themeTestCustomThemes struct {
	themes []ResellerCustomTheme
}

func (t *themeTestCustomThemes) ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]ResellerCustomTheme, error) {
	return t.themes, nil
}

func (t *themeTestCustomThemes) CountByResellerID(ctx context.Context, resellerID uuid.UUID) (int, error) {
	return len(t.themes), nil
}

func (t *themeTestCustomThemes) Get(ctx context.Context, id uuid.UUID) (*ResellerCustomTheme, error) {
	for i := range t.themes {
		if t.themes[i].ID == id {
			return &t.themes[i], nil
		}
	}
	return nil, ErrNotFound.New("")
}

func (t *themeTestCustomThemes) GetByResellerID(ctx context.Context, resellerID, id uuid.UUID) (*ResellerCustomTheme, error) {
	theme, err := t.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if theme.ResellerID != resellerID {
		return nil, ErrNotFound.New("")
	}
	return theme, nil
}

func (t *themeTestCustomThemes) GetByResellerIDAndName(ctx context.Context, resellerID uuid.UUID, name string) (*ResellerCustomTheme, error) {
	for i := range t.themes {
		if t.themes[i].ResellerID == resellerID && t.themes[i].Name == name {
			return &t.themes[i], nil
		}
	}
	return nil, ErrNotFound.New("")
}

func (t *themeTestCustomThemes) Insert(ctx context.Context, theme *ResellerCustomTheme) (*ResellerCustomTheme, error) {
	t.themes = append(t.themes, *theme)
	return theme, nil
}

func (t *themeTestCustomThemes) Update(ctx context.Context, id uuid.UUID, name string, colors ResellerBrandingTheme, updatedAt time.Time) (*ResellerCustomTheme, error) {
	for i := range t.themes {
		if t.themes[i].ID == id {
			t.themes[i].Name = name
			t.themes[i].Colors = colors
			return &t.themes[i], nil
		}
	}
	return nil, ErrNotFound.New("")
}

func (t *themeTestCustomThemes) Delete(ctx context.Context, id uuid.UUID) error {
	for i := range t.themes {
		if t.themes[i].ID == id {
			t.themes = append(t.themes[:i], t.themes[i+1:]...)
			return nil
		}
	}
	return ErrNotFound.New("")
}

func (t *themeTestCustomThemes) DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) error {
	t.themes = nil
	return nil
}

func TestResolveActiveThemeSystemPreset(t *testing.T) {
	presetID, err := uuid.FromString("00000000-0000-4000-8000-000000000011")
	require.NoError(t, err)
	store := &themeTestDB{
		preset: ThemePreset{
			ID:   presetID,
			Slug: FallbackThemePresetSlug,
			Name: "Modern Blue",
			Colors: ResellerBrandingTheme{
				Primary: "#2563EB",
			},
		},
	}

	dbCfg := &ResellerConfig{
		ActiveThemeType: ActiveThemeTypeSystem,
		ActiveThemeID:   &presetID,
		Config:          json.RawMessage(`{"brandName":"Acme"}`),
	}

	view, err := ResolveActiveTheme(context.Background(), store, dbCfg)
	require.NoError(t, err)
	require.Equal(t, ActiveThemeTypeSystem, view.Type)
	require.Equal(t, "Modern Blue", view.Name)
	require.Equal(t, "#2563EB", view.Colors.Primary)
}

func TestResolveActiveThemeCustom(t *testing.T) {
	customID, err := uuid.New()
	require.NoError(t, err)
	resellerID, err := uuid.New()
	require.NoError(t, err)
	defaultID, err := uuid.New()
	require.NoError(t, err)
	store := &themeTestDB{
		preset: ThemePreset{ID: defaultID, Slug: FallbackThemePresetSlug, Name: "Modern Blue"},
		custom: []ResellerCustomTheme{{
			ID:         customID,
			ResellerID: resellerID,
			Name:       "My Blue",
			Colors:     ResellerBrandingTheme{Primary: "#0000FF"},
		}},
	}

	dbCfg := &ResellerConfig{
		ActiveThemeType: ActiveThemeTypeCustom,
		ActiveThemeID:   &customID,
		Config:          json.RawMessage(`{"brandName":"Acme"}`),
	}

	view, err := ResolveActiveTheme(context.Background(), store, dbCfg)
	require.NoError(t, err)
	require.Equal(t, ActiveThemeTypeCustom, view.Type)
	require.Equal(t, "My Blue", view.Name)
	require.Equal(t, "#0000FF", view.Colors.Primary)
}

func TestResolveActiveThemeLegacyJSONFallback(t *testing.T) {
	defaultID, err := uuid.New()
	require.NoError(t, err)
	store := &themeTestDB{
		preset: ThemePreset{
			ID:     defaultID,
			Slug:   FallbackThemePresetSlug,
			Name:   "Modern Blue",
			Colors: ResellerBrandingTheme{Primary: "#2563EB"},
		},
	}

	cfg, err := json.Marshal(ResellerBrandingConfig{
		BrandName: "Acme",
		Theme:     ResellerBrandingTheme{Primary: "#FF0000"},
	})
	require.NoError(t, err)

	dbCfg := &ResellerConfig{Config: cfg}

	view, err := ResolveActiveTheme(context.Background(), store, dbCfg)
	require.NoError(t, err)
	require.Equal(t, ActiveThemeTypeCustom, view.Type)
	require.Equal(t, "#FF0000", view.Colors.Primary)
}

func TestParseResellerBrandingThemeJSON(t *testing.T) {
	theme, err := parseResellerBrandingThemeJSON([]byte(`{
		"primary":"#2563EB",
		"secondary":"#06B6D4",
		"background":"#F8FAFC",
		"sidebar":"#0F172A"
	}`))
	require.NoError(t, err)
	require.Equal(t, "#2563EB", theme.Primary)
	require.Equal(t, "#06B6D4", theme.Secondary)
	require.Equal(t, "#F8FAFC", theme.Background)
	require.Equal(t, "#0F172A", theme.Sidebar)
}

func TestParseResellerBrandingThemeJSONLegacyKeys(t *testing.T) {
	theme, err := parseResellerBrandingThemeJSON([]byte(`{
		"sidebarHighlight":"#aeecf4",
		"sidebar":"#001f66",
		"background":"#fafbff",
		"text":"#fa0000",
		"textMuted":"#c19a9a"
	}`))
	require.NoError(t, err)
	require.Equal(t, "#aeecf4", theme.Primary)
	require.Equal(t, "", theme.Secondary)
	require.Equal(t, "#fafbff", theme.Background)
	require.Equal(t, "#001f66", theme.Sidebar)
}

func TestMergeBrandingConfigKeepsExistingThemeFields(t *testing.T) {
	existing := ResellerBrandingConfig{
		BrandName:    "Smart Byte Labs",
		SupportEmail: "support@example.com",
		Logo: map[string]string{
			"main": "logo-main.svg",
		},
		Favicon: "favicon.svg",
		Theme: ResellerBrandingTheme{
			Primary:    "#2563EB",
			Secondary:  "#06B6D4",
			Sidebar:    "#0F172A",
			Background: "#fafbff",
		},
	}

	incoming := ResellerBrandingConfig{
		BrandName: "Smart Byte Labs",
		Theme: ResellerBrandingTheme{
			Background: "#eeff05",
		},
	}

	merged := mergeBrandingConfig(existing, incoming)

	require.Equal(t, "#eeff05", merged.Theme.Background)
	require.Equal(t, "#06B6D4", merged.Theme.Secondary)
	require.Equal(t, "#0F172A", merged.Theme.Sidebar)
	require.Equal(t, "#2563EB", merged.Theme.Primary)
	require.Equal(t, "logo-main.svg", merged.Logo["main"])
	require.Equal(t, "favicon.svg", merged.Favicon)
	require.Equal(t, "support@example.com", merged.SupportEmail)
}
