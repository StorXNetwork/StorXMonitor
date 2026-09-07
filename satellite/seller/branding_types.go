// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/StorXNetwork/common/uuid"
)

// ResellerBrandingConfig is stored in reseller_configs.config (JSON).
// Logo/favicon values are filenames on disk; GET responses return public asset URLs.
// Mail SMTP settings are managed via /seller/mail-settings and omitted from branding GET responses.
type ResellerBrandingConfig struct {
	BrandName    string                `json:"brandName"`
	SupportEmail string                `json:"supportEmail"`
	Logo         map[string]string     `json:"logo"`
	Favicon      string                `json:"favicon"`
	Theme        ResellerBrandingTheme `json:"theme"`
	Mail         *ResellerMailSettings `json:"mail,omitempty"`
}

// ResellerBrandingTheme contains seller-configured brand colors.
// Sellers configure only primary, secondary, background, and sidebar.
// Text / hover / soft colors are computed by the UI, not the backend.
type ResellerBrandingTheme struct {
	Primary    string `json:"primary"`
	Secondary  string `json:"secondary"`
	Background string `json:"background"`
	Sidebar    string `json:"sidebar"`
}

const (
	brandingLogoMain  = "main"
	brandingLogoSmall = "small"
	brandingFavicon   = "favicon"
)

func normalizeBrandingConfig(cfg *ResellerBrandingConfig) {
	if cfg.Logo == nil {
		cfg.Logo = map[string]string{}
	}
}

// ParseBrandingConfigJSON parses reseller branding config JSON from reseller_configs.
func ParseBrandingConfigJSON(data []byte) (ResellerBrandingConfig, error) {
	return parseBrandingConfigJSON(data)
}

func parseBrandingConfigJSON(data []byte) (ResellerBrandingConfig, error) {
	var raw struct {
		BrandName    string                 `json:"brandName"`
		SupportEmail string                 `json:"supportEmail"`
		Logo         map[string]string      `json:"logo"`
		Favicon      json.RawMessage        `json:"favicon"`
		Theme        json.RawMessage        `json:"theme"`
		Mail         *ResellerMailSettings  `json:"mail"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ResellerBrandingConfig{}, err
	}

	theme, err := parseResellerBrandingThemeJSON(raw.Theme)
	if err != nil {
		return ResellerBrandingConfig{}, err
	}

	cfg := ResellerBrandingConfig{
		BrandName:    raw.BrandName,
		SupportEmail: raw.SupportEmail,
		Logo:         raw.Logo,
		Theme:        theme,
		Mail:         raw.Mail,
	}
	cfg.Favicon = parseStoredFavicon(raw.Favicon)
	normalizeBrandingConfig(&cfg)
	return cfg, nil
}

func parseResellerBrandingThemeJSON(data []byte) (ResellerBrandingTheme, error) {
	if len(data) == 0 {
		return ResellerBrandingTheme{}, nil
	}
	var themeMap map[string]string
	if err := json.Unmarshal(data, &themeMap); err != nil {
		return ResellerBrandingTheme{}, err
	}
	return resellerBrandingThemeFromMap(themeMap), nil
}

func resellerBrandingThemeFromMap(m map[string]string) ResellerBrandingTheme {
	first := func(keys ...string) string {
		for _, key := range keys {
			if v := strings.TrimSpace(m[key]); v != "" {
				return v
			}
		}
		return ""
	}
	return ResellerBrandingTheme{
		Primary:    first("primary", "sidebarHighlight"),
		Secondary:  first("secondary"),
		Background: first("background"),
		Sidebar:    first("sidebar"),
	}
}

// ThemeFromColorMap builds a theme from a flat color map (legacy JSON keys supported).
func ThemeFromColorMap(m map[string]string) ResellerBrandingTheme {
	return resellerBrandingThemeFromMap(m)
}

func parseStoredFavicon(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var filename string
	if err := json.Unmarshal(raw, &filename); err == nil {
		return strings.TrimSpace(filename)
	}
	var legacy map[string]string
	if err := json.Unmarshal(raw, &legacy); err == nil {
		for _, key := range []string{"32", "16", "appleTouch", "main"} {
			if v := strings.TrimSpace(legacy[key]); v != "" {
				return v
			}
		}
		for _, v := range legacy {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return ""
}

const (
	// MaxCustomThemesPerReseller is the maximum number of custom themes a reseller may save.
	MaxCustomThemesPerReseller = 5

	// ActiveThemeTypeSystem uses a row from theme_presets.
	ActiveThemeTypeSystem = "system"
	// ActiveThemeTypeCustom uses a row from reseller_themes.
	ActiveThemeTypeCustom = "custom"

	// FallbackThemePresetSlug is used when no active theme is set and no preset is marked default.
	FallbackThemePresetSlug = "modern-blue"
)

var hexColorPattern = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// ThemePreset is a system-wide theme available to all resellers.
type ThemePreset struct {
	ID          uuid.UUID
	Slug        string
	Name        string
	Description *string
	Colors      ResellerBrandingTheme
	IsSystem    bool
}

// ResellerCustomTheme is a seller-defined theme (max 5 per reseller).
type ResellerCustomTheme struct {
	ID         uuid.UUID
	ResellerID uuid.UUID
	Name       string
	Colors     ResellerBrandingTheme
}

// ActiveThemeInfo describes the theme currently applied to a reseller portal.
type ActiveThemeInfo struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug,omitempty"`
}

// ActiveThemeView is the resolved active theme returned in branding APIs.
type ActiveThemeView struct {
	ActiveThemeInfo
	Colors ResellerBrandingTheme `json:"colors"`
}

// CustomThemeSummary is a list item for seller custom themes.
type CustomThemeSummary struct {
	ID     string                `json:"id"`
	Name   string                `json:"name"`
	Colors ResellerBrandingTheme `json:"colors"`
}

// CreateCustomThemeRequest is the body for POST /seller/themes/custom.
type CreateCustomThemeRequest struct {
	Name   string                `json:"name"`
	Colors ResellerBrandingTheme `json:"colors"`
}

// UpdateCustomThemeRequest is the body for PUT /seller/themes/custom/{id}.
type UpdateCustomThemeRequest struct {
	Name   string                `json:"name"`
	Colors ResellerBrandingTheme `json:"colors"`
}

// SetActiveThemeRequest is the body for PUT /seller/branding/active-theme.
type SetActiveThemeRequest struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ResellerBrandingView extends branding config with resolved theme state.
type ResellerBrandingView struct {
	ResellerBrandingConfig
	ActiveTheme        ActiveThemeView      `json:"activeTheme"`
	CustomThemes       []CustomThemeSummary `json:"customThemes"`
	CustomThemeCount   int                  `json:"customThemeCount"`
	CustomThemeLimit   int                  `json:"customThemeLimit"`
	SystemThemePresets []ThemePresetSummary `json:"systemThemePresets,omitempty"`
}

// ThemePresetSummary is a read-only system preset for the seller UI.
type ThemePresetSummary struct {
	ID          string                `json:"id"`
	Slug        string                `json:"slug"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Colors      ResellerBrandingTheme `json:"colors"`
}

func themeColorsToJSON(theme ResellerBrandingTheme) (json.RawMessage, error) {
	return json.Marshal(theme)
}

func themeColorsFromJSON(data json.RawMessage) (ResellerBrandingTheme, error) {
	if len(data) == 0 {
		return ResellerBrandingTheme{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return ResellerBrandingTheme{}, err
	}
	return resellerBrandingThemeFromMap(m), nil
}

func validateThemeColors(theme ResellerBrandingTheme) error {
	check := func(field, value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if !hexColorPattern.MatchString(value) {
			return ErrValidation.New("%s must be a hex color (#RGB or #RRGGBB)", field)
		}
		return nil
	}
	for field, value := range map[string]string{
		"primary":    theme.Primary,
		"secondary":  theme.Secondary,
		"background": theme.Background,
		"sidebar":    theme.Sidebar,
	} {
		if err := check(field, value); err != nil {
			return err
		}
	}
	if theme.IsEmpty() {
		return ErrValidation.New("at least one theme color is required (primary, secondary, background, or sidebar)")
	}
	return nil
}

// IsEmpty reports whether no seller-configurable theme colors are set.
func (t ResellerBrandingTheme) IsEmpty() bool {
	return strings.TrimSpace(t.Primary) == "" &&
		strings.TrimSpace(t.Secondary) == "" &&
		strings.TrimSpace(t.Background) == "" &&
		strings.TrimSpace(t.Sidebar) == ""
}

func validateCustomThemeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ErrValidation.New("name is required")
	}
	if len(name) > 64 {
		return "", ErrValidation.New("name must be at most 64 characters")
	}
	return name, nil
}

// ResolveActiveTheme loads the active theme colors and metadata for a reseller config row.
func ResolveActiveTheme(ctx context.Context, store DB, dbCfg *ResellerConfig) (ActiveThemeView, error) {
	if dbCfg == nil {
		return ActiveThemeView{}, ErrBrandingNotFound.New("branding configuration not found")
	}

	themeType := strings.TrimSpace(dbCfg.ActiveThemeType)
	if themeType == "" {
		themeType = ActiveThemeTypeSystem
	}

	if dbCfg.ActiveThemeID != nil && !dbCfg.ActiveThemeID.IsZero() {
		view, resolveErr := resolveThemeByTypeAndID(ctx, store, themeType, *dbCfg.ActiveThemeID)
		if resolveErr == nil {
			return view, nil
		}
		if !ErrNotFound.Has(resolveErr) {
			return ActiveThemeView{}, resolveErr
		}
	}

	brandingCfg, err := parseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return ActiveThemeView{}, Error.Wrap(err)
	}

	if !brandingCfg.Theme.IsEmpty() {
		return ActiveThemeView{
			ActiveThemeInfo: ActiveThemeInfo{
				Type: ActiveThemeTypeCustom,
				Name: "Custom",
			},
			Colors: brandingCfg.Theme,
		}, nil
	}

	preset, err := store.ThemePresets().GetDefault(ctx)
	if err != nil {
		return ActiveThemeView{}, Error.Wrap(err)
	}
	return activeThemeViewFromPreset(*preset), nil
}

func resolveThemeByTypeAndID(ctx context.Context, store DB, themeType string, themeID uuid.UUID) (ActiveThemeView, error) {
	switch themeType {
	case ActiveThemeTypeCustom:
		theme, err := store.ResellerThemes().Get(ctx, themeID)
		if err != nil {
			return ActiveThemeView{}, err
		}
		return activeThemeViewFromCustom(*theme), nil
	default:
		preset, err := store.ThemePresets().Get(ctx, themeID)
		if err != nil {
			return ActiveThemeView{}, err
		}
		return activeThemeViewFromPreset(*preset), nil
	}
}

func activeThemeViewFromPreset(preset ThemePreset) ActiveThemeView {
	return ActiveThemeView{
		ActiveThemeInfo: ActiveThemeInfo{
			Type: ActiveThemeTypeSystem,
			ID:   preset.ID.String(),
			Name: preset.Name,
			Slug: preset.Slug,
		},
		Colors: preset.Colors,
	}
}

func activeThemeViewFromCustom(theme ResellerCustomTheme) ActiveThemeView {
	return ActiveThemeView{
		ActiveThemeInfo: ActiveThemeInfo{
			Type: ActiveThemeTypeCustom,
			ID:   theme.ID.String(),
			Name: theme.Name,
		},
		Colors: theme.Colors,
	}
}

func presetSummaries(presets []ThemePreset) []ThemePresetSummary {
	out := make([]ThemePresetSummary, 0, len(presets))
	for _, preset := range presets {
		desc := ""
		if preset.Description != nil {
			desc = strings.TrimSpace(*preset.Description)
		}
		out = append(out, ThemePresetSummary{
			ID:          preset.ID.String(),
			Slug:        preset.Slug,
			Name:        preset.Name,
			Description: desc,
			Colors:      preset.Colors,
		})
	}
	return out
}

func customThemeSummaries(themes []ResellerCustomTheme) []CustomThemeSummary {
	out := make([]CustomThemeSummary, 0, len(themes))
	for _, theme := range themes {
		out = append(out, CustomThemeSummary{
			ID:     theme.ID.String(),
			Name:   theme.Name,
			Colors: theme.Colors,
		})
	}
	return out
}
