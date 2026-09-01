// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"
)

type themePresetSeed struct {
	slug        string
	name        string
	description string
	colors      ResellerBrandingTheme
}

var themePresetSeeds = []themePresetSeed{
	{
		slug:        "modern-blue",
		name:        "Modern Blue",
		description: "Modern blue preset",
		colors: ResellerBrandingTheme{
			Primary: "#2563EB", Secondary: "#06B6D4", Sidebar: "#1E293B",
			Background: "#F8FAFC",
		},
	},
	{
		slug:        "emerald",
		name:        "Emerald",
		description: "Emerald green preset",
		colors: ResellerBrandingTheme{
			Primary: "#10B981", Secondary: "#059669", Sidebar: "#064E3B",
			Background: "#F9FAFB",
		},
	},
	{
		slug:        "purple-tech",
		name:        "Purple Tech",
		description: "Purple tech preset",
		colors: ResellerBrandingTheme{
			Primary: "#7C3AED", Secondary: "#A855F7", Sidebar: "#312E81",
			Background: "#FAF5FF",
		},
	},
	{
		slug:        "orange-startup",
		name:        "Orange Startup",
		description: "Orange startup preset",
		colors: ResellerBrandingTheme{
			Primary: "#F97316", Secondary: "#FB923C", Sidebar: "#7C2D12",
			Background: "#FFF7ED",
		},
	},
	{
		slug:        "crimson-pro",
		name:        "Crimson Pro",
		description: "Crimson pro preset",
		colors: ResellerBrandingTheme{
			Primary: "#DC2626", Secondary: "#EF4444", Sidebar: "#7F1D1D",
			Background: "#FEF2F2",
		},
	},
	{
		slug:        "indigo-cloud",
		name:        "Indigo Cloud",
		description: "Indigo cloud preset",
		colors: ResellerBrandingTheme{
			Primary: "#4F46E5", Secondary: "#6366F1", Sidebar: "#312E81",
			Background: "#EEF2FF",
		},
	},
	{
		slug:        "ocean",
		name:        "Ocean",
		description: "Ocean blue preset",
		colors: ResellerBrandingTheme{
			Primary: "#0284C7", Secondary: "#0EA5E9", Sidebar: "#0C4A6E",
			Background: "#F0F9FF",
		},
	},
	{
		slug:        "cyber-dark",
		name:        "Cyber Dark",
		description: "Cyber dark preset",
		colors: ResellerBrandingTheme{
			Primary: "#3B82F6", Secondary: "#06B6D4", Sidebar: "#111827",
			Background: "#0F172A",
		},
	},
	{
		slug:        "forest",
		name:        "Forest",
		description: "Forest green preset",
		colors: ResellerBrandingTheme{
			Primary: "#15803D", Secondary: "#22C55E", Sidebar: "#14532D",
			Background: "#F0FDF4",
		},
	},
	{
		slug:        "slate-minimal",
		name:        "Slate Minimal",
		description: "Slate minimal preset",
		colors: ResellerBrandingTheme{
			Primary: "#334155", Secondary: "#64748B", Sidebar: "#1E293B",
			Background: "#F8FAFC",
		},
	},
	{
		slug:        "sky-blue",
		name:        "Sky Blue",
		description: "Bright sky blue preset",
		colors: ResellerBrandingTheme{
			Primary: "#0EA5E9", Secondary: "#38BDF8", Sidebar: "#075985",
			Background: "#F0F9FF",
		},
	},
	{
		slug:        "teal-pro",
		name:        "Teal Pro",
		description: "Professional teal preset",
		colors: ResellerBrandingTheme{
			Primary: "#0F766E", Secondary: "#14B8A6", Sidebar: "#134E4A",
			Background: "#F0FDFA",
		},
	},
	{
		slug:        "rose-pink",
		name:        "Rose Pink",
		description: "Rose pink preset",
		colors: ResellerBrandingTheme{
			Primary: "#E11D48", Secondary: "#FB7185", Sidebar: "#881337",
			Background: "#FFF1F2",
		},
	},
	{
		slug:        "gold-premium",
		name:        "Gold Premium",
		description: "Gold premium preset",
		colors: ResellerBrandingTheme{
			Primary: "#CA8A04", Secondary: "#FACC15", Sidebar: "#713F12",
			Background: "#FEFCE8",
		},
	},
	{
		slug:        "coffee-brown",
		name:        "Coffee Brown",
		description: "Coffee brown preset",
		colors: ResellerBrandingTheme{
			Primary: "#92400E", Secondary: "#D97706", Sidebar: "#451A03",
			Background: "#FFFBEB",
		},
	},
	{
		slug:        "navy-enterprise",
		name:        "Navy Enterprise",
		description: "Navy enterprise preset",
		colors: ResellerBrandingTheme{
			Primary: "#1D4ED8", Secondary: "#60A5FA", Sidebar: "#1E3A8A",
			Background: "#EFF6FF",
		},
	},
	{
		slug:        "cyan-breeze",
		name:        "Cyan Breeze",
		description: "Cyan breeze preset",
		colors: ResellerBrandingTheme{
			Primary: "#0891B2", Secondary: "#22D3EE", Sidebar: "#164E63",
			Background: "#ECFEFF",
		},
	},
	{
		slug:        "magenta-studio",
		name:        "Magenta Studio",
		description: "Magenta studio preset",
		colors: ResellerBrandingTheme{
			Primary: "#C026D3", Secondary: "#E879F9", Sidebar: "#701A75",
			Background: "#FDF4FF",
		},
	},
	{
		slug:        "lime-fresh",
		name:        "Lime Fresh",
		description: "Lime fresh preset",
		colors: ResellerBrandingTheme{
			Primary: "#65A30D", Secondary: "#84CC16", Sidebar: "#365314",
			Background: "#F7FEE7",
		},
	},
	{
		slug:        "charcoal-professional",
		name:        "Charcoal Professional",
		description: "Charcoal professional preset",
		colors: ResellerBrandingTheme{
			Primary: "#475569", Secondary: "#94A3B8", Sidebar: "#0F172A",
			Background: "#F8FAFC",
		},
	},
}

// seedThemePresets ensures system theme presets exist on seller server startup.
func seedThemePresets(log *zap.Logger, store DB) {
	if log == nil {
		log = zap.NewNop()
	}
	if store == nil {
		log.Warn("skipping theme preset seeding: seller store is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, seed := range themePresetSeeds {
		if err := ensureThemePreset(ctx, log, store, seed); err != nil {
			log.Error("failed to seed theme preset",
				zap.String("slug", seed.slug),
				zap.Error(err))
		}
	}
}

func ensureThemePreset(ctx context.Context, log *zap.Logger, store DB, seed themePresetSeed) error {
	if _, err := store.ThemePresets().GetBySlug(ctx, seed.slug); err == nil {
		return nil
	} else if !ErrNotFound.Has(err) {
		return err
	}
	if _, err := store.ThemePresets().GetByName(ctx, seed.name); err == nil {
		return nil
	} else if !ErrNotFound.Has(err) {
		return err
	}

	description := seed.description
	created, err := store.ThemePresets().Insert(ctx, &ThemePreset{
		Slug:        seed.slug,
		Name:        seed.name,
		Description: &description,
		Colors:      seed.colors,
		IsSystem:    true,
	})
	if err != nil {
		if isDuplicateDBError(err) {
			return nil
		}
		return Error.Wrap(err)
	}

	log.Info("seeded theme preset",
		zap.String("slug", seed.slug),
		zap.String("name", seed.name),
		zap.String("id", created.ID.String()))
	return nil
}

func isDuplicateDBError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "duplicate") ||
		strings.Contains(errStr, "unique") ||
		strings.Contains(errStr, "already exists")
}
