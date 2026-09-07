// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

func (db *sellerDB) ThemePresets() seller.ThemePresets {
	return &themePresets{db: db.db}
}

func (db *sellerDB) ResellerThemes() seller.ResellerThemes {
	return &resellerThemes{db: db.db}
}

var _ seller.ThemePresets = (*themePresets)(nil)

type themePresets struct {
	db *satelliteDB
}

func (repo *themePresets) List(ctx context.Context) (_ []seller.ThemePreset, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_ThemePreset(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]seller.ThemePreset, 0, len(rows))
	for _, row := range rows {
		preset, convErr := themePresetFromDBX(row)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *preset)
	}
	return out, nil
}

func (repo *themePresets) Get(ctx context.Context, id uuid.UUID) (_ *seller.ThemePreset, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_ThemePreset_By_Id(ctx, dbx.ThemePreset_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return themePresetFromDBX(row)
}

func (repo *themePresets) GetBySlug(ctx context.Context, slug string) (_ *seller.ThemePreset, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_ThemePreset_By_Slug(ctx, dbx.ThemePreset_Slug(slug))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return themePresetFromDBX(row)
}

func (repo *themePresets) GetByName(ctx context.Context, name string) (_ *seller.ThemePreset, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_ThemePreset_By_Name(ctx, dbx.ThemePreset_Name(name))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return themePresetFromDBX(row)
}

func (repo *themePresets) GetDefault(ctx context.Context) (_ *seller.ThemePreset, err error) {
	defer mon.Task()(&ctx)(&err)

	if preset, slugErr := repo.GetBySlug(ctx, seller.FallbackThemePresetSlug); slugErr == nil {
		return preset, nil
	} else if !seller.ErrNotFound.Has(slugErr) {
		return nil, slugErr
	}

	list, listErr := repo.List(ctx)
	if listErr != nil {
		return nil, listErr
	}
	if len(list) == 0 {
		return nil, seller.ErrNotFound.New("")
	}
	return &list[0], nil
}

func (repo *themePresets) Insert(ctx context.Context, preset *seller.ThemePreset) (_ *seller.ThemePreset, err error) {
	defer mon.Task()(&ctx)(&err)

	if preset == nil {
		return nil, Error.New("theme preset is nil")
	}
	if preset.ID.IsZero() {
		id, genErr := uuid.New()
		if genErr != nil {
			return nil, Error.Wrap(genErr)
		}
		preset.ID = id
	}
	if strings.TrimSpace(preset.Slug) == "" {
		return nil, Error.New("theme preset slug is not set")
	}
	if strings.TrimSpace(preset.Name) == "" {
		return nil, Error.New("theme preset name is not set")
	}

	colorsJSON, err := themeColorsToDBX(preset.Colors)
	if err != nil {
		return nil, err
	}

	optional := dbx.ThemePreset_Create_Fields{
		IsSystem: dbx.ThemePreset_IsSystem(preset.IsSystem),
	}
	if preset.Description != nil {
		optional.Description = dbx.ThemePreset_Description(*preset.Description)
	}

	now := time.Now()
	created, err := repo.db.Create_ThemePreset(ctx,
		dbx.ThemePreset_Id(preset.ID[:]),
		dbx.ThemePreset_Slug(preset.Slug),
		dbx.ThemePreset_Name(preset.Name),
		dbx.ThemePreset_Colors(colorsJSON),
		dbx.ThemePreset_UpdatedAt(now),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return themePresetFromDBX(created)
}

func themePresetFromDBX(row *dbx.ThemePreset) (*seller.ThemePreset, error) {
	if row == nil {
		return nil, Error.New("theme preset parameter is nil")
	}
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	colors, err := themeColorsFromDBX(row.Colors)
	if err != nil {
		return nil, err
	}
	return &seller.ThemePreset{
		ID:          id,
		Slug:        row.Slug,
		Name:        row.Name,
		Description: row.Description,
		Colors:      colors,
		IsSystem:    row.IsSystem,
	}, nil
}

var _ seller.ResellerThemes = (*resellerThemes)(nil)

type resellerThemes struct {
	db *satelliteDB
}

func (repo *resellerThemes) ListByResellerID(ctx context.Context, resellerID uuid.UUID) (_ []seller.ResellerCustomTheme, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_ResellerTheme_By_ResellerId(ctx, dbx.ResellerTheme_ResellerId(resellerID[:]))
	if err != nil {
		return nil, err
	}
	out := make([]seller.ResellerCustomTheme, 0, len(rows))
	for _, row := range rows {
		theme, convErr := resellerThemeFromDBX(row)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *theme)
	}
	return out, nil
}

func (repo *resellerThemes) CountByResellerID(ctx context.Context, resellerID uuid.UUID) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	themes, err := repo.ListByResellerID(ctx, resellerID)
	if err != nil {
		return 0, err
	}
	return len(themes), nil
}

func (repo *resellerThemes) Get(ctx context.Context, id uuid.UUID) (_ *seller.ResellerCustomTheme, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_ResellerTheme_By_Id(ctx, dbx.ResellerTheme_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return resellerThemeFromDBX(row)
}

func (repo *resellerThemes) GetByResellerID(ctx context.Context, resellerID, id uuid.UUID) (_ *seller.ResellerCustomTheme, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_ResellerTheme_By_Id_And_ResellerId(ctx,
		dbx.ResellerTheme_Id(id[:]),
		dbx.ResellerTheme_ResellerId(resellerID[:]),
	)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return resellerThemeFromDBX(row)
}

func (repo *resellerThemes) GetByResellerIDAndName(ctx context.Context, resellerID uuid.UUID, name string) (_ *seller.ResellerCustomTheme, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_ResellerTheme_By_ResellerId_And_Name(ctx,
		dbx.ResellerTheme_ResellerId(resellerID[:]),
		dbx.ResellerTheme_Name(name),
	)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return resellerThemeFromDBX(row)
}

func (repo *resellerThemes) Insert(ctx context.Context, theme *seller.ResellerCustomTheme) (_ *seller.ResellerCustomTheme, err error) {
	defer mon.Task()(&ctx)(&err)

	if theme.ID.IsZero() {
		id, genErr := uuid.New()
		if genErr != nil {
			return nil, Error.Wrap(genErr)
		}
		theme.ID = id
	}
	if theme.ResellerID.IsZero() {
		return nil, Error.New("reseller id is not set")
	}

	colorsJSON, err := themeColorsToDBX(theme.Colors)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	created, err := repo.db.Create_ResellerTheme(ctx,
		dbx.ResellerTheme_Id(theme.ID[:]),
		dbx.ResellerTheme_ResellerId(theme.ResellerID[:]),
		dbx.ResellerTheme_Name(theme.Name),
		dbx.ResellerTheme_Colors(colorsJSON),
		dbx.ResellerTheme_UpdatedAt(now),
	)
	if err != nil {
		return nil, err
	}
	return resellerThemeFromDBX(created)
}

func (repo *resellerThemes) Update(ctx context.Context, id uuid.UUID, name string, colors seller.ResellerBrandingTheme, updatedAt time.Time) (_ *seller.ResellerCustomTheme, err error) {
	defer mon.Task()(&ctx)(&err)

	colorsJSON, err := themeColorsToDBX(colors)
	if err != nil {
		return nil, err
	}

	updated, err := repo.db.Update_ResellerTheme_By_Id(ctx, dbx.ResellerTheme_Id(id[:]),
		dbx.ResellerTheme_Update_Fields{
			Name:      dbx.ResellerTheme_Name(name),
			Colors:    dbx.ResellerTheme_Colors(colorsJSON),
			UpdatedAt: dbx.ResellerTheme_UpdatedAt(updatedAt),
		},
	)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return resellerThemeFromDBX(updated)
}

func (repo *resellerThemes) Delete(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = repo.db.Delete_ResellerTheme_By_Id(ctx, dbx.ResellerTheme_Id(id[:]))
	if errs.Is(err, sql.ErrNoRows) {
		return seller.ErrNotFound.New("")
	}
	return err
}

func (repo *resellerThemes) DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	themes, err := repo.ListByResellerID(ctx, resellerID)
	if err != nil {
		return err
	}
	for _, theme := range themes {
		if delErr := repo.Delete(ctx, theme.ID); delErr != nil && !seller.ErrNotFound.Has(delErr) {
			return delErr
		}
	}
	return nil
}

func resellerThemeFromDBX(row *dbx.ResellerTheme) (*seller.ResellerCustomTheme, error) {
	if row == nil {
		return nil, Error.New("reseller theme parameter is nil")
	}
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	resellerID, err := uuid.FromBytes(row.ResellerId)
	if err != nil {
		return nil, err
	}
	colors, err := themeColorsFromDBX(row.Colors)
	if err != nil {
		return nil, err
	}
	return &seller.ResellerCustomTheme{
		ID:         id,
		ResellerID: resellerID,
		Name:       row.Name,
		Colors:     colors,
	}, nil
}

func themeColorsFromDBX(data []byte) (seller.ResellerBrandingTheme, error) {
	var theme seller.ResellerBrandingTheme
	if len(data) == 0 {
		return theme, nil
	}
	if err := json.Unmarshal(data, &theme); err != nil {
		var m map[string]string
		if err2 := json.Unmarshal(data, &m); err2 != nil {
			return theme, err
		}
		theme = seller.ThemeFromColorMap(m)
	}
	return theme, nil
}

func themeColorsToDBX(theme seller.ResellerBrandingTheme) ([]byte, error) {
	return json.Marshal(theme)
}
