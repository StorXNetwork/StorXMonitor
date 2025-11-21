// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console/configs"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that configsDB implements configs.DB.
var _ configs.DB = (*configsDB)(nil)

// ErrConfigs represents errors from the configs database.
var ErrConfigs = errs.Class("configs")

type configsDB struct {
	db *satelliteDB
}

// InsertConfig creates a new configuration with transaction support.
func (c *configsDB) InsertConfig(ctx context.Context, config configs.Config) (_ configs.Config, err error) {
	defer mon.Task()(&ctx)(&err)

	configDataJSON, err := json.Marshal(config.ConfigData)
	if err != nil {
		return config, ErrConfigs.Wrap(err)
	}

	var optional dbx.Config_Create_Fields
	if config.Category != nil {
		optional.Category = dbx.Config_Category(*config.Category)
	}
	if !config.IsActive {
		optional.IsActive = dbx.Config_IsActive(config.IsActive)
	}
	if config.CreatedBy != nil {
		optional.CreatedBy = dbx.Config_CreatedBy(config.CreatedBy[:])
	}

	dbxConfig, err := c.db.Create_Config(ctx,
		dbx.Config_Id(config.ID[:]),
		dbx.Config_ConfigType(string(config.ConfigType)),
		dbx.Config_Name(config.Name),
		dbx.Config_ConfigData(configDataJSON),
		dbx.Config_UpdatedAt(time.Now()),
		optional)
	if err != nil {
		return config, ErrConfigs.Wrap(err)
	}

	return configFromDBX(dbxConfig)
}

// GetConfigByID retrieves a configuration by ID.
func (c *configsDB) GetConfigByID(ctx context.Context, id uuid.UUID) (_ configs.Config, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxConfig, err := c.db.Get_Config_By_Id(ctx, dbx.Config_Id(id[:]))
	if err != nil {
		return configs.Config{}, ErrConfigs.Wrap(err)
	}

	return configFromDBX(dbxConfig)
}

// GetConfigByName retrieves a configuration by type and name.
func (c *configsDB) GetConfigByName(ctx context.Context, configType configs.ConfigType, name string) (_ configs.Config, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxConfig, err := c.db.Get_Config_By_ConfigType_And_Name(ctx,
		dbx.Config_ConfigType(string(configType)),
		dbx.Config_Name(name))
	if err != nil {
		return configs.Config{}, ErrConfigs.Wrap(err)
	}

	return configFromDBX(dbxConfig)
}

// ListConfigs lists configurations with optional filters.
func (c *configsDB) ListConfigs(ctx context.Context, filters configs.ListConfigFilters) (_ []configs.Config, err error) {
	defer mon.Task()(&ctx)(&err)

	var dbxConfigs []*dbx.Config
	var queryErr error

	if filters.ConfigType != nil && filters.Category != nil {
		dbxConfigs, queryErr = c.db.All_Config_By_ConfigType_And_Category(ctx,
			dbx.Config_ConfigType(string(*filters.ConfigType)),
			dbx.Config_Category(*filters.Category))
	} else if filters.ConfigType != nil {
		dbxConfigs, queryErr = c.db.All_Config_By_ConfigType(ctx,
			dbx.Config_ConfigType(string(*filters.ConfigType)))
	} else if filters.IsActive != nil && filters.ConfigType != nil {
		dbxConfigs, queryErr = c.db.All_Config_By_IsActive_And_ConfigType(ctx,
			dbx.Config_IsActive(*filters.IsActive),
			dbx.Config_ConfigType(string(*filters.ConfigType)))
	} else {
		// If no filters, query all configs using raw SQL
		// Since there's no "All_Config" method in dbx, we use a direct query
		query := `SELECT id, config_type, name, category, config_data, is_active, created_by, created_at, updated_at FROM configs`

		var args []interface{}
		argIndex := 1

		// Apply is_active filter if provided (without type)
		if filters.IsActive != nil {
			query += ` WHERE is_active = $` + fmt.Sprintf("%d", argIndex)
			args = append(args, *filters.IsActive)
			argIndex++
		}

		query += ` ORDER BY created_at DESC`

		rows, err := c.db.Query(ctx, query, args...)
		if err != nil {
			if errs.Is(err, sql.ErrNoRows) {
				return []configs.Config{}, nil
			}
			return nil, ErrConfigs.Wrap(err)
		}
		defer func() { err = errs.Combine(err, rows.Close()) }()

		var allConfigs []configs.Config
		for rows.Next() {
			var dbxConfig dbx.Config
			var idBytes, createdByBytes []byte
			var category sql.NullString

			err := rows.Scan(
				&idBytes,
				&dbxConfig.ConfigType,
				&dbxConfig.Name,
				&category,
				&dbxConfig.ConfigData,
				&dbxConfig.IsActive,
				&createdByBytes,
				&dbxConfig.CreatedAt,
				&dbxConfig.UpdatedAt,
			)
			if err != nil {
				return nil, ErrConfigs.Wrap(err)
			}

			// Convert bytes to UUID
			dbxConfig.Id = idBytes

			// Handle nullable created_by (bytea can be NULL, which results in empty []byte)
			if len(createdByBytes) > 0 {
				dbxConfig.CreatedBy = createdByBytes
			}

			// Handle nullable category
			if category.Valid {
				dbxConfig.Category = &category.String
			}

			config, err := configFromDBX(&dbxConfig)
			if err != nil {
				return nil, ErrConfigs.Wrap(err)
			}
			allConfigs = append(allConfigs, config)
		}

		if err := rows.Err(); err != nil {
			return nil, ErrConfigs.Wrap(err)
		}

		return allConfigs, nil
	}

	if queryErr != nil {
		if errs.Is(queryErr, sql.ErrNoRows) {
			return []configs.Config{}, nil
		}
		return nil, ErrConfigs.Wrap(queryErr)
	}

	result := make([]configs.Config, 0, len(dbxConfigs))
	for _, dbxConfig := range dbxConfigs {
		config, err := configFromDBX(dbxConfig)
		if err != nil {
			return nil, ErrConfigs.Wrap(err)
		}
		result = append(result, config)
	}

	return result, nil
}

// UpdateConfig updates a configuration with transaction support.
func (c *configsDB) UpdateConfig(ctx context.Context, id uuid.UUID, update configs.UpdateConfigRequest) (_ configs.Config, err error) {
	defer mon.Task()(&ctx)(&err)

	var updateFields dbx.Config_Update_Fields

	if update.ConfigData != nil {
		configDataJSON, err := json.Marshal(*update.ConfigData)
		if err != nil {
			return configs.Config{}, ErrConfigs.Wrap(err)
		}
		updateFields.ConfigData = dbx.Config_ConfigData(configDataJSON)
	}

	if update.IsActive != nil {
		updateFields.IsActive = dbx.Config_IsActive(*update.IsActive)
	}

	if update.Category != nil {
		if *update.Category == "" {
			updateFields.Category = dbx.Config_Category_Null()
		} else {
			updateFields.Category = dbx.Config_Category(*update.Category)
		}
	}

	updateFields.UpdatedAt = dbx.Config_UpdatedAt(time.Now())

	dbxConfig, err := c.db.Update_Config_By_Id(ctx,
		dbx.Config_Id(id[:]),
		updateFields)
	if err != nil {
		return configs.Config{}, ErrConfigs.Wrap(err)
	}

	return configFromDBX(dbxConfig)
}

// DeleteConfig permanently deletes a configuration.
func (c *configsDB) DeleteConfig(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = c.db.Delete_Config_By_Id(ctx, dbx.Config_Id(id[:]))
	return ErrConfigs.Wrap(err)
}

// GetConfigsByType retrieves all configs of a specific type.
func (c *configsDB) GetConfigsByType(ctx context.Context, configType configs.ConfigType) (_ []configs.Config, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxConfigs, err := c.db.All_Config_By_ConfigType(ctx,
		dbx.Config_ConfigType(string(configType)))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return []configs.Config{}, nil
		}
		return nil, ErrConfigs.Wrap(err)
	}

	result := make([]configs.Config, 0, len(dbxConfigs))
	for _, dbxConfig := range dbxConfigs {
		config, err := configFromDBX(dbxConfig)
		if err != nil {
			return nil, ErrConfigs.Wrap(err)
		}
		result = append(result, config)
	}

	return result, nil
}

// configFromDBX converts a dbx.Config to configs.Config.
func configFromDBX(dbxConfig *dbx.Config) (configs.Config, error) {
	id, err := uuid.FromBytes(dbxConfig.Id)
	if err != nil {
		return configs.Config{}, ErrConfigs.Wrap(err)
	}

	var createdBy *uuid.UUID
	if len(dbxConfig.CreatedBy) > 0 {
		createdByUUID, err := uuid.FromBytes(dbxConfig.CreatedBy)
		if err != nil {
			return configs.Config{}, ErrConfigs.Wrap(err)
		}
		createdBy = &createdByUUID
	}

	var configData map[string]interface{}
	if dbxConfig.ConfigData != nil {
		if err := json.Unmarshal(dbxConfig.ConfigData, &configData); err != nil {
			return configs.Config{}, ErrConfigs.Wrap(err)
		}
	}

	config := configs.Config{
		ID:         id,
		ConfigType: configs.ConfigType(dbxConfig.ConfigType),
		Name:       dbxConfig.Name,
		ConfigData: configData,
		IsActive:   dbxConfig.IsActive,
		CreatedBy:  createdBy,
		CreatedAt:  dbxConfig.CreatedAt,
		UpdatedAt:  dbxConfig.UpdatedAt,
	}

	if dbxConfig.Category != nil {
		category := *dbxConfig.Category
		config.Category = &category
	}

	return config, nil
}
