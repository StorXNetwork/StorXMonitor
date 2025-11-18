// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"context"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
)

var (
	// ErrService represents errors from the configs service.
	ErrService = errs.Class("configs service")
)

// Service provides read-only operations for configurations.
type Service struct {
	db DB
}

// NewService creates a new configuration service.
func NewService(db DB) *Service {
	return &Service{
		db: db,
	}
}

// GetConfigByID retrieves a configuration by ID.
func (s *Service) GetConfigByID(ctx context.Context, id uuid.UUID) (Config, error) {
	return s.db.GetConfigByID(ctx, id)
}

// GetConfigByName retrieves a configuration by type and name.
func (s *Service) GetConfigByName(ctx context.Context, configType ConfigType, name string) (Config, error) {
	return s.db.GetConfigByName(ctx, configType, name)
}

// ListConfigs lists configurations with optional filters.
func (s *Service) ListConfigs(ctx context.Context, filters ListConfigFilters) ([]Config, error) {
	return s.db.ListConfigs(ctx, filters)
}

// GetConfigsByType retrieves all configs of a specific type.
func (s *Service) GetConfigsByType(ctx context.Context, configType ConfigType) ([]Config, error) {
	return s.db.GetConfigsByType(ctx, configType)
}

