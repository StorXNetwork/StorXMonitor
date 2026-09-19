// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/sync2"
)

// PlanScheduleConfig configures the plan switch chore.
type PlanScheduleConfig struct {
	Interval time.Duration `help:"how often to apply due future plans and notify" default:"1h" testDefault:"1s"`
	Enabled  bool          `help:"whether the seller plan schedule chore is enabled" default:"true" testDefault:"true"`
}

// PlanScheduleChore applies due scheduled plan switches and ending notifications.
//
// architecture: Chore
type PlanScheduleChore struct {
	log     *zap.Logger
	service *Service
	Loop    *sync2.Cycle
}

// NewPlanScheduleChore creates the plan schedule chore.
func NewPlanScheduleChore(log *zap.Logger, service *Service, config PlanScheduleConfig) *PlanScheduleChore {
	return &PlanScheduleChore{
		log:     log,
		service: service,
		Loop:    sync2.NewCycle(config.Interval),
	}
}

// Run starts the chore loop.
func (chore *PlanScheduleChore) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)
	return chore.Loop.Run(ctx, func(ctx context.Context) error {
		applied, err := chore.service.ApplyDuePlanSwitches(ctx)
		if err != nil {
			chore.log.Error("seller plan schedule chore failed", zap.Error(err))
			return nil
		}
		if applied > 0 {
			chore.log.Info("applied due seller plan switches", zap.Int("count", applied))
		}
		return nil
	})
}

// Close stops the chore.
func (chore *PlanScheduleChore) Close() error {
	chore.Loop.Close()
	return nil
}
