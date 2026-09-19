// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/StorXNetwork/common/sync2"
)

// PlanScheduleConfig configures the seller plan + invoice chore.
type PlanScheduleConfig struct {
	Interval time.Duration `help:"how often to apply due future plans, notify, and generate invoices" default:"1h" testDefault:"1s"`
	Enabled  bool          `help:"whether the seller plan schedule chore is enabled" default:"true" testDefault:"true"`

	// Invoice cutover used when auto-generating wholesale invoices for all sellers.
	InvoiceBillingDay  int  `help:"day of month (1-28) when invoices close / auto-generate" default:"1"`
	InvoiceBillingHour int  `help:"UTC hour of the invoice billing cutover" default:"0"`
	InvoiceBillingMin  int  `help:"UTC minute of the invoice billing cutover" default:"0"`
	GenerateInvoices   bool `help:"whether this chore also auto-generates seller invoices" default:"true" testDefault:"true"`
}

// InvoiceClock returns the configured billing cutover for invoices.
func (c PlanScheduleConfig) InvoiceClock() BillingClock {
	day := c.InvoiceBillingDay
	if day < InvoiceBillingDayMin || day > InvoiceBillingDayMax {
		day = 1
	}
	hour := c.InvoiceBillingHour
	if hour < 0 || hour > 23 {
		hour = 0
	}
	min := c.InvoiceBillingMin
	if min < 0 || min > 59 {
		min = 0
	}
	return BillingClock{Day: day, Hour: hour, Minute: min}
}

// PlanScheduleChore applies due scheduled plan switches, ending notifications,
// and (optionally) automatic wholesale invoice generation.
//
// architecture: Chore
type PlanScheduleChore struct {
	log              *zap.Logger
	service          *Service
	generateInvoices bool
	invoiceClock     BillingClock
	Loop             *sync2.Cycle
}

// NewPlanScheduleChore creates the plan schedule chore.
func NewPlanScheduleChore(log *zap.Logger, service *Service, config PlanScheduleConfig) *PlanScheduleChore {
	clock := config.InvoiceClock()
	service.SetInvoiceBillingClock(clock)
	return &PlanScheduleChore{
		log:              log,
		service:          service,
		generateInvoices: config.GenerateInvoices,
		invoiceClock:     clock,
		Loop:             sync2.NewCycle(config.Interval),
	}
}

// Run starts the chore loop.
func (chore *PlanScheduleChore) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)
	return chore.Loop.Run(ctx, func(ctx context.Context) error {
		applied, err := chore.service.ApplyDuePlanSwitches(ctx)
		if err != nil {
			chore.log.Error("seller plan schedule chore failed", zap.Error(err))
		} else if applied > 0 {
			chore.log.Info("applied due seller plan switches", zap.Int("count", applied))
		}

		if chore.generateInvoices {
			created, ierr := chore.service.GenerateDueInvoicesForAllResellers(ctx, chore.invoiceClock)
			if ierr != nil {
				chore.log.Error("seller invoice generation failed", zap.Error(ierr))
			} else if created > 0 {
				chore.log.Info("auto-generated seller invoices", zap.Int("count", created))
			}
		}
		return nil
	})
}

// Close stops the chore.
func (chore *PlanScheduleChore) Close() error {
	chore.Loop.Close()
	return nil
}
