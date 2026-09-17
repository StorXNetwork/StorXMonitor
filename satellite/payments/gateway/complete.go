// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/post"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/billing"
	"github.com/StorXNetwork/common/memory"
	"github.com/StorXNetwork/common/uuid"
)

// CompletePayment applies plan limits, records billing, and emails the user after a successful one-time pay.
func (s *Service) CompletePayment(ctx context.Context, attempt *Attempt, paymentRef, description string) (err error) {
	defer mon.Task()(&ctx)(&err)

	plan, err := s.deps.Billing.GetPaymentPlansByID(ctx, attempt.PlanID)
	if err != nil {
		return Error.Wrap(err)
	}
	if err := s.applyLimits(ctx, attempt.UserID, plan.Storage, plan.Bandwidth); err != nil {
		return err
	}
	s.sendUpgradeEmail(ctx, attempt.UserID, plan)

	amount, _ := strconv.ParseFloat(FormatAmountMajor(attempt.AmountMinor), 64)
	meta, _ := json.Marshal(map[string]string{
		"payment_ref": paymentRef,
		"provider":    attempt.Provider,
		"attempt_id":  attempt.ID.String(),
	})
	planID := plan.ID
	err = s.deps.Billing.Inserts(ctx, billing.Transactions{
		UserID:      attempt.UserID,
		Amount:      amount,
		Description: description,
		Source:      attempt.Provider,
		Status:      billing.TransactionStatusCompleted,
		Type:        billing.TransactionTypeDebit,
		Metadata:    meta,
		Timestamp:   time.Now().UTC(),
		CreatedAt:   time.Now().UTC(),
		PlanID:      &planID,
	})
	if err != nil {
		s.log.Error("failed to insert billing transaction", zap.Error(err))
	}
	return nil
}

// ApplyRenewal extends entitlements and records a billing debit for a subscription charge.
func (s *Service) ApplyRenewal(ctx context.Context, sub *LocalSubscription, paymentRef string, amountMinor int64) (err error) {
	defer mon.Task()(&ctx)(&err)

	plan, err := s.deps.Billing.GetPaymentPlansByID(ctx, sub.PlanID)
	if err != nil {
		return Error.Wrap(err)
	}
	if err := s.applyLimits(ctx, sub.UserID, plan.Storage, plan.Bandwidth); err != nil {
		return err
	}
	s.sendUpgradeEmail(ctx, sub.UserID, plan)

	amount, _ := strconv.ParseFloat(FormatAmountMajor(amountMinor), 64)
	if amountMinor == 0 {
		amount = plan.Price
	}
	meta, _ := json.Marshal(map[string]string{
		"payment_ref":     paymentRef,
		"provider":        sub.Provider,
		"subscription_id": sub.ID.String(),
	})
	planID := plan.ID
	err = s.deps.Billing.Inserts(ctx, billing.Transactions{
		UserID:      sub.UserID,
		Amount:      amount,
		Description: "Subscription renewal via " + sub.Provider,
		Source:      sub.Provider,
		Status:      billing.TransactionStatusCompleted,
		Type:        billing.TransactionTypeDebit,
		Metadata:    meta,
		Timestamp:   time.Now().UTC(),
		CreatedAt:   time.Now().UTC(),
		PlanID:      &planID,
	})
	if err != nil {
		s.log.Error("failed to insert renewal billing transaction", zap.Error(err))
	}
	return nil
}

// HandleCancel downgrades paid tier when a subscription is fully cancelled.
func (s *Service) HandleCancel(ctx context.Context, sub *LocalSubscription) (err error) {
	defer mon.Task()(&ctx)(&err)

	if sub.CurrentPeriodEnd != nil && sub.CurrentPeriodEnd.After(time.Now().UTC()) {
		s.log.Info("subscription cancelled at period end; limits retained until period end",
			zap.String("subscription_id", sub.ID.String()),
			zap.Time("period_end", *sub.CurrentPeriodEnd))
		return nil
	}
	if err := s.deps.Users.UpdatePaidTiers(ctx, sub.UserID, false); err != nil {
		return Error.Wrap(err)
	}
	return nil
}

func (s *Service) applyLimits(ctx context.Context, userID uuid.UUID, storage, bandwidth int64) error {
	newLimits := console.UsageLimits{Storage: storage, Bandwidth: bandwidth}
	if err := s.deps.Users.UpdateUserProjectLimits(ctx, userID, newLimits); err != nil {
		return Error.Wrap(err)
	}
	if err := s.deps.Users.UpdatePaidTiers(ctx, userID, true); err != nil {
		return Error.Wrap(err)
	}
	projects, err := s.deps.Projects.GetOwn(ctx, userID)
	if err != nil {
		return Error.Wrap(err)
	}
	for _, project := range projects {
		if err := s.deps.Projects.UpdateUsageLimits(ctx, project.ID, console.UsageLimits{
			Storage:   storage,
			Bandwidth: bandwidth,
		}); err != nil {
			s.log.Error("failed to update project limits", zap.Error(err), zap.String("project_id", project.ID.String()))
		}
	}
	return nil
}

func (s *Service) sendUpgradeEmail(ctx context.Context, userID uuid.UUID, plan *billing.PaymentPlans) {
	if s.deps.Mail == nil {
		return
	}
	user, err := s.deps.Users.Get(ctx, userID)
	if err != nil {
		s.log.Error("failed to load user for upgrade email", zap.Error(err))
		return
	}
	s.deps.Mail.SendRenderedAsync(
		ctx,
		[]post.Address{{Address: user.Email}},
		&console.UpgradeSuccessfullEmail{
			UserName:  user.ShortName,
			Signature: "Storx Team",
			GBsize:    fmt.Sprintf("%0.2f GB", float64(plan.Storage)/float64(memory.GB)),
			Bandwidth: fmt.Sprintf("%0.2f GB", float64(plan.Bandwidth)/float64(memory.GB)),
		},
	)
}
