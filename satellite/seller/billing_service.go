// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/billing"
	"github.com/StorXNetwork/common/uuid"
)

// ListActivePlans returns the shared admin plan catalog (active only).
func (s *Service) ListActivePlans(ctx context.Context) (plans []SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.store.SellerPlans().ListActive(ctx)
}

// ListAllPlans returns all plans including inactive (admin).
func (s *Service) ListAllPlans(ctx context.Context) (plans []SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.store.SellerPlans().List(ctx)
}

// CreatePlan creates a shared user plan (admin).
func (s *Service) CreatePlan(ctx context.Context, req CreateSellerPlanRequest) (plan *SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)

	if req.Name == "" {
		return nil, ErrValidation.New("name is required")
	}
	if req.TierKey == "" {
		req.TierKey = slugifyPlanKey(req.Name)
	}
	if req.TierKey == "" {
		return nil, ErrValidation.New("tierKey is required")
	}
	if req.BillingPeriod != BillingPeriodMonth && req.BillingPeriod != BillingPeriodYear {
		return nil, ErrValidation.New("billingPeriod must be month or year")
	}
	if req.RetailAmount < 0 {
		return nil, ErrValidation.New("retailAmount must be >= 0")
	}
	if req.WholesaleAmount < 0 {
		return nil, ErrValidation.New("wholesaleAmount must be >= 0")
	}
	if req.Currency == "" {
		req.Currency = "INR"
	}
	if req.Features == nil {
		req.Features = []string{}
	}

	plan, err = s.store.SellerPlans().Insert(ctx, &SellerPlan{
		Name:            req.Name,
		TierKey:         req.TierKey,
		BillingPeriod:   req.BillingPeriod,
		StorageBytes:    req.StorageBytes,
		BandwidthBytes:  req.BandwidthBytes,
		RetailAmount:    req.RetailAmount,
		WholesaleAmount: req.WholesaleAmount,
		Currency:        req.Currency,
		Description:     req.Description,
		Features:        req.Features,
		Recommended:     req.Recommended,
		Active:          true,
	})
	if err != nil {
		return nil, err
	}

	if req.Recommended {
		if clearErr := s.store.SellerPlans().ClearRecommendedExcept(ctx, plan.ID); clearErr != nil {
			return nil, Error.Wrap(clearErr)
		}
	}
	// Note: payment_plans dual-write intentionally omitted — seller_plans is the catalog.
	return plan, nil
}

// UpdatePlan updates a shared user plan (admin).
func (s *Service) UpdatePlan(ctx context.Context, id uuid.UUID, update UpdateSellerPlanRequest) (plan *SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)
	update.UpdatedAt = s.nowFn().UTC()

	if update.Recommended != nil && *update.Recommended {
		if clearErr := s.store.SellerPlans().ClearRecommendedExcept(ctx, id); clearErr != nil {
			return nil, Error.Wrap(clearErr)
		}
	}

	plan, err = s.store.SellerPlans().Update(ctx, id, update)
	if err != nil {
		return nil, err
	}
	return plan, nil
}

// DeactivatePlan deactivates a shared user plan (admin).
func (s *Service) DeactivatePlan(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	return s.store.SellerPlans().Deactivate(ctx, id)
}

// ListTenantUsers returns users for the authenticated reseller with plan info.
func (s *Service) ListTenantUsers(ctx context.Context, cursor console.UserCursor) (users []TenantUserWithPlan, page *console.UsersPage, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, nil, err
	}
	return s.listTenantUsersForReseller(ctx, reseller.ID, cursor)
}

// ListTenantUsersForReseller is used by admin to list a seller's users.
func (s *Service) ListTenantUsersForReseller(ctx context.Context, resellerID uuid.UUID, cursor console.UserCursor) (users []TenantUserWithPlan, page *console.UsersPage, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.listTenantUsersForReseller(ctx, resellerID, cursor)
}

func (s *Service) listTenantUsersForReseller(ctx context.Context, resellerID uuid.UUID, cursor console.UserCursor) ([]TenantUserWithPlan, *console.UsersPage, error) {
	if s.usersDB == nil {
		return nil, nil, Error.New("users db not configured")
	}
	if cursor.Limit == 0 {
		cursor.Limit = 50
	}
	if cursor.Page == 0 {
		cursor.Page = 1
	}

	page, err := s.usersDB.GetPagedByTenantID(ctx, resellerID.String(), cursor)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	out := make([]TenantUserWithPlan, 0, len(page.Users))
	for _, u := range page.Users {
		item := TenantUserWithPlan{
			ID:        u.ID,
			Email:     u.Email,
			FullName:  u.FullName,
			Status:    int(u.Status),
			Kind:      int(u.Kind),
			CreatedAt: u.CreatedAt,
		}
		if active, aerr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, u.ID, AssignmentStatusActive); aerr == nil {
			item.ActivePlan = active
		}
		if scheduled, serr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, u.ID, AssignmentStatusScheduled); serr == nil {
			item.ScheduledPlan = scheduled
		}
		out = append(out, item)
	}
	return out, page, nil
}

// AssignPlan assigns a plan to a user under the authenticated reseller.
func (s *Service) AssignPlan(ctx context.Context, userID uuid.UUID, req AssignPlanRequest) (active *UserPlanAssignment, scheduled *UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, nil, err
	}
	return s.assignPlan(ctx, reseller.ID, userID, req, true)
}

func (s *Service) assignPlan(ctx context.Context, resellerID, userID uuid.UUID, req AssignPlanRequest, byReseller bool) (active *UserPlanAssignment, scheduled *UserPlanAssignment, err error) {
	if s.usersDB == nil {
		return nil, nil, Error.New("users db not configured")
	}

	user, err := s.usersDB.Get(ctx, userID)
	if err != nil {
		return nil, nil, ErrNotFound.Wrap(err)
	}
	if user.TenantID == nil || *user.TenantID != resellerID.String() {
		return nil, nil, ErrValidation.New("user does not belong to this seller")
	}

	plan, err := s.store.SellerPlans().Get(ctx, req.PlanID)
	if err != nil {
		return nil, nil, ErrNotFound.Wrap(err)
	}
	if !plan.Active {
		return nil, nil, ErrValidation.New("plan is not active")
	}

	if req.FuturePlanID != nil {
		fp, ferr := s.store.SellerPlans().Get(ctx, *req.FuturePlanID)
		if ferr != nil {
			return nil, nil, ErrNotFound.New("future plan not found")
		}
		if !fp.Active {
			return nil, nil, ErrValidation.New("future plan is not active")
		}
	}

	now := s.nowFn().UTC()

	prev, prevErr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, userID, AssignmentStatusActive)
	if prevErr == nil {
		// Paid active assignment is locked — seller cannot switch until it ends.
		if prev.UserPaidAt != nil {
			if prev.PlanID != req.PlanID {
				return nil, nil, ErrValidation.New("current plan is marked paid; cannot change plan until it ends")
			}
			return nil, nil, ErrValidation.New("current plan is marked paid; use future-plan to schedule the next plan after end")
		}
		prev.Status = AssignmentStatusEnded
		prev.EndedAt = &now
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, prev.ID, prev); uerr != nil {
			return nil, nil, Error.Wrap(uerr)
		}
	}

	// One billing period per assignment: monthly = 1 month, annual = 12 months.
	duration := assignmentDurationMonths(plan.BillingPeriod)
	endsAt := now.AddDate(0, duration, 0)

	if prevSched, serr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, userID, AssignmentStatusScheduled); serr == nil {
		prevSched.Status = AssignmentStatusEnded
		prevSched.EndedAt = &now
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, prevSched.ID, prevSched); uerr != nil {
			return nil, nil, Error.Wrap(uerr)
		}
	}

	active = &UserPlanAssignment{
		ResellerID:         resellerID,
		UserID:             userID,
		PlanID:             plan.ID,
		Status:             AssignmentStatusActive,
		RetailAmount:       plan.RetailAmount,
		WholesaleAmount:    plan.WholesaleAmount,
		BillingPeriod:      plan.BillingPeriod,
		DurationMonths:     &duration,
		PlanStartsAt:       now,
		PlanEndsAt:         &endsAt,
		FuturePlanID:       req.FuturePlanID,
		AutoSwitchOnEnd:    req.AutoSwitchOnEnd && req.FuturePlanID != nil,
		NotifyBeforeEnd:    req.NotifyBeforeEnd,
		AssignedByReseller: byReseller,
		PlanName:           plan.Name,
		UserEmail:          user.Email,
	}
	if req.UserPaid {
		active.UserPaidAt = &now
	}
	if req.Notes != "" {
		notes := req.Notes
		active.Notes = &notes
	}

	active, err = s.store.UserPlanAssignments().Insert(ctx, active)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	if err = s.applyPlanLimits(ctx, userID, plan, &endsAt); err != nil {
		return nil, nil, err
	}

	if req.FuturePlanID != nil && req.AutoSwitchOnEnd {
		futurePlan, ferr := s.store.SellerPlans().Get(ctx, *req.FuturePlanID)
		if ferr != nil || futurePlan == nil {
			return nil, nil, ErrNotFound.New("future plan not found")
		}
		scheduled = &UserPlanAssignment{
			ResellerID:         resellerID,
			UserID:             userID,
			PlanID:             *req.FuturePlanID,
			Status:             AssignmentStatusScheduled,
			RetailAmount:       futurePlan.RetailAmount,
			WholesaleAmount:    futurePlan.WholesaleAmount,
			BillingPeriod:      futurePlan.BillingPeriod,
			PlanStartsAt:       endsAt,
			AutoSwitchOnEnd:    false,
			NotifyBeforeEnd:    req.NotifyBeforeEnd,
			AssignedByReseller: byReseller,
			PlanName:           futurePlan.Name,
			UserEmail:          user.Email,
		}
		scheduled, err = s.store.UserPlanAssignments().Insert(ctx, scheduled)
		if err != nil {
			return nil, nil, Error.Wrap(err)
		}
	}

	return active, scheduled, nil
}

func assignmentDurationMonths(billingPeriod string) int {
	if billingPeriod == BillingPeriodYear {
		return 12
	}
	return 1
}

func (s *Service) applyPlanLimits(ctx context.Context, userID uuid.UUID, plan *SellerPlan, planEndsAt *time.Time) error {
	if err := console.ApplyPaidUsageLimits(
		ctx,
		s.usersDB,
		s.projectsDB,
		userID,
		plan.StorageBytes,
		plan.BandwidthBytes,
		100000000,
	); err != nil {
		return Error.Wrap(err)
	}

	// Debit row lets dashboard Plan State show plan name + days left (via metadata).
	if s.billing != nil {
		metaMap := map[string]string{
			"source":         "seller_assign",
			"plan_id":        plan.ID.String(),
			"plan_name":      plan.Name,
			"billing_period": plan.BillingPeriod,
		}
		if planEndsAt != nil {
			metaMap["plan_ends_at"] = planEndsAt.UTC().Format(time.RFC3339)
		}
		meta, _ := json.Marshal(metaMap)
		now := s.nowFn().UTC()
		tx := billing.Transactions{
			UserID:      userID,
			Amount:      float64(plan.RetailAmount),
			Description: "Seller plan assignment: " + plan.Name,
			Source:      "seller",
			Status:      billing.TransactionStatusCompleted,
			Type:        billing.TransactionTypeDebit,
			Metadata:    meta,
			Timestamp:   now,
			CreatedAt:   now,
		}
		if plan.PaymentPlanID != nil {
			planID := *plan.PaymentPlanID
			tx.PlanID = &planID
		}
		if err := s.billing.Inserts(ctx, tx); err != nil {
			s.log.Error("failed to record seller plan billing transaction",
				zap.Error(err),
				zap.String("user_id", userID.String()),
				zap.String("plan_id", plan.ID.String()),
			)
		}
	}
	return nil
}

// UpdateFuturePlan sets, changes, or cancels the scheduled future plan for a user.
func (s *Service) UpdateFuturePlan(ctx context.Context, userID uuid.UUID, req UpdateFuturePlanRequest) (scheduled *UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, err
	}

	active, err := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, userID, AssignmentStatusActive)
	if err != nil {
		return nil, ErrNotFound.New("no active assignment")
	}
	if active.ResellerID != reseller.ID {
		return nil, ErrValidation.New("user does not belong to this seller")
	}

	now := s.nowFn().UTC()

	// Cancel existing scheduled.
	if prev, serr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, userID, AssignmentStatusScheduled); serr == nil {
		prev.Status = AssignmentStatusEnded
		prev.EndedAt = &now
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, prev.ID, prev); uerr != nil {
			return nil, Error.Wrap(uerr)
		}
	}

	if req.Cancel || req.FuturePlanID == nil {
		active.FuturePlanID = nil
		active.AutoSwitchOnEnd = false
		if req.NotifyBeforeEnd != nil {
			active.NotifyBeforeEnd = *req.NotifyBeforeEnd
		}
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, active.ID, active); uerr != nil {
			return nil, Error.Wrap(uerr)
		}
		return nil, nil
	}

	fp, err := s.store.SellerPlans().Get(ctx, *req.FuturePlanID)
	if err != nil || !fp.Active {
		return nil, ErrValidation.New("future plan not found or inactive")
	}

	startsAt := now
	if active.PlanEndsAt != nil {
		startsAt = *active.PlanEndsAt
	}

	autoSwitch := true
	if req.AutoSwitchOnEnd != nil {
		autoSwitch = *req.AutoSwitchOnEnd
	}
	notify := active.NotifyBeforeEnd
	if req.NotifyBeforeEnd != nil {
		notify = *req.NotifyBeforeEnd
	}

	active.FuturePlanID = req.FuturePlanID
	active.AutoSwitchOnEnd = autoSwitch
	active.NotifyBeforeEnd = notify
	if _, uerr := s.store.UserPlanAssignments().Update(ctx, active.ID, active); uerr != nil {
		return nil, Error.Wrap(uerr)
	}

	if !autoSwitch {
		return nil, nil
	}

	user, _ := s.usersDB.Get(ctx, userID)
	email := ""
	if user != nil {
		email = user.Email
	}

	scheduled = &UserPlanAssignment{
		ResellerID:         reseller.ID,
		UserID:             userID,
		PlanID:             fp.ID,
		Status:             AssignmentStatusScheduled,
		RetailAmount:       fp.RetailAmount,
		WholesaleAmount:    fp.WholesaleAmount,
		BillingPeriod:      fp.BillingPeriod,
		PlanStartsAt:       startsAt,
		NotifyBeforeEnd:    notify,
		AssignedByReseller: true,
		PlanName:           fp.Name,
		UserEmail:          email,
	}
	return s.store.UserPlanAssignments().Insert(ctx, scheduled)
}

// ListAssignments returns assignment history for the authenticated reseller.
func (s *Service) ListAssignments(ctx context.Context) (assignments []UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, err
	}
	return s.listAssignmentsHydrated(ctx, reseller.ID)
}

// ListAssignmentsForReseller returns assignment history for admin.
func (s *Service) ListAssignmentsForReseller(ctx context.Context, resellerID uuid.UUID) (assignments []UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.listAssignmentsHydrated(ctx, resellerID)
}

func (s *Service) listAssignmentsHydrated(ctx context.Context, resellerID uuid.UUID) ([]UserPlanAssignment, error) {
	list, err := s.store.UserPlanAssignments().ListByResellerID(ctx, resellerID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if plan, perr := s.store.SellerPlans().Get(ctx, list[i].PlanID); perr == nil {
			list[i].PlanName = plan.Name
		}
		if s.usersDB != nil {
			if user, uerr := s.usersDB.Get(ctx, list[i].UserID); uerr == nil {
				list[i].UserEmail = user.Email
			}
		}
	}
	return list, nil
}

// ListInvoices returns invoices for the authenticated reseller.
func (s *Service) ListInvoices(ctx context.Context) (invoices []SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, err
	}
	return s.store.SellerInvoices().ListByResellerID(ctx, reseller.ID)
}

// GetInvoice returns invoice detail with lines for the authenticated reseller.
func (s *Service) GetInvoice(ctx context.Context, id uuid.UUID) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := s.store.SellerInvoices().Get(ctx, id)
	if err != nil {
		return nil, ErrNotFound.Wrap(err)
	}
	if inv.ResellerID != reseller.ID {
		return nil, ErrNotFound.New("")
	}
	lines, err := s.store.SellerInvoices().ListLines(ctx, id)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	inv.Lines = s.hydrateInvoiceLines(ctx, lines)
	return inv, nil
}

// GetInvoiceAdmin returns invoice detail (admin, no reseller scoping).
func (s *Service) GetInvoiceAdmin(ctx context.Context, id uuid.UUID) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	inv, err := s.store.SellerInvoices().Get(ctx, id)
	if err != nil {
		return nil, ErrNotFound.Wrap(err)
	}
	lines, err := s.store.SellerInvoices().ListLines(ctx, id)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	inv.Lines = s.hydrateInvoiceLines(ctx, lines)
	return inv, nil
}

func (s *Service) hydrateInvoiceLines(ctx context.Context, lines []SellerInvoiceLine) []SellerInvoiceLine {
	for i := range lines {
		if plan, err := s.store.SellerPlans().Get(ctx, lines[i].PlanID); err == nil {
			lines[i].PlanName = plan.Name
		}
		if s.usersDB != nil {
			if user, err := s.usersDB.Get(ctx, lines[i].UserID); err == nil {
				lines[i].UserEmail = user.Email
			}
		}
	}
	return lines
}

// ListInvoicesForReseller returns invoices for a reseller (admin).
func (s *Service) ListInvoicesForReseller(ctx context.Context, resellerID uuid.UUID) (invoices []SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.store.SellerInvoices().ListByResellerID(ctx, resellerID)
}

// LastCompletedMonthPeriod returns the UTC calendar month fully before asOf.
// Example: asOf in September → August 1 00:00:00 … August 31 23:59:59 UTC.
func LastCompletedMonthPeriod(asOf time.Time) (periodStart, periodEnd time.Time) {
	asOf = asOf.UTC()
	thisMonth := time.Date(asOf.Year(), asOf.Month(), 1, 0, 0, 0, 0, time.UTC)
	periodStart = thisMonth.AddDate(0, -1, 0)
	periodEnd = thisMonth.Add(-time.Second)
	return periodStart, periodEnd
}

func sameInvoicePeriod(aStart, _, bStart, _ time.Time) bool {
	a, b := aStart.UTC(), bStart.UTC()
	return a.Year() == b.Year() && a.Month() == b.Month()
}

// GenerateLastMonthInvoice builds the wholesale invoice for the last completed month relative to asOf.
func (s *Service) GenerateLastMonthInvoice(ctx context.Context, resellerID uuid.UUID, asOf time.Time, adminNote string) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)
	start, end := LastCompletedMonthPeriod(asOf)
	return s.GenerateInvoice(ctx, resellerID, GenerateInvoiceRequest{
		PeriodStart: start,
		PeriodEnd:   end,
		AdminNote:   adminNote,
	})
}

// assignmentBillableInPeriod is true when the assignment cycle starts inside the invoice period.
// Monthly and annual both bill once at start (not on every overlapping month).
func assignmentBillableInPeriod(a UserPlanAssignment, periodStart, periodEnd time.Time) bool {
	if a.Status != AssignmentStatusActive && a.Status != AssignmentStatusEnded {
		return false
	}
	start := a.PlanStartsAt.UTC()
	if start.Before(periodStart) || start.After(periodEnd) {
		return false
	}
	return true
}

// GenerateInvoice creates a wholesale invoice for a reseller period (admin).
// Rejects future periods, empty invoices, and duplicate non-cancelled invoices for the same calendar month.
func (s *Service) GenerateInvoice(ctx context.Context, resellerID uuid.UUID, req GenerateInvoiceRequest) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	if req.PeriodEnd.Before(req.PeriodStart) {
		return nil, ErrValidation.New("periodEnd must be after periodStart")
	}
	now := s.nowFn().UTC()
	if req.PeriodStart.After(now) {
		return nil, ErrValidation.New("cannot generate invoice for a future period")
	}
	if req.PeriodEnd.After(now) {
		return nil, ErrValidation.New("invoice period must end in the past; use last completed month")
	}

	existing, err := s.store.SellerInvoices().ListByResellerID(ctx, resellerID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	for _, inv := range existing {
		if inv.Status == InvoiceStatusCancelled {
			continue
		}
		if sameInvoicePeriod(inv.PeriodStart, inv.PeriodEnd, req.PeriodStart, req.PeriodEnd) {
			return nil, ErrValidation.New("invoice already exists for this period")
		}
	}

	assignments, err := s.store.UserPlanAssignments().ListByResellerID(ctx, resellerID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	issued := now
	inv := &SellerInvoice{
		ResellerID:  resellerID,
		PeriodStart: req.PeriodStart.UTC(),
		PeriodEnd:   req.PeriodEnd.UTC(),
		Currency:    "INR",
		Status:      InvoiceStatusPending,
		IssuedAt:    &issued,
	}
	if req.AdminNote != "" {
		note := req.AdminNote
		inv.AdminNote = &note
	}

	var lines []SellerInvoiceLine
	var total int64
	currency := "INR"

	for _, a := range assignments {
		if !assignmentBillableInPeriod(a, req.PeriodStart, req.PeriodEnd) {
			continue
		}

		planName := a.PlanID.String()
		if plan, perr := s.store.SellerPlans().Get(ctx, a.PlanID); perr == nil {
			planName = plan.Name
			if plan.Currency != "" {
				currency = plan.Currency
			}
		}

		lines = append(lines, SellerInvoiceLine{
			AssignmentID: a.ID,
			UserID:       a.UserID,
			PlanID:       a.PlanID,
			Description:  fmt.Sprintf("%s (%s)", planName, a.BillingPeriod),
			Amount:       a.WholesaleAmount,
			RetailAmount: a.RetailAmount,
			AssignedAt:   a.AssignedAt,
		})
		total += a.WholesaleAmount
	}

	if len(lines) == 0 {
		return nil, ErrValidation.New("no billable assignments in this period")
	}

	inv.Currency = currency
	inv.TotalAmount = total
	inv, err = s.store.SellerInvoices().Insert(ctx, inv)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for i := range lines {
		lines[i].InvoiceID = inv.ID
		if _, lerr := s.store.SellerInvoices().InsertLine(ctx, &lines[i]); lerr != nil {
			return nil, Error.Wrap(lerr)
		}
	}

	return s.GetInvoiceAdmin(ctx, inv.ID)
}

// UpdateInvoiceStatus updates invoice status (admin).
func (s *Service) UpdateInvoiceStatus(ctx context.Context, id uuid.UUID, req UpdateInvoiceStatusRequest) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	switch req.Status {
	case InvoiceStatusPending, InvoiceStatusPaymentReceived, InvoiceStatusOverdue, InvoiceStatusCancelled, InvoiceStatusDraft:
	default:
		return nil, ErrValidation.New("invalid status")
	}

	inv, err := s.store.SellerInvoices().Get(ctx, id)
	if err != nil {
		return nil, ErrNotFound.Wrap(err)
	}
	inv.Status = req.Status
	if req.AdminNote != "" {
		note := req.AdminNote
		inv.AdminNote = &note
	}
	if req.Status == InvoiceStatusPaymentReceived {
		now := s.nowFn().UTC()
		inv.PaidAt = &now
	} else {
		inv.PaidAt = nil
	}
	return s.store.SellerInvoices().Update(ctx, inv)
}

// ListResellerSummaries returns all resellers with counts (admin).
func (s *Service) ListResellerSummaries(ctx context.Context) (summaries []ResellerSummary, err error) {
	defer mon.Task()(&ctx)(&err)

	resellers, err := s.store.Resellers().List(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	out := make([]ResellerSummary, 0, len(resellers))
	for _, r := range resellers {
		sum := ResellerSummary{Reseller: r}
		if count, cerr := s.store.UserPlanAssignments().CountByResellerID(ctx, r.ID); cerr == nil {
			sum.AssignmentCount = count
		}
		if s.usersDB != nil {
			if page, perr := s.usersDB.GetPagedByTenantID(ctx, r.ID.String(), console.UserCursor{Limit: 1, Page: 1}); perr == nil {
				sum.UserCount = int64(page.TotalCount)
			}
		}
		out = append(out, sum)
	}
	return out, nil
}

// GetResellerDetail returns a reseller (admin).
func (s *Service) GetResellerDetail(ctx context.Context, id uuid.UUID) (reseller *Reseller, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.store.Resellers().Get(ctx, id)
}

// ListNotifications returns billing notifications for the authenticated reseller.
func (s *Service) ListNotifications(ctx context.Context) (notes []BillingNotification, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, err
	}
	return s.store.BillingNotifications().ListByResellerID(ctx, reseller.ID)
}

// ApplyDuePlanSwitches activates due scheduled assignments and emits notifications.
func (s *Service) ApplyDuePlanSwitches(ctx context.Context) (applied int, err error) {
	defer mon.Task()(&ctx)(&err)

	now := s.nowFn().UTC()

	// Notify before end (7 days window by default — anything ending before notifyBefore).
	notifyBefore := now.Add(7 * 24 * time.Hour)
	needing, err := s.store.UserPlanAssignments().ListNeedingEndNotification(ctx, notifyBefore)
	if err != nil {
		return 0, Error.Wrap(err)
	}
	for _, a := range needing {
		if a.PlanEndsAt == nil || a.PlanEndsAt.After(notifyBefore) {
			continue
		}
		title := "Plan ending soon"
		body := fmt.Sprintf("User plan ends on %s.", a.PlanEndsAt.Format("2006-01-02"))
		uid := a.UserID
		_, _ = s.store.BillingNotifications().Insert(ctx, &BillingNotification{
			ResellerID: a.ResellerID,
			UserID:     &uid,
			Type:       NotificationTypePlanEnding,
			Title:      title,
			Body:       body,
		})
		notified := now
		a.NotifiedEndingAt = &notified
		_, _ = s.store.UserPlanAssignments().Update(ctx, a.ID, &a)
	}

	due, err := s.store.UserPlanAssignments().ListDueScheduled(ctx, now)
	if err != nil {
		return 0, Error.Wrap(err)
	}
	for _, sched := range due {
		if active, aerr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, sched.UserID, AssignmentStatusActive); aerr == nil {
			active.Status = AssignmentStatusEnded
			active.EndedAt = &now
			if _, uerr := s.store.UserPlanAssignments().Update(ctx, active.ID, active); uerr != nil {
				s.log.Error("failed to end active assignment before switch",
					zap.Error(uerr), zap.String("assignment_id", active.ID.String()))
				continue
			}
		}

		plan, perr := s.store.SellerPlans().Get(ctx, sched.PlanID)
		if perr != nil || plan == nil {
			s.log.Error("scheduled plan missing", zap.String("plan_id", sched.PlanID.String()), zap.Error(perr))
			continue
		}

		duration := assignmentDurationMonths(plan.BillingPeriod)
		ends := now.AddDate(0, duration, 0)
		sched.Status = AssignmentStatusActive
		sched.PlanStartsAt = now
		sched.PlanEndsAt = &ends
		sched.DurationMonths = &duration
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, sched.ID, &sched); uerr != nil {
			s.log.Error("failed to activate scheduled assignment",
				zap.Error(uerr), zap.String("assignment_id", sched.ID.String()))
			continue
		}
		if s.usersDB != nil {
			if lerr := s.applyPlanLimits(ctx, sched.UserID, plan, &ends); lerr != nil {
				s.log.Error("failed to apply limits after plan switch",
					zap.Error(lerr), zap.String("user_id", sched.UserID.String()))
				continue
			}
		}
		uid := sched.UserID
		if _, nerr := s.store.BillingNotifications().Insert(ctx, &BillingNotification{
			ResellerID: sched.ResellerID,
			UserID:     &uid,
			Type:       NotificationTypePlanSwitched,
			Title:      "Plan switched",
			Body:       fmt.Sprintf("Future plan %s is now active.", plan.Name),
		}); nerr != nil {
			s.log.Error("failed to insert plan-switched notification", zap.Error(nerr))
		}
		applied++
	}

	// Expire any active assignment whose plan_ends_at has passed (with or without auto-switch).
	// Scheduled switches above already end the prior active; this catches no-future-plan cases.
	expired, err := s.store.UserPlanAssignments().ListDueAutoSwitch(ctx, now)
	if err != nil {
		return applied, Error.Wrap(err)
	}
	for _, a := range expired {
		if a.Status != AssignmentStatusActive {
			continue
		}
		a.Status = AssignmentStatusEnded
		a.EndedAt = &now
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, a.ID, &a); uerr != nil {
			s.log.Error("failed to expire assignment",
				zap.Error(uerr), zap.String("assignment_id", a.ID.String()))
		}
	}

	return applied, nil
}

func slugifyPlanKey(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('_')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "_")
}
