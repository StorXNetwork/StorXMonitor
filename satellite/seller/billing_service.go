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
			item.ActivePlan = s.hydrateAssignment(ctx, active)
		}
		if scheduled, serr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, u.ID, AssignmentStatusScheduled); serr == nil {
			item.ScheduledPlan = s.hydrateAssignment(ctx, scheduled)
		}
		out = append(out, item)
	}
	return out, page, nil
}

// hydrateAssignment fills planName (and userEmail when missing) for API responses.
func (s *Service) hydrateAssignment(ctx context.Context, a *UserPlanAssignment) *UserPlanAssignment {
	if a == nil {
		return nil
	}
	if plan, err := s.store.SellerPlans().Get(ctx, a.PlanID); err == nil {
		a.PlanName = plan.Name
	}
	if a.UserEmail == "" && s.usersDB != nil {
		if user, err := s.usersDB.Get(ctx, a.UserID); err == nil {
			a.UserEmail = user.Email
		}
	}
	return a
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
		AutoSwitchOnEnd:    req.FuturePlanID != nil, // selecting a future plan always auto-switches
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

	// Future plan selected → always create scheduled row (no separate auto-switch flag).
	if req.FuturePlanID != nil {
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

func (s *Service) downgradeToFree(ctx context.Context, userID uuid.UUID) error {
	if s.usersDB == nil || s.projectsDB == nil {
		return nil
	}
	storage := s.freeStorageBytes
	bandwidth := s.freeBandwidthBytes
	segment := s.freeSegmentLimit
	if storage <= 0 {
		storage = 2 * 1e9
	}
	if bandwidth <= 0 {
		bandwidth = 2 * 1e9
	}
	if segment <= 0 {
		segment = 1000000
	}
	return console.ApplyFreeUsageLimits(ctx, s.usersDB, s.projectsDB, userID, storage, bandwidth, segment)
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

	notify := active.NotifyBeforeEnd
	if req.NotifyBeforeEnd != nil {
		notify = *req.NotifyBeforeEnd
	}

	// Future plan always means auto-switch; no separate flag.
	active.FuturePlanID = req.FuturePlanID
	active.AutoSwitchOnEnd = true
	active.NotifyBeforeEnd = notify
	if _, uerr := s.store.UserPlanAssignments().Update(ctx, active.ID, active); uerr != nil {
		return nil, Error.Wrap(uerr)
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
		s.hydrateAssignment(ctx, &list[i])
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
	inv, err := s.loadInvoiceDetail(ctx, id)
	if err != nil {
		return nil, err
	}
	if inv.ResellerID != reseller.ID {
		return nil, ErrNotFound.New("")
	}
	return inv, nil
}

// GetInvoiceAdmin returns invoice detail (admin, no reseller scoping).
func (s *Service) GetInvoiceAdmin(ctx context.Context, id uuid.UUID) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)
	return s.loadInvoiceDetail(ctx, id)
}

// loadInvoiceDetail loads invoice + lines + seller party fields (single path for admin/seller).
func (s *Service) loadInvoiceDetail(ctx context.Context, id uuid.UUID) (*SellerInvoice, error) {
	inv, err := s.store.SellerInvoices().Get(ctx, id)
	if err != nil {
		return nil, ErrNotFound.Wrap(err)
	}
	lines, err := s.store.SellerInvoices().ListLines(ctx, id)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	inv.Lines = s.hydrateInvoiceLines(ctx, lines)
	s.attachSellerParty(ctx, inv)
	return inv, nil
}

func (s *Service) attachSellerParty(ctx context.Context, inv *SellerInvoice) {
	if inv == nil {
		return
	}
	r, err := s.store.Resellers().Get(ctx, inv.ResellerID)
	if err != nil {
		return
	}
	inv.SellerName = r.Name
	inv.SellerEmail = r.Email
	if r.CompanyName != nil {
		inv.SellerCompany = *r.CompanyName
	}
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

// InvoiceBillingDayMin/Max are the allowed admin day-of-month choices (safe in every month).
const (
	InvoiceBillingDayMin = 1
	InvoiceBillingDayMax = 28
)

// BillingClock is the admin-chosen day-of-month (1–28) and clock time (UTC) for cutovers.
type BillingClock struct {
	Day    int // 1–28
	Hour   int // 0–23
	Minute int // 0–59
}

func validateBillingDay(day int) error {
	if day < InvoiceBillingDayMin || day > InvoiceBillingDayMax {
		return ErrValidation.New("billing day must be between %d and %d", InvoiceBillingDayMin, InvoiceBillingDayMax)
	}
	return nil
}

func validateBillingClock(c BillingClock) error {
	if err := validateBillingDay(c.Day); err != nil {
		return err
	}
	if c.Hour < 0 || c.Hour > 23 {
		return ErrValidation.New("billing hour must be between 0 and 23")
	}
	if c.Minute < 0 || c.Minute > 59 {
		return ErrValidation.New("billing minute must be between 0 and 59")
	}
	return nil
}

// InvoicePeriodForBillingCutover builds the invoice window closed by a cutover in year/month.
// Cutover on day D of month M bills from the 1st of month M−1 through the cutover instant.
//
// Example: cutover 1 Oct 2026 20:29 → 1 Sept 00:00 … 1 Oct 20:29 (September invoice)
// Example: cutover 25 Sept 2026 00:00 → 1 Aug 00:00 … 25 Sept 00:00 (August invoice)
func InvoicePeriodForBillingCutover(year int, month time.Month, c BillingClock) (periodStart, periodEnd time.Time) {
	asOf := time.Date(year, month, c.Day, c.Hour, c.Minute, 0, 0, time.UTC)
	return InvoicePeriodFromAsOf(asOf)
}

// InvoicePeriodForBillingDay is the midnight cutover helper (hour=0, minute=0).
func InvoicePeriodForBillingDay(year int, month time.Month, billingDay int) (periodStart, periodEnd time.Time) {
	return InvoicePeriodForBillingCutover(year, month, BillingClock{Day: billingDay})
}

// LatestCompletedBillingAsOf returns the most recent cutover (day + clock) that is still <= now.
func LatestCompletedBillingAsOf(now time.Time, c BillingClock) time.Time {
	now = now.UTC()
	asOf := time.Date(now.Year(), now.Month(), c.Day, c.Hour, c.Minute, 0, 0, time.UTC)
	if asOf.After(now) {
		asOf = asOf.AddDate(0, -1, 0)
	}
	return asOf
}

// NextBillingAsOf returns the next cutover at or after now (if today's cutover already passed, next month).
func NextBillingAsOf(now time.Time, c BillingClock) time.Time {
	now = now.UTC()
	asOf := time.Date(now.Year(), now.Month(), c.Day, c.Hour, c.Minute, 0, 0, time.UTC)
	if !asOf.After(now) {
		asOf = asOf.AddDate(0, 1, 0)
	}
	return asOf
}

// InvoicePeriodFromAsOf builds the window closed by cutover asOf:
// periodStart = 1st of the previous calendar month 00:00 UTC
// periodEnd   = asOf (selected day + time)
func InvoicePeriodFromAsOf(asOf time.Time) (periodStart, periodEnd time.Time) {
	asOf = asOf.UTC()
	periodEnd = asOf
	periodStart = time.Date(asOf.Year(), asOf.Month()-1, 1, 0, 0, 0, 0, time.UTC)
	return periodStart, periodEnd
}

// LastCompletedMonthPeriod returns the invoice window for the last completed day-1 midnight cutover.
func LastCompletedMonthPeriod(asOf time.Time) (periodStart, periodEnd time.Time) {
	asOf = asOf.UTC()
	anchor := LatestCompletedBillingAsOf(asOf, BillingClock{Day: 1})
	return InvoicePeriodFromAsOf(anchor)
}

func sameInvoicePeriod(aStart, aEnd, bStart, bEnd time.Time) bool {
	return aStart.UTC().Truncate(time.Second).Equal(bStart.UTC().Truncate(time.Second)) &&
		aEnd.UTC().Truncate(time.Second).Equal(bEnd.UTC().Truncate(time.Second))
}

// invoicePeriodsOverlap is true when two closed periods share any time (avoids double-billing
// when regenerating under a different billing-day scheme than existing invoices).
func invoicePeriodsOverlap(aStart, aEnd, bStart, bEnd time.Time) bool {
	aStart, aEnd = aStart.UTC(), aEnd.UTC()
	bStart, bEnd = bStart.UTC(), bEnd.UTC()
	return !aEnd.Before(bStart) && !bEnd.Before(aStart)
}

// GenerateLastMonthInvoice builds one invoice for the period ending at asOf.
func (s *Service) GenerateLastMonthInvoice(ctx context.Context, resellerID uuid.UUID, asOf time.Time, adminNote string) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)
	start, end := InvoicePeriodFromAsOf(asOf)
	return s.GenerateInvoice(ctx, resellerID, GenerateInvoiceRequest{
		PeriodStart: start,
		PeriodEnd:   end,
		AdminNote:   adminNote,
	})
}

// GenerateLastCompletedInvoice creates at most one invoice: the latest completed
// billing period for this reseller's saved billing day/time (or provided clock).
func (s *Service) GenerateLastCompletedInvoice(ctx context.Context, resellerID uuid.UUID, clock BillingClock, adminNote string) (invoice *SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	if clock.Day == 0 {
		clock, err = s.InvoiceBillingClockForReseller(ctx, resellerID)
		if err != nil {
			return nil, err
		}
	}
	if err = validateBillingClock(clock); err != nil {
		return nil, err
	}

	now := s.nowFn().UTC()
	asOf := LatestCompletedBillingAsOf(now, clock)
	start, end := InvoicePeriodFromAsOf(asOf)
	return s.GenerateInvoice(ctx, resellerID, GenerateInvoiceRequest{
		PeriodStart: start,
		PeriodEnd:   end,
		AdminNote:   adminNote,
	})
}

// InvoiceBillingClockForReseller returns the admin-selected cutover for this seller (default day 1).
func (s *Service) InvoiceBillingClockForReseller(ctx context.Context, resellerID uuid.UUID) (BillingClock, error) {
	if s.store.ResellerConfigs() == nil {
		return defaultInvoiceBillingSettings().Clock(), nil
	}
	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, resellerID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return defaultInvoiceBillingSettings().Clock(), nil
		}
		return BillingClock{}, Error.Wrap(err)
	}
	return ExtractInvoiceBillingSettings(dbCfg.Config).Clock(), nil
}

// GetResellerInvoiceBilling returns saved invoice billing day/time for admin UI.
func (s *Service) GetResellerInvoiceBilling(ctx context.Context, resellerID uuid.UUID) (settings InvoiceBillingSettings, err error) {
	defer mon.Task()(&ctx)(&err)
	clock, err := s.InvoiceBillingClockForReseller(ctx, resellerID)
	if err != nil {
		return InvoiceBillingSettings{}, err
	}
	return InvoiceBillingSettings{Day: clock.Day, Hour: clock.Hour, Minute: clock.Minute}, nil
}

// SetResellerInvoiceBilling saves admin-selected day/time used by manual + auto invoice generation.
func (s *Service) SetResellerInvoiceBilling(ctx context.Context, resellerID uuid.UUID, settings InvoiceBillingSettings) (saved InvoiceBillingSettings, err error) {
	defer mon.Task()(&ctx)(&err)

	if s.store.ResellerConfigs() == nil {
		return InvoiceBillingSettings{}, Error.New("reseller configs unavailable")
	}

	clock := settings.Clock()
	if err = validateBillingClock(clock); err != nil {
		return InvoiceBillingSettings{}, err
	}
	settings = InvoiceBillingSettings{Day: clock.Day, Hour: clock.Hour, Minute: clock.Minute}

	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, resellerID)
	now := s.nowFn().UTC()
	switch {
	case err == nil:
		merged, merr := MergeInvoiceBillingSettings(dbCfg.Config, settings)
		if merr != nil {
			return InvoiceBillingSettings{}, Error.Wrap(merr)
		}
		_, err = s.store.ResellerConfigs().Update(ctx, resellerID, UpdateResellerConfigRequest{
			Config:    merged,
			UpdatedAt: now,
		})
		if err != nil {
			return InvoiceBillingSettings{}, Error.Wrap(err)
		}
	case ErrNotFound.Has(err):
		merged, merr := MergeInvoiceBillingSettings(nil, settings)
		if merr != nil {
			return InvoiceBillingSettings{}, Error.Wrap(merr)
		}
		configID, idErr := uuid.New()
		if idErr != nil {
			return InvoiceBillingSettings{}, Error.Wrap(idErr)
		}
		_, err = s.store.ResellerConfigs().Insert(ctx, &ResellerConfig{
			ID:         configID,
			ResellerID: resellerID,
			Config:     merged,
			CreatedAt:  now,
			UpdatedAt:  now,
		})
		if err != nil {
			return InvoiceBillingSettings{}, Error.Wrap(err)
		}
	default:
		return InvoiceBillingSettings{}, Error.Wrap(err)
	}
	return settings, nil
}

// GenerateDueInvoicesForAllResellers creates missing invoices for every reseller
// using each seller's saved billing day/time (catch-up of completed periods).
func (s *Service) GenerateDueInvoicesForAllResellers(ctx context.Context, _ BillingClock) (createdCount int, err error) {
	defer mon.Task()(&ctx)(&err)

	resellers, err := s.store.Resellers().List(ctx)
	if err != nil {
		return 0, Error.Wrap(err)
	}

	for _, r := range resellers {
		clock, cerr := s.InvoiceBillingClockForReseller(ctx, r.ID)
		if cerr != nil {
			s.log.Error("load invoice billing clock failed",
				zap.String("resellerId", r.ID.String()),
				zap.Error(cerr),
			)
			continue
		}
		created, gerr := s.GenerateAllInvoicesForBillingClock(ctx, r.ID, clock, "auto")
		if gerr != nil {
			if ErrValidation.Has(gerr) {
				continue
			}
			s.log.Error("auto invoice generation failed for reseller",
				zap.String("resellerId", r.ID.String()),
				zap.Error(gerr),
			)
			continue
		}
		createdCount += len(created)
	}
	return createdCount, nil
}

// GenerateAllInvoicesForBillingDay creates every missing invoice for day-of-month (1–28) at midnight UTC.
func (s *Service) GenerateAllInvoicesForBillingDay(ctx context.Context, resellerID uuid.UUID, billingDay int, adminNote string) (created []SellerInvoice, err error) {
	return s.GenerateAllInvoicesForBillingClock(ctx, resellerID, BillingClock{Day: billingDay}, adminNote)
}

// GenerateAllInvoicesForBillingClock creates every missing invoice for the chosen day + clock time.
// Each invoice is one calendar month: 1st 00:00 → cutover−1s. Walks back until the first assignment.
func (s *Service) GenerateAllInvoicesForBillingClock(ctx context.Context, resellerID uuid.UUID, clock BillingClock, adminNote string) (created []SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	if err = validateBillingClock(clock); err != nil {
		return nil, err
	}

	now := s.nowFn().UTC()
	asOf := LatestCompletedBillingAsOf(now, clock)
	return s.generateAllInvoicesWalkingAsOf(ctx, resellerID, asOf, adminNote)
}

// GenerateAllInvoicesUpToAsOf walks billing periods ending at asOf, asOf−1 month, …
func (s *Service) GenerateAllInvoicesUpToAsOf(ctx context.Context, resellerID uuid.UUID, asOf time.Time, adminNote string) (created []SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)
	asOf = asOf.UTC()
	day := asOf.Day()
	if day > InvoiceBillingDayMax {
		day = InvoiceBillingDayMax
	}
	if err = validateBillingDay(day); err != nil {
		return nil, err
	}
	asOf = time.Date(asOf.Year(), asOf.Month(), day, asOf.Hour(), asOf.Minute(), 0, 0, time.UTC)
	now := s.nowFn().UTC()
	if asOf.After(now) {
		return nil, ErrValidation.New("as-of date/time must not be in the future")
	}
	return s.generateAllInvoicesWalkingAsOf(ctx, resellerID, asOf, adminNote)
}

func (s *Service) generateAllInvoicesWalkingAsOf(ctx context.Context, resellerID uuid.UUID, asOf time.Time, adminNote string) (created []SellerInvoice, err error) {
	assignments, err := s.store.UserPlanAssignments().ListByResellerID(ctx, resellerID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	var earliest *time.Time
	for _, a := range assignments {
		if a.Status != AssignmentStatusActive && a.Status != AssignmentStatusEnded {
			continue
		}
		start := a.PlanStartsAt.UTC()
		if earliest == nil || start.Before(*earliest) {
			t := start
			earliest = &t
		}
	}
	if earliest == nil {
		return nil, ErrValidation.New("no billable assignments for this seller")
	}

	existing, err := s.store.SellerInvoices().ListByResellerID(ctx, resellerID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	cursor := asOf.UTC()
	const maxPeriods = 240
	for i := 0; i < maxPeriods; i++ {
		start, end := InvoicePeriodFromAsOf(cursor)
		if end.Before(*earliest) {
			break
		}

		already := false
		for _, inv := range existing {
			if inv.Status == InvoiceStatusCancelled {
				continue
			}
			if sameInvoicePeriod(inv.PeriodStart, inv.PeriodEnd, start, end) ||
				invoicePeriodsOverlap(inv.PeriodStart, inv.PeriodEnd, start, end) {
				already = true
				break
			}
		}
		if !already {
			inv, gerr := s.GenerateInvoice(ctx, resellerID, GenerateInvoiceRequest{
				PeriodStart: start,
				PeriodEnd:   end,
				AdminNote:   adminNote,
			})
			if gerr != nil {
				if !ErrValidation.Has(gerr) {
					return created, gerr
				}
			} else if inv != nil {
				created = append(created, *inv)
				existing = append(existing, *inv)
			}
		}

		cursor = cursor.AddDate(0, -1, 0)
	}

	if len(created) == 0 {
		return nil, ErrValidation.New("no new invoices to generate: completed periods already have invoices, or no plan assignments started in those periods yet (plans bill after the cutover day/time)")
	}
	return created, nil
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
		return nil, ErrValidation.New("invoice period must end in the past; pick an as-of date/time that has already passed")
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
		if invoicePeriodsOverlap(inv.PeriodStart, inv.PeriodEnd, req.PeriodStart, req.PeriodEnd) {
			return nil, ErrValidation.New("invoice period overlaps an existing invoice")
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
	if _, err = s.store.SellerInvoices().Update(ctx, inv); err != nil {
		return nil, Error.Wrap(err)
	}
	// Single read path: lines + seller party for slip/UI.
	return s.loadInvoiceDetail(ctx, id)
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

// ApplyDuePlanSwitches is the plan cron:
//  1. notify sellers/users ~7 days before plan end (if notifyBeforeEnd)
//  2. when a scheduled future plan's start time is due → end current, activate future,
//     apply quotas, then re-schedule that same plan again for the next period
//  3. expire actives past plan_ends_at with no future left
func (s *Service) ApplyDuePlanSwitches(ctx context.Context) (applied int, err error) {
	defer mon.Task()(&ctx)(&err)

	now := s.nowFn().UTC()

	notifyBefore := now.Add(7 * 24 * time.Hour)
	needing, err := s.store.UserPlanAssignments().ListNeedingEndNotification(ctx, notifyBefore)
	if err != nil {
		return 0, Error.Wrap(err)
	}
	for _, a := range needing {
		if a.PlanEndsAt == nil || a.PlanEndsAt.After(notifyBefore) {
			continue
		}
		uid := a.UserID
		_, _ = s.store.BillingNotifications().Insert(ctx, &BillingNotification{
			ResellerID: a.ResellerID,
			UserID:     &uid,
			Type:       NotificationTypePlanEnding,
			Title:      "Plan ending soon",
			Body:       fmt.Sprintf("User plan ends on %s.", a.PlanEndsAt.Format("2006-01-02")),
		})
		notified := now
		a.NotifiedEndingAt = &notified
		_, _ = s.store.UserPlanAssignments().Update(ctx, a.ID, &a)
	}

	due, err := s.store.UserPlanAssignments().ListDueScheduled(ctx, now)
	if err != nil {
		return 0, Error.Wrap(err)
	}
	for i := range due {
		if ok := s.activateFutureAssignment(ctx, &due[i], now); ok {
			applied++
		}
	}

	// Actives past end with FuturePlanID but missing/late scheduled row — still switch.
	expired, err := s.store.UserPlanAssignments().ListDueAutoSwitch(ctx, now)
	if err != nil {
		return applied, Error.Wrap(err)
	}
	for i := range expired {
		a := &expired[i]
		if a.Status != AssignmentStatusActive {
			continue
		}
		// Already switched above if a due scheduled existed.
		if _, serr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, a.UserID, AssignmentStatusScheduled); serr == nil {
			continue
		}
		if a.FuturePlanID != nil {
			plan, perr := s.store.SellerPlans().Get(ctx, *a.FuturePlanID)
			if perr != nil || plan == nil {
				s.log.Error("future plan missing on expire",
					zap.String("plan_id", a.FuturePlanID.String()), zap.Error(perr))
			} else {
				synth := &UserPlanAssignment{
					ResellerID:         a.ResellerID,
					UserID:             a.UserID,
					PlanID:             *a.FuturePlanID,
					Status:             AssignmentStatusScheduled,
					RetailAmount:       plan.RetailAmount,
					WholesaleAmount:    plan.WholesaleAmount,
					BillingPeriod:      plan.BillingPeriod,
					PlanStartsAt:       now,
					NotifyBeforeEnd:    a.NotifyBeforeEnd,
					AssignedByReseller: a.AssignedByReseller,
					PlanName:           plan.Name,
					UserEmail:          a.UserEmail,
				}
				inserted, ierr := s.store.UserPlanAssignments().Insert(ctx, synth)
				if ierr != nil {
					s.log.Error("failed to insert synthetic scheduled on expire", zap.Error(ierr))
				} else if s.activateFutureAssignment(ctx, inserted, now) {
					applied++
					continue
				}
			}
		}
		a.Status = AssignmentStatusEnded
		a.EndedAt = &now
		if _, uerr := s.store.UserPlanAssignments().Update(ctx, a.ID, a); uerr != nil {
			s.log.Error("failed to expire assignment",
				zap.Error(uerr), zap.String("assignment_id", a.ID.String()))
			continue
		}
		// No future plan → downgrade user to free tier.
		if derr := s.downgradeToFree(ctx, a.UserID); derr != nil {
			s.log.Error("failed to downgrade user to free after plan end",
				zap.Error(derr), zap.String("user_id", a.UserID.String()))
		} else {
			uid := a.UserID
			_, _ = s.store.BillingNotifications().Insert(ctx, &BillingNotification{
				ResellerID: a.ResellerID,
				UserID:     &uid,
				Type:       NotificationTypePlanSwitched,
				Title:      "Plan ended",
				Body:       "Plan ended with no future plan; user downgraded to Free.",
			})
		}
	}

	return applied, nil
}

// activateFutureAssignment ends the current active plan and makes sched the new active period,
// then re-schedules the same plan again for after the new period ends.
func (s *Service) activateFutureAssignment(ctx context.Context, sched *UserPlanAssignment, now time.Time) bool {
	if active, aerr := s.store.UserPlanAssignments().GetByUserAndStatus(ctx, sched.UserID, AssignmentStatusActive); aerr == nil {
		if active.ID == sched.ID {
			// Should not happen; scheduled and active are different rows.
		} else {
			active.Status = AssignmentStatusEnded
			active.EndedAt = &now
			if _, uerr := s.store.UserPlanAssignments().Update(ctx, active.ID, active); uerr != nil {
				s.log.Error("failed to end active assignment before switch",
					zap.Error(uerr), zap.String("assignment_id", active.ID.String()))
				return false
			}
		}
	}

	plan, perr := s.store.SellerPlans().Get(ctx, sched.PlanID)
	if perr != nil || plan == nil {
		s.log.Error("scheduled plan missing", zap.String("plan_id", sched.PlanID.String()), zap.Error(perr))
		return false
	}

	duration := assignmentDurationMonths(plan.BillingPeriod)
	ends := now.AddDate(0, duration, 0)
	nextPlanID := sched.PlanID

	sched.Status = AssignmentStatusActive
	sched.PlanStartsAt = now
	sched.PlanEndsAt = &ends
	sched.DurationMonths = &duration
	sched.FuturePlanID = &nextPlanID
	sched.AutoSwitchOnEnd = true
	sched.EndedAt = nil
	sched.NotifiedEndingAt = nil
	if _, uerr := s.store.UserPlanAssignments().Update(ctx, sched.ID, sched); uerr != nil {
		s.log.Error("failed to activate scheduled assignment",
			zap.Error(uerr), zap.String("assignment_id", sched.ID.String()))
		return false
	}

	if s.usersDB != nil {
		if lerr := s.applyPlanLimits(ctx, sched.UserID, plan, &ends); lerr != nil {
			s.log.Error("failed to apply limits after plan switch",
				zap.Error(lerr), zap.String("user_id", sched.UserID.String()))
			return false
		}
	}

	// Re-set future: same plan again for the following period (until seller cancels).
	next := &UserPlanAssignment{
		ResellerID:         sched.ResellerID,
		UserID:             sched.UserID,
		PlanID:             nextPlanID,
		Status:             AssignmentStatusScheduled,
		RetailAmount:       plan.RetailAmount,
		WholesaleAmount:    plan.WholesaleAmount,
		BillingPeriod:      plan.BillingPeriod,
		PlanStartsAt:       ends,
		NotifyBeforeEnd:    sched.NotifyBeforeEnd,
		AssignedByReseller: sched.AssignedByReseller,
		PlanName:           plan.Name,
		UserEmail:          sched.UserEmail,
	}
	if _, ierr := s.store.UserPlanAssignments().Insert(ctx, next); ierr != nil {
		s.log.Error("failed to re-schedule next period",
			zap.Error(ierr), zap.String("user_id", sched.UserID.String()))
		// Active switch still succeeded.
	}

	uid := sched.UserID
	if _, nerr := s.store.BillingNotifications().Insert(ctx, &BillingNotification{
		ResellerID: sched.ResellerID,
		UserID:     &uid,
		Type:       NotificationTypePlanSwitched,
		Title:      "Plan switched",
		Body:       fmt.Sprintf("Plan %s is now active and scheduled again for the next period.", plan.Name),
	}); nerr != nil {
		s.log.Error("failed to insert plan-switched notification", zap.Error(nerr))
	}
	return true
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
