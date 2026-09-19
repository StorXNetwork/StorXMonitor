// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

func (db *sellerDB) SellerPlans() seller.SellerPlans {
	return &sellerPlans{db: db.db}
}

func (db *sellerDB) UserPlanAssignments() seller.UserPlanAssignments {
	return &userPlanAssignments{db: db.db}
}

func (db *sellerDB) SellerInvoices() seller.SellerInvoices {
	return &sellerInvoices{db: db.db}
}

func (db *sellerDB) BillingNotifications() seller.BillingNotifications {
	return &billingNotifications{db: db.db}
}

type sellerPlans struct {
	db *satelliteDB
}

func (repo *sellerPlans) Insert(ctx context.Context, plan *seller.SellerPlan) (_ *seller.SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)

	if plan.ID.IsZero() {
		plan.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	plan.CreatedAt = now
	plan.UpdatedAt = now
	if plan.Currency == "" {
		plan.Currency = "INR"
	}
	if plan.Features == nil {
		plan.Features = []string{}
	}
	featuresJSON, err := json.Marshal(plan.Features)
	if err != nil {
		return nil, err
	}

	optional := dbx.SellerPlan_Create_Fields{
		Currency:    dbx.SellerPlan_Currency(plan.Currency),
		Description: dbx.SellerPlan_Description(plan.Description),
		Features:    dbx.SellerPlan_Features(featuresJSON),
		Recommended: dbx.SellerPlan_Recommended(plan.Recommended),
		Active:      dbx.SellerPlan_Active(plan.Active),
	}
	if plan.PaymentPlanID != nil {
		optional.PaymentPlanId = dbx.SellerPlan_PaymentPlanId(*plan.PaymentPlanID)
	}

	row, err := repo.db.Create_SellerPlan(ctx,
		dbx.SellerPlan_Id(plan.ID[:]),
		dbx.SellerPlan_Name(plan.Name),
		dbx.SellerPlan_TierKey(plan.TierKey),
		dbx.SellerPlan_BillingPeriod(plan.BillingPeriod),
		dbx.SellerPlan_StorageBytes(plan.StorageBytes),
		dbx.SellerPlan_BandwidthBytes(plan.BandwidthBytes),
		dbx.SellerPlan_RetailAmount(plan.RetailAmount),
		dbx.SellerPlan_WholesaleAmount(plan.WholesaleAmount),
		dbx.SellerPlan_UpdatedAt(plan.UpdatedAt),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return sellerPlanFromDBX(row)
}

func (repo *sellerPlans) Get(ctx context.Context, id uuid.UUID) (_ *seller.SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_SellerPlan_By_Id(ctx, dbx.SellerPlan_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return sellerPlanFromDBX(row)
}

func (repo *sellerPlans) List(ctx context.Context) (_ []seller.SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerPlan(ctx)
	if err != nil {
		return nil, err
	}
	return sellerPlansFromDBX(rows)
}

func (repo *sellerPlans) ListActive(ctx context.Context) (_ []seller.SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerPlan_By_Active_OrderBy_Asc_Name(ctx, dbx.SellerPlan_Active(true))
	if err != nil {
		return nil, err
	}
	return sellerPlansFromDBX(rows)
}

func (repo *sellerPlans) Update(ctx context.Context, id uuid.UUID, update seller.UpdateSellerPlanRequest) (_ *seller.SellerPlan, err error) {
	defer mon.Task()(&ctx)(&err)

	fields := dbx.SellerPlan_Update_Fields{
		UpdatedAt: dbx.SellerPlan_UpdatedAt(update.UpdatedAt),
	}
	if update.Name != nil {
		fields.Name = dbx.SellerPlan_Name(*update.Name)
	}
	if update.TierKey != nil {
		fields.TierKey = dbx.SellerPlan_TierKey(*update.TierKey)
	}
	if update.BillingPeriod != nil {
		fields.BillingPeriod = dbx.SellerPlan_BillingPeriod(*update.BillingPeriod)
	}
	if update.StorageBytes != nil {
		fields.StorageBytes = dbx.SellerPlan_StorageBytes(*update.StorageBytes)
	}
	if update.BandwidthBytes != nil {
		fields.BandwidthBytes = dbx.SellerPlan_BandwidthBytes(*update.BandwidthBytes)
	}
	if update.RetailAmount != nil {
		fields.RetailAmount = dbx.SellerPlan_RetailAmount(*update.RetailAmount)
	}
	if update.WholesaleAmount != nil {
		fields.WholesaleAmount = dbx.SellerPlan_WholesaleAmount(*update.WholesaleAmount)
	}
	if update.Currency != nil {
		fields.Currency = dbx.SellerPlan_Currency(*update.Currency)
	}
	if update.Description != nil {
		fields.Description = dbx.SellerPlan_Description(*update.Description)
	}
	if update.Features != nil {
		featuresJSON, marshalErr := json.Marshal(*update.Features)
		if marshalErr != nil {
			return nil, marshalErr
		}
		fields.Features = dbx.SellerPlan_Features(featuresJSON)
	}
	if update.Recommended != nil {
		fields.Recommended = dbx.SellerPlan_Recommended(*update.Recommended)
	}
	if update.Active != nil {
		fields.Active = dbx.SellerPlan_Active(*update.Active)
	}
	if update.PaymentPlanID != nil {
		fields.PaymentPlanId = dbx.SellerPlan_PaymentPlanId(*update.PaymentPlanID)
	}

	row, err := repo.db.Update_SellerPlan_By_Id(ctx, dbx.SellerPlan_Id(id[:]), fields)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return sellerPlanFromDBX(row)
}

func (repo *sellerPlans) Deactivate(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	active := false
	_, err = repo.Update(ctx, id, seller.UpdateSellerPlanRequest{
		Active:    &active,
		UpdatedAt: time.Now().UTC(),
	})
	return err
}

func (repo *sellerPlans) ClearRecommendedExcept(ctx context.Context, exceptID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	query := repo.db.Rebind(`
		UPDATE seller_plans
		SET recommended = false, updated_at = ?
		WHERE recommended = true AND id <> ?
	`)
	_, err = repo.db.DB.ExecContext(ctx, query, time.Now().UTC(), exceptID[:])
	return err
}

func sellerPlanFromDBX(row *dbx.SellerPlan) (*seller.SellerPlan, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	features := []string{}
	if len(row.Features) > 0 {
		if err = json.Unmarshal(row.Features, &features); err != nil {
			return nil, err
		}
	}
	plan := &seller.SellerPlan{
		ID:              id,
		Name:            row.Name,
		TierKey:         row.TierKey,
		BillingPeriod:   row.BillingPeriod,
		StorageBytes:    row.StorageBytes,
		BandwidthBytes:  row.BandwidthBytes,
		RetailAmount:    row.RetailAmount,
		WholesaleAmount: row.WholesaleAmount,
		Currency:        row.Currency,
		Description:     row.Description,
		Features:        features,
		Recommended:     row.Recommended,
		Active:          row.Active,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}
	if row.PaymentPlanId != nil {
		plan.PaymentPlanID = row.PaymentPlanId
	}
	return plan, nil
}

func sellerPlansFromDBX(rows []*dbx.SellerPlan) ([]seller.SellerPlan, error) {
	out := make([]seller.SellerPlan, 0, len(rows))
	for _, row := range rows {
		p, err := sellerPlanFromDBX(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

type userPlanAssignments struct {
	db *satelliteDB
}

func (repo *userPlanAssignments) Insert(ctx context.Context, a *seller.UserPlanAssignment) (_ *seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	if a.ID.IsZero() {
		a.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	a.AssignedAt = now
	a.CreatedAt = now
	a.UpdatedAt = now

	optional := dbx.SellerUserPlanAssignment_Create_Fields{
		AutoSwitchOnEnd:     dbx.SellerUserPlanAssignment_AutoSwitchOnEnd(a.AutoSwitchOnEnd),
		NotifyBeforeEnd:     dbx.SellerUserPlanAssignment_NotifyBeforeEnd(a.NotifyBeforeEnd),
		AssignedByReseller: dbx.SellerUserPlanAssignment_AssignedByReseller(a.AssignedByReseller),
	}
	if a.DurationMonths != nil {
		optional.DurationMonths = dbx.SellerUserPlanAssignment_DurationMonths(*a.DurationMonths)
	}
	if a.PlanEndsAt != nil {
		optional.PlanEndsAt = dbx.SellerUserPlanAssignment_PlanEndsAt(*a.PlanEndsAt)
	}
	if a.FuturePlanID != nil {
		optional.FuturePlanId = dbx.SellerUserPlanAssignment_FuturePlanId(a.FuturePlanID[:])
	}
	if a.NotifiedEndingAt != nil {
		optional.NotifiedEndingAt = dbx.SellerUserPlanAssignment_NotifiedEndingAt(*a.NotifiedEndingAt)
	}
	if a.UserPaidAt != nil {
		optional.UserPaidAt = dbx.SellerUserPlanAssignment_UserPaidAt(*a.UserPaidAt)
	}
	if a.Notes != nil {
		optional.Notes = dbx.SellerUserPlanAssignment_Notes(*a.Notes)
	}
	if a.EndedAt != nil {
		optional.EndedAt = dbx.SellerUserPlanAssignment_EndedAt(*a.EndedAt)
	}

	row, err := repo.db.Create_SellerUserPlanAssignment(ctx,
		dbx.SellerUserPlanAssignment_Id(a.ID[:]),
		dbx.SellerUserPlanAssignment_ResellerId(a.ResellerID[:]),
		dbx.SellerUserPlanAssignment_UserId(a.UserID[:]),
		dbx.SellerUserPlanAssignment_PlanId(a.PlanID[:]),
		dbx.SellerUserPlanAssignment_Status(a.Status),
		dbx.SellerUserPlanAssignment_RetailAmount(a.RetailAmount),
		dbx.SellerUserPlanAssignment_WholesaleAmount(a.WholesaleAmount),
		dbx.SellerUserPlanAssignment_BillingPeriod(a.BillingPeriod),
		dbx.SellerUserPlanAssignment_PlanStartsAt(a.PlanStartsAt),
		dbx.SellerUserPlanAssignment_UpdatedAt(a.UpdatedAt),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return assignmentFromDBX(row)
}

func (repo *userPlanAssignments) Get(ctx context.Context, id uuid.UUID) (_ *seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_SellerUserPlanAssignment_By_Id(ctx, dbx.SellerUserPlanAssignment_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return assignmentFromDBX(row)
}

func (repo *userPlanAssignments) GetByUserAndStatus(ctx context.Context, userID uuid.UUID, status string) (_ *seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_SellerUserPlanAssignment_By_UserId_And_Status(ctx,
		dbx.SellerUserPlanAssignment_UserId(userID[:]),
		dbx.SellerUserPlanAssignment_Status(status),
	)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return assignmentFromDBX(row)
}

func (repo *userPlanAssignments) ListByResellerID(ctx context.Context, resellerID uuid.UUID) (_ []seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerUserPlanAssignment_By_ResellerId(ctx, dbx.SellerUserPlanAssignment_ResellerId(resellerID[:]))
	if err != nil {
		return nil, err
	}
	return assignmentsFromDBX(rows)
}

func (repo *userPlanAssignments) ListByResellerIDAndStatus(ctx context.Context, resellerID uuid.UUID, status string) (_ []seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerUserPlanAssignment_By_ResellerId_And_Status(ctx,
		dbx.SellerUserPlanAssignment_ResellerId(resellerID[:]),
		dbx.SellerUserPlanAssignment_Status(status),
	)
	if err != nil {
		return nil, err
	}
	return assignmentsFromDBX(rows)
}

func (repo *userPlanAssignments) ListByUserID(ctx context.Context, userID uuid.UUID) (_ []seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerUserPlanAssignment_By_UserId(ctx, dbx.SellerUserPlanAssignment_UserId(userID[:]))
	if err != nil {
		return nil, err
	}
	return assignmentsFromDBX(rows)
}

func (repo *userPlanAssignments) ListDueScheduled(ctx context.Context, now time.Time) (_ []seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerUserPlanAssignment_By_Status_And_PlanStartsAt_LessOrEqual(ctx,
		dbx.SellerUserPlanAssignment_Status(seller.AssignmentStatusScheduled),
		dbx.SellerUserPlanAssignment_PlanStartsAt(now),
	)
	if err != nil {
		return nil, err
	}
	return assignmentsFromDBX(rows)
}

func (repo *userPlanAssignments) ListDueAutoSwitch(ctx context.Context, now time.Time) (_ []seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	// Returns all active assignments past plan_ends_at (auto_switch true or false).
	withSwitch, err := repo.db.All_SellerUserPlanAssignment_By_Status_And_PlanEndsAt_LessOrEqual_And_AutoSwitchOnEnd(ctx,
		dbx.SellerUserPlanAssignment_Status(seller.AssignmentStatusActive),
		dbx.SellerUserPlanAssignment_PlanEndsAt(now),
		dbx.SellerUserPlanAssignment_AutoSwitchOnEnd(true),
	)
	if err != nil {
		return nil, err
	}
	withoutSwitch, err := repo.db.All_SellerUserPlanAssignment_By_Status_And_PlanEndsAt_LessOrEqual_And_AutoSwitchOnEnd(ctx,
		dbx.SellerUserPlanAssignment_Status(seller.AssignmentStatusActive),
		dbx.SellerUserPlanAssignment_PlanEndsAt(now),
		dbx.SellerUserPlanAssignment_AutoSwitchOnEnd(false),
	)
	if err != nil {
		return nil, err
	}
	rows := append(withSwitch, withoutSwitch...)
	return assignmentsFromDBX(rows)
}

func (repo *userPlanAssignments) ListNeedingEndNotification(ctx context.Context, notifyBefore time.Time) (_ []seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerUserPlanAssignment_By_Status_And_NotifyBeforeEnd_And_PlanEndsAt_LessOrEqual_And_NotifiedEndingAt_Is_Null(ctx,
		dbx.SellerUserPlanAssignment_Status(seller.AssignmentStatusActive),
		dbx.SellerUserPlanAssignment_NotifyBeforeEnd(true),
		dbx.SellerUserPlanAssignment_PlanEndsAt(notifyBefore),
	)
	if err != nil {
		return nil, err
	}
	return assignmentsFromDBX(rows)
}

func (repo *userPlanAssignments) CountByResellerID(ctx context.Context, resellerID uuid.UUID) (count int64, err error) {
	defer mon.Task()(&ctx)(&err)

	c, err := repo.db.Count_SellerUserPlanAssignment_By_ResellerId(ctx, dbx.SellerUserPlanAssignment_ResellerId(resellerID[:]))
	if err != nil {
		return 0, err
	}
	return c, nil
}

func (repo *userPlanAssignments) Update(ctx context.Context, id uuid.UUID, a *seller.UserPlanAssignment) (_ *seller.UserPlanAssignment, err error) {
	defer mon.Task()(&ctx)(&err)

	a.UpdatedAt = time.Now().UTC()
	fields := dbx.SellerUserPlanAssignment_Update_Fields{
		Status:          dbx.SellerUserPlanAssignment_Status(a.Status),
		PlanStartsAt:    dbx.SellerUserPlanAssignment_PlanStartsAt(a.PlanStartsAt),
		AutoSwitchOnEnd: dbx.SellerUserPlanAssignment_AutoSwitchOnEnd(a.AutoSwitchOnEnd),
		NotifyBeforeEnd: dbx.SellerUserPlanAssignment_NotifyBeforeEnd(a.NotifyBeforeEnd),
		UpdatedAt:       dbx.SellerUserPlanAssignment_UpdatedAt(a.UpdatedAt),
	}
	if a.DurationMonths != nil {
		fields.DurationMonths = dbx.SellerUserPlanAssignment_DurationMonths(*a.DurationMonths)
	} else {
		fields.DurationMonths = dbx.SellerUserPlanAssignment_DurationMonths_Null()
	}
	if a.PlanEndsAt != nil {
		fields.PlanEndsAt = dbx.SellerUserPlanAssignment_PlanEndsAt(*a.PlanEndsAt)
	} else {
		fields.PlanEndsAt = dbx.SellerUserPlanAssignment_PlanEndsAt_Null()
	}
	if a.FuturePlanID != nil {
		fields.FuturePlanId = dbx.SellerUserPlanAssignment_FuturePlanId(a.FuturePlanID[:])
	} else {
		fields.FuturePlanId = dbx.SellerUserPlanAssignment_FuturePlanId_Null()
	}
	if a.NotifiedEndingAt != nil {
		fields.NotifiedEndingAt = dbx.SellerUserPlanAssignment_NotifiedEndingAt(*a.NotifiedEndingAt)
	} else {
		fields.NotifiedEndingAt = dbx.SellerUserPlanAssignment_NotifiedEndingAt_Null()
	}
	if a.UserPaidAt != nil {
		fields.UserPaidAt = dbx.SellerUserPlanAssignment_UserPaidAt(*a.UserPaidAt)
	} else {
		fields.UserPaidAt = dbx.SellerUserPlanAssignment_UserPaidAt_Null()
	}
	if a.Notes != nil {
		fields.Notes = dbx.SellerUserPlanAssignment_Notes(*a.Notes)
	} else {
		fields.Notes = dbx.SellerUserPlanAssignment_Notes_Null()
	}
	if a.EndedAt != nil {
		fields.EndedAt = dbx.SellerUserPlanAssignment_EndedAt(*a.EndedAt)
	} else {
		fields.EndedAt = dbx.SellerUserPlanAssignment_EndedAt_Null()
	}

	row, err := repo.db.Update_SellerUserPlanAssignment_By_Id(ctx, dbx.SellerUserPlanAssignment_Id(id[:]), fields)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return assignmentFromDBX(row)
}

func assignmentFromDBX(row *dbx.SellerUserPlanAssignment) (*seller.UserPlanAssignment, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	resellerID, err := uuid.FromBytes(row.ResellerId)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}
	planID, err := uuid.FromBytes(row.PlanId)
	if err != nil {
		return nil, err
	}
	a := &seller.UserPlanAssignment{
		ID:                 id,
		ResellerID:         resellerID,
		UserID:             userID,
		PlanID:             planID,
		Status:             row.Status,
		RetailAmount:       row.RetailAmount,
		WholesaleAmount:    row.WholesaleAmount,
		BillingPeriod:      row.BillingPeriod,
		DurationMonths:     row.DurationMonths,
		PlanStartsAt:       row.PlanStartsAt,
		PlanEndsAt:         row.PlanEndsAt,
		AutoSwitchOnEnd:    row.AutoSwitchOnEnd,
		NotifyBeforeEnd:    row.NotifyBeforeEnd,
		NotifiedEndingAt:   row.NotifiedEndingAt,
		UserPaidAt:         row.UserPaidAt,
		Notes:              row.Notes,
		AssignedAt:         row.AssignedAt,
		EndedAt:            row.EndedAt,
		AssignedByReseller: row.AssignedByReseller,
		CreatedAt:          row.CreatedAt,
		UpdatedAt:          row.UpdatedAt,
	}
	if len(row.FuturePlanId) > 0 {
		fp, err := uuid.FromBytes(row.FuturePlanId)
		if err != nil {
			return nil, err
		}
		a.FuturePlanID = &fp
	}
	return a, nil
}

func assignmentsFromDBX(rows []*dbx.SellerUserPlanAssignment) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0, len(rows))
	for _, row := range rows {
		a, err := assignmentFromDBX(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, nil
}

type sellerInvoices struct {
	db *satelliteDB
}

func (repo *sellerInvoices) Insert(ctx context.Context, inv *seller.SellerInvoice) (_ *seller.SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	if inv.ID.IsZero() {
		inv.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	inv.CreatedAt = now
	inv.UpdatedAt = now
	if inv.Currency == "" {
		inv.Currency = "INR"
	}

	optional := dbx.SellerInvoice_Create_Fields{
		Currency: dbx.SellerInvoice_Currency(inv.Currency),
	}
	if inv.IssuedAt != nil {
		optional.IssuedAt = dbx.SellerInvoice_IssuedAt(*inv.IssuedAt)
	}
	if inv.PaidAt != nil {
		optional.PaidAt = dbx.SellerInvoice_PaidAt(*inv.PaidAt)
	}
	if inv.AdminNote != nil {
		optional.AdminNote = dbx.SellerInvoice_AdminNote(*inv.AdminNote)
	}

	row, err := repo.db.Create_SellerInvoice(ctx,
		dbx.SellerInvoice_Id(inv.ID[:]),
		dbx.SellerInvoice_ResellerId(inv.ResellerID[:]),
		dbx.SellerInvoice_PeriodStart(inv.PeriodStart),
		dbx.SellerInvoice_PeriodEnd(inv.PeriodEnd),
		dbx.SellerInvoice_TotalAmount(inv.TotalAmount),
		dbx.SellerInvoice_Status(inv.Status),
		dbx.SellerInvoice_UpdatedAt(inv.UpdatedAt),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return invoiceFromDBX(row)
}

func (repo *sellerInvoices) Get(ctx context.Context, id uuid.UUID) (_ *seller.SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := repo.db.Get_SellerInvoice_By_Id(ctx, dbx.SellerInvoice_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return invoiceFromDBX(row)
}

func (repo *sellerInvoices) ListByResellerID(ctx context.Context, resellerID uuid.UUID) (_ []seller.SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerInvoice_By_ResellerId(ctx, dbx.SellerInvoice_ResellerId(resellerID[:]))
	if err != nil {
		return nil, err
	}
	out := make([]seller.SellerInvoice, 0, len(rows))
	for _, row := range rows {
		inv, convErr := invoiceFromDBX(row)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *inv)
	}
	return out, nil
}

func (repo *sellerInvoices) Update(ctx context.Context, inv *seller.SellerInvoice) (_ *seller.SellerInvoice, err error) {
	defer mon.Task()(&ctx)(&err)

	inv.UpdatedAt = time.Now().UTC()
	fields := dbx.SellerInvoice_Update_Fields{
		TotalAmount: dbx.SellerInvoice_TotalAmount(inv.TotalAmount),
		Currency:    dbx.SellerInvoice_Currency(inv.Currency),
		Status:      dbx.SellerInvoice_Status(inv.Status),
		UpdatedAt:   dbx.SellerInvoice_UpdatedAt(inv.UpdatedAt),
	}
	if inv.IssuedAt != nil {
		fields.IssuedAt = dbx.SellerInvoice_IssuedAt(*inv.IssuedAt)
	} else {
		fields.IssuedAt = dbx.SellerInvoice_IssuedAt_Null()
	}
	if inv.PaidAt != nil {
		fields.PaidAt = dbx.SellerInvoice_PaidAt(*inv.PaidAt)
	} else {
		fields.PaidAt = dbx.SellerInvoice_PaidAt_Null()
	}
	if inv.AdminNote != nil {
		fields.AdminNote = dbx.SellerInvoice_AdminNote(*inv.AdminNote)
	} else {
		fields.AdminNote = dbx.SellerInvoice_AdminNote_Null()
	}

	row, err := repo.db.Update_SellerInvoice_By_Id(ctx, dbx.SellerInvoice_Id(inv.ID[:]), fields)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}
	return invoiceFromDBX(row)
}

func (repo *sellerInvoices) InsertLine(ctx context.Context, line *seller.SellerInvoiceLine) (_ *seller.SellerInvoiceLine, err error) {
	defer mon.Task()(&ctx)(&err)

	if line.ID.IsZero() {
		line.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	line.CreatedAt = time.Now().UTC()

	row, err := repo.db.Create_SellerInvoiceLine(ctx,
		dbx.SellerInvoiceLine_Id(line.ID[:]),
		dbx.SellerInvoiceLine_InvoiceId(line.InvoiceID[:]),
		dbx.SellerInvoiceLine_AssignmentId(line.AssignmentID[:]),
		dbx.SellerInvoiceLine_UserId(line.UserID[:]),
		dbx.SellerInvoiceLine_PlanId(line.PlanID[:]),
		dbx.SellerInvoiceLine_Description(line.Description),
		dbx.SellerInvoiceLine_Amount(line.Amount),
		dbx.SellerInvoiceLine_RetailAmount(line.RetailAmount),
		dbx.SellerInvoiceLine_AssignedAt(line.AssignedAt),
	)
	if err != nil {
		return nil, err
	}
	return invoiceLineFromDBX(row)
}

func (repo *sellerInvoices) ListLines(ctx context.Context, invoiceID uuid.UUID) (_ []seller.SellerInvoiceLine, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerInvoiceLine_By_InvoiceId(ctx, dbx.SellerInvoiceLine_InvoiceId(invoiceID[:]))
	if err != nil {
		return nil, err
	}
	out := make([]seller.SellerInvoiceLine, 0, len(rows))
	for _, row := range rows {
		line, convErr := invoiceLineFromDBX(row)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *line)
	}
	return out, nil
}

func invoiceFromDBX(row *dbx.SellerInvoice) (*seller.SellerInvoice, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	resellerID, err := uuid.FromBytes(row.ResellerId)
	if err != nil {
		return nil, err
	}
	return &seller.SellerInvoice{
		ID:          id,
		ResellerID:  resellerID,
		PeriodStart: row.PeriodStart,
		PeriodEnd:   row.PeriodEnd,
		TotalAmount: row.TotalAmount,
		Currency:    row.Currency,
		Status:      row.Status,
		IssuedAt:    row.IssuedAt,
		PaidAt:      row.PaidAt,
		AdminNote:   row.AdminNote,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

func invoiceLineFromDBX(row *dbx.SellerInvoiceLine) (*seller.SellerInvoiceLine, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	invoiceID, err := uuid.FromBytes(row.InvoiceId)
	if err != nil {
		return nil, err
	}
	assignmentID, err := uuid.FromBytes(row.AssignmentId)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}
	planID, err := uuid.FromBytes(row.PlanId)
	if err != nil {
		return nil, err
	}
	return &seller.SellerInvoiceLine{
		ID:           id,
		InvoiceID:    invoiceID,
		AssignmentID: assignmentID,
		UserID:       userID,
		PlanID:       planID,
		Description:  row.Description,
		Amount:       row.Amount,
		RetailAmount: row.RetailAmount,
		AssignedAt:   row.AssignedAt,
		CreatedAt:    row.CreatedAt,
	}, nil
}

type billingNotifications struct {
	db *satelliteDB
}

func (repo *billingNotifications) Insert(ctx context.Context, n *seller.BillingNotification) (_ *seller.BillingNotification, err error) {
	defer mon.Task()(&ctx)(&err)

	if n.ID.IsZero() {
		n.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	n.CreatedAt = time.Now().UTC()

	optional := dbx.SellerBillingNotification_Create_Fields{
		Read: dbx.SellerBillingNotification_Read(n.Read),
	}
	if n.UserID != nil {
		optional.UserId = dbx.SellerBillingNotification_UserId(n.UserID[:])
	}

	row, err := repo.db.Create_SellerBillingNotification(ctx,
		dbx.SellerBillingNotification_Id(n.ID[:]),
		dbx.SellerBillingNotification_ResellerId(n.ResellerID[:]),
		dbx.SellerBillingNotification_Type(n.Type),
		dbx.SellerBillingNotification_Title(n.Title),
		dbx.SellerBillingNotification_Body(n.Body),
		optional,
	)
	if err != nil {
		return nil, err
	}
	return notificationFromDBX(row)
}

func (repo *billingNotifications) ListByResellerID(ctx context.Context, resellerID uuid.UUID) (_ []seller.BillingNotification, err error) {
	defer mon.Task()(&ctx)(&err)

	rows, err := repo.db.All_SellerBillingNotification_By_ResellerId(ctx, dbx.SellerBillingNotification_ResellerId(resellerID[:]))
	if err != nil {
		return nil, err
	}
	out := make([]seller.BillingNotification, 0, len(rows))
	for _, row := range rows {
		n, convErr := notificationFromDBX(row)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *n)
	}
	return out, nil
}

func (repo *billingNotifications) MarkRead(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = repo.db.Update_SellerBillingNotification_By_Id(ctx,
		dbx.SellerBillingNotification_Id(id[:]),
		dbx.SellerBillingNotification_Update_Fields{
			Read: dbx.SellerBillingNotification_Read(true),
		},
	)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return seller.ErrNotFound.New("")
		}
		return err
	}
	return nil
}

func notificationFromDBX(row *dbx.SellerBillingNotification) (*seller.BillingNotification, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	resellerID, err := uuid.FromBytes(row.ResellerId)
	if err != nil {
		return nil, err
	}
	n := &seller.BillingNotification{
		ID:         id,
		ResellerID: resellerID,
		Type:       row.Type,
		Title:      row.Title,
		Body:       row.Body,
		Read:       row.Read,
		CreatedAt:  row.CreatedAt,
	}
	if len(row.UserId) > 0 {
		uid, err := uuid.FromBytes(row.UserId)
		if err != nil {
			return nil, err
		}
		n.UserID = &uid
	}
	return n, nil
}
