// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

type memPlans struct {
	byID map[uuid.UUID]*seller.SellerPlan
}

func (m *memPlans) Insert(ctx context.Context, plan *seller.SellerPlan) (*seller.SellerPlan, error) {
	if plan.ID.IsZero() {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		plan.ID = id
	}
	now := time.Now().UTC()
	plan.CreatedAt = now
	plan.UpdatedAt = now
	cp := *plan
	m.byID[plan.ID] = &cp
	return &cp, nil
}
func (m *memPlans) Get(ctx context.Context, id uuid.UUID) (*seller.SellerPlan, error) {
	p, ok := m.byID[id]
	if !ok {
		return nil, seller.ErrNotFound.New("")
	}
	cp := *p
	return &cp, nil
}
func (m *memPlans) List(ctx context.Context) ([]seller.SellerPlan, error) {
	out := make([]seller.SellerPlan, 0, len(m.byID))
	for _, p := range m.byID {
		out = append(out, *p)
	}
	return out, nil
}
func (m *memPlans) ListActive(ctx context.Context) ([]seller.SellerPlan, error) {
	out := make([]seller.SellerPlan, 0)
	for _, p := range m.byID {
		if p.Active {
			out = append(out, *p)
		}
	}
	return out, nil
}
func (m *memPlans) Update(ctx context.Context, id uuid.UUID, update seller.UpdateSellerPlanRequest) (*seller.SellerPlan, error) {
	p, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if update.Active != nil {
		p.Active = *update.Active
	}
	if update.Name != nil {
		p.Name = *update.Name
	}
	p.UpdatedAt = update.UpdatedAt
	m.byID[id] = p
	return p, nil
}
func (m *memPlans) Deactivate(ctx context.Context, id uuid.UUID) error {
	active := false
	_, err := m.Update(ctx, id, seller.UpdateSellerPlanRequest{Active: &active, UpdatedAt: time.Now().UTC()})
	return err
}

func (m *memPlans) ClearRecommendedExcept(ctx context.Context, exceptID uuid.UUID) error {
	for id, p := range m.byID {
		if id != exceptID {
			p.Recommended = false
		}
	}
	return nil
}

type memAssignments struct {
	items []*seller.UserPlanAssignment
}

func (m *memAssignments) Insert(ctx context.Context, a *seller.UserPlanAssignment) (*seller.UserPlanAssignment, error) {
	if a.ID.IsZero() {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		a.ID = id
	}
	now := time.Now().UTC()
	a.AssignedAt = now
	a.CreatedAt = now
	a.UpdatedAt = now
	cp := *a
	m.items = append(m.items, &cp)
	out := cp
	return &out, nil
}
func (m *memAssignments) Get(ctx context.Context, id uuid.UUID) (*seller.UserPlanAssignment, error) {
	for _, a := range m.items {
		if a.ID == id {
			cp := *a
			return &cp, nil
		}
	}
	return nil, seller.ErrNotFound.New("")
}
func (m *memAssignments) GetByUserAndStatus(ctx context.Context, userID uuid.UUID, status string) (*seller.UserPlanAssignment, error) {
	for _, a := range m.items {
		if a.UserID == userID && a.Status == status {
			cp := *a
			return &cp, nil
		}
	}
	return nil, seller.ErrNotFound.New("")
}
func (m *memAssignments) ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0)
	for _, a := range m.items {
		if a.ResellerID == resellerID {
			out = append(out, *a)
		}
	}
	return out, nil
}
func (m *memAssignments) ListByResellerIDAndStatus(ctx context.Context, resellerID uuid.UUID, status string) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0)
	for _, a := range m.items {
		if a.ResellerID == resellerID && a.Status == status {
			out = append(out, *a)
		}
	}
	return out, nil
}
func (m *memAssignments) ListByUserID(ctx context.Context, userID uuid.UUID) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0)
	for _, a := range m.items {
		if a.UserID == userID {
			out = append(out, *a)
		}
	}
	return out, nil
}
func (m *memAssignments) ListDueScheduled(ctx context.Context, now time.Time) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0)
	for _, a := range m.items {
		if a.Status == seller.AssignmentStatusScheduled && !a.PlanStartsAt.After(now) {
			out = append(out, *a)
		}
	}
	return out, nil
}
func (m *memAssignments) ListDueAutoSwitch(ctx context.Context, now time.Time) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0)
	for _, a := range m.items {
		if a.Status == seller.AssignmentStatusActive && a.PlanEndsAt != nil && !a.PlanEndsAt.After(now) {
			out = append(out, *a)
		}
	}
	return out, nil
}
func (m *memAssignments) ListNeedingEndNotification(ctx context.Context, notifyBefore time.Time) ([]seller.UserPlanAssignment, error) {
	out := make([]seller.UserPlanAssignment, 0)
	for _, a := range m.items {
		if a.Status == seller.AssignmentStatusActive && a.NotifyBeforeEnd && a.NotifiedEndingAt == nil && a.PlanEndsAt != nil && !a.PlanEndsAt.After(notifyBefore) {
			out = append(out, *a)
		}
	}
	return out, nil
}
func (m *memAssignments) CountByResellerID(ctx context.Context, resellerID uuid.UUID) (int64, error) {
	var n int64
	for _, a := range m.items {
		if a.ResellerID == resellerID {
			n++
		}
	}
	return n, nil
}
func (m *memAssignments) Update(ctx context.Context, id uuid.UUID, a *seller.UserPlanAssignment) (*seller.UserPlanAssignment, error) {
	for i, existing := range m.items {
		if existing.ID == id {
			cp := *a
			cp.ID = id
			m.items[i] = &cp
			out := cp
			return &out, nil
		}
	}
	return nil, seller.ErrNotFound.New("")
}

type memInvoices struct {
	items []*seller.SellerInvoice
	lines []*seller.SellerInvoiceLine
}

func (m *memInvoices) Insert(ctx context.Context, inv *seller.SellerInvoice) (*seller.SellerInvoice, error) {
	if inv.ID.IsZero() {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		inv.ID = id
	}
	cp := *inv
	m.items = append(m.items, &cp)
	out := cp
	return &out, nil
}
func (m *memInvoices) Get(ctx context.Context, id uuid.UUID) (*seller.SellerInvoice, error) {
	for _, inv := range m.items {
		if inv.ID == id {
			cp := *inv
			return &cp, nil
		}
	}
	return nil, seller.ErrNotFound.New("")
}
func (m *memInvoices) ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]seller.SellerInvoice, error) {
	out := make([]seller.SellerInvoice, 0)
	for _, inv := range m.items {
		if inv.ResellerID == resellerID {
			out = append(out, *inv)
		}
	}
	return out, nil
}
func (m *memInvoices) Update(ctx context.Context, inv *seller.SellerInvoice) (*seller.SellerInvoice, error) {
	for i, existing := range m.items {
		if existing.ID == inv.ID {
			cp := *inv
			m.items[i] = &cp
			out := cp
			return &out, nil
		}
	}
	return nil, seller.ErrNotFound.New("")
}
func (m *memInvoices) InsertLine(ctx context.Context, line *seller.SellerInvoiceLine) (*seller.SellerInvoiceLine, error) {
	if line.ID.IsZero() {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		line.ID = id
	}
	cp := *line
	m.lines = append(m.lines, &cp)
	out := cp
	return &out, nil
}
func (m *memInvoices) ListLines(ctx context.Context, invoiceID uuid.UUID) ([]seller.SellerInvoiceLine, error) {
	out := make([]seller.SellerInvoiceLine, 0)
	for _, line := range m.lines {
		if line.InvoiceID == invoiceID {
			out = append(out, *line)
		}
	}
	return out, nil
}

type memNotifications struct {
	items []*seller.BillingNotification
}

func (m *memNotifications) Insert(ctx context.Context, n *seller.BillingNotification) (*seller.BillingNotification, error) {
	if n.ID.IsZero() {
		id, err := uuid.New()
		if err != nil {
			return nil, err
		}
		n.ID = id
	}
	cp := *n
	m.items = append(m.items, &cp)
	out := cp
	return &out, nil
}
func (m *memNotifications) ListByResellerID(ctx context.Context, resellerID uuid.UUID) ([]seller.BillingNotification, error) {
	out := make([]seller.BillingNotification, 0)
	for _, n := range m.items {
		if n.ResellerID == resellerID {
			out = append(out, *n)
		}
	}
	return out, nil
}
func (m *memNotifications) MarkRead(ctx context.Context, id uuid.UUID) error { return nil }

type memResellers struct {
	byID map[uuid.UUID]*seller.Reseller
}

func (m *memResellers) Get(ctx context.Context, id uuid.UUID) (*seller.Reseller, error) {
	r, ok := m.byID[id]
	if !ok {
		return nil, seller.ErrNotFound.New("")
	}
	cp := *r
	return &cp, nil
}
func (m *memResellers) GetByEmail(ctx context.Context, email string) (*seller.Reseller, error) {
	return nil, seller.ErrNotFound.New("")
}
func (m *memResellers) GetByEmailAnyStatus(ctx context.Context, email string) (*seller.Reseller, error) {
	return nil, seller.ErrNotFound.New("")
}
func (m *memResellers) GetByEmailWithUnverified(ctx context.Context, email string) (*seller.Reseller, []seller.Reseller, error) {
	return nil, nil, seller.ErrNotFound.New("")
}
func (m *memResellers) Insert(ctx context.Context, reseller *seller.Reseller) (*seller.Reseller, error) {
	return reseller, nil
}
func (m *memResellers) Update(ctx context.Context, id uuid.UUID, update seller.UpdateResellerRequest) (*seller.Reseller, error) {
	return m.Get(ctx, id)
}
func (m *memResellers) List(ctx context.Context) ([]seller.Reseller, error) {
	out := make([]seller.Reseller, 0, len(m.byID))
	for _, r := range m.byID {
		out = append(out, *r)
	}
	return out, nil
}

type billingTestDB struct {
	plans         *memPlans
	assignments   *memAssignments
	invoices      *memInvoices
	notifications *memNotifications
	resellers     *memResellers
}

func (d *billingTestDB) Resellers() seller.Resellers                             { return d.resellers }
func (d *billingTestDB) ResellerConfigs() seller.ResellerConfigs                 { return nil }
func (d *billingTestDB) ResellerDomains() seller.ResellerDomains                 { return nil }
func (d *billingTestDB) ThemePresets() seller.ThemePresets                       { return nil }
func (d *billingTestDB) ResellerThemes() seller.ResellerThemes                   { return nil }
func (d *billingTestDB) WebappSessionResellers() seller.WebappSessionResellers   { return nil }
func (d *billingTestDB) ResetPasswordTokens() seller.ResellerResetPasswordTokens { return nil }
func (d *billingTestDB) ResellerDeleteRequests() seller.ResellerDeleteRequests   { return nil }
func (d *billingTestDB) SellerPlans() seller.SellerPlans                         { return d.plans }
func (d *billingTestDB) UserPlanAssignments() seller.UserPlanAssignments         { return d.assignments }
func (d *billingTestDB) SellerInvoices() seller.SellerInvoices                   { return d.invoices }
func (d *billingTestDB) BillingNotifications() seller.BillingNotifications       { return d.notifications }

type memUsers struct {
	byID     map[uuid.UUID]*console.User
	limits   map[uuid.UUID]console.UsageLimits
	paidTier map[uuid.UUID]bool
}

func (m *memUsers) Get(ctx context.Context, id uuid.UUID) (*console.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return nil, seller.ErrNotFound.New("user")
	}
	cp := *u
	return &cp, nil
}
func (m *memUsers) GetPagedByTenantID(ctx context.Context, tenantID string, cursor console.UserCursor) (*console.UsersPage, error) {
	page := &console.UsersPage{Limit: cursor.Limit, CurrentPage: cursor.Page}
	for _, u := range m.byID {
		if u.TenantID != nil && *u.TenantID == tenantID {
			page.Users = append(page.Users, *u)
		}
	}
	page.TotalCount = uint64(len(page.Users))
	return page, nil
}
func (m *memUsers) UpdateUserProjectLimits(ctx context.Context, id uuid.UUID, limits console.UsageLimits) error {
	m.limits[id] = limits
	return nil
}
func (m *memUsers) UpdatePaidTiers(ctx context.Context, id uuid.UUID, paidTier bool) error {
	m.paidTier[id] = paidTier
	return nil
}

// Remaining Users interface methods panic — only used methods are implemented above via embedding trick.
// We use a narrow adapter in tests through SetUsersDB with a typed wrapper.

type usersAdapter struct {
	*memUsers
}

// Satisfy console.Users by embedding and providing stubs for unused methods — use a compile-time
// check via assignPlan which only needs Get / UpdateUserProjectLimits / UpdatePaidTiers / GetPagedByTenantID.

func newBillingService(t *testing.T, store *billingTestDB, users *memUsers) *seller.Service {
	t.Helper()
	svc, err := seller.NewService(
		zaptest.NewLogger(t),
		store,
		nil,
		consoleauth.NewService(consoleauth.Config{TokenExpirationTime: time.Hour}, &consoleauth.Hmac{Secret: []byte("test")}),
		seller.AuthConfig{},
		"http://localhost",
		false,
	)
	require.NoError(t, err)
	svc.SetUsersDB(&billingUsers{mem: users})
	svc.SetProjectsDB(&memProjects{})
	return svc
}

// memProjects is a minimal console.Projects stub for plan-limit tests.
type memProjects struct {
	console.Projects
	byOwner map[uuid.UUID][]console.Project
	limits  map[uuid.UUID]console.UsageLimits
}

func (m *memProjects) GetOwn(ctx context.Context, userID uuid.UUID) ([]console.Project, error) {
	if m.byOwner == nil {
		return nil, nil
	}
	return m.byOwner[userID], nil
}

func (m *memProjects) UpdateUsageLimits(ctx context.Context, id uuid.UUID, limits console.UsageLimits) error {
	if m.limits == nil {
		m.limits = map[uuid.UUID]console.UsageLimits{}
	}
	m.limits[id] = limits
	return nil
}

// billingUsers implements only the Users methods billing needs; others return zero values.
type billingUsers struct {
	mem *memUsers
	console.Users
}

func (b *billingUsers) Get(ctx context.Context, id uuid.UUID) (*console.User, error) {
	return b.mem.Get(ctx, id)
}
func (b *billingUsers) GetPagedByTenantID(ctx context.Context, tenantID string, cursor console.UserCursor) (*console.UsersPage, error) {
	return b.mem.GetPagedByTenantID(ctx, tenantID, cursor)
}
func (b *billingUsers) UpdateUserProjectLimits(ctx context.Context, id uuid.UUID, limits console.UsageLimits) error {
	return b.mem.UpdateUserProjectLimits(ctx, id, limits)
}
func (b *billingUsers) UpdatePaidTiers(ctx context.Context, id uuid.UUID, paidTier bool) error {
	return b.mem.UpdatePaidTiers(ctx, id, paidTier)
}

func TestCreatePlanAndAssignAppliesLimits(t *testing.T) {
	ctx := context.Background()
	resellerID, err := uuid.New()
	require.NoError(t, err)
	userID, err := uuid.New()
	require.NoError(t, err)
	tenant := resellerID.String()

	store := &billingTestDB{
		plans:         &memPlans{byID: map[uuid.UUID]*seller.SellerPlan{}},
		assignments:   &memAssignments{},
		invoices:      &memInvoices{},
		notifications: &memNotifications{},
		resellers:     &memResellers{byID: map[uuid.UUID]*seller.Reseller{resellerID: {ID: resellerID, Email: "s@test.com", Status: seller.ResellerActive}}},
	}
	users := &memUsers{
		byID: map[uuid.UUID]*console.User{
			userID: {ID: userID, Email: "u@test.com", FullName: "User", TenantID: &tenant, Status: console.Active},
		},
		limits:   map[uuid.UUID]console.UsageLimits{},
		paidTier: map[uuid.UUID]bool{},
	}
	svc := newBillingService(t, store, users)

	plan, err := svc.CreatePlan(ctx, seller.CreateSellerPlanRequest{
		Name: "Basic", TierKey: "basic", BillingPeriod: seller.BillingPeriodMonth,
		StorageBytes: 100e9, BandwidthBytes: 200e9, RetailAmount: 1000, WholesaleAmount: 800,
	})
	require.NoError(t, err)
	require.True(t, plan.Active)

	ctx = seller.WithReseller(ctx, &seller.Reseller{ID: resellerID, Email: "s@test.com"})
	future, err := svc.CreatePlan(ctx, seller.CreateSellerPlanRequest{
		Name: "Pro", TierKey: "pro", BillingPeriod: seller.BillingPeriodMonth,
		StorageBytes: 500e9, BandwidthBytes: 1000e9, RetailAmount: 2500, WholesaleAmount: 2000,
	})
	require.NoError(t, err)

	active, scheduled, err := svc.AssignPlan(ctx, userID, seller.AssignPlanRequest{
		PlanID: plan.ID, FuturePlanID: &future.ID,
		AutoSwitchOnEnd: true, NotifyBeforeEnd: true, UserPaid: true,
	})
	require.NoError(t, err)
	require.NotNil(t, active)
	require.Equal(t, seller.AssignmentStatusActive, active.Status)
	require.Equal(t, int64(1000), active.RetailAmount)
	require.Equal(t, int64(800), active.WholesaleAmount)
	require.NotNil(t, active.DurationMonths)
	require.Equal(t, 1, *active.DurationMonths)
	require.NotNil(t, scheduled)
	require.Equal(t, seller.AssignmentStatusScheduled, scheduled.Status)
	require.Equal(t, future.ID, scheduled.PlanID)

	lim := users.limits[userID]
	require.Equal(t, int64(100e9), lim.Storage)
	require.Equal(t, int64(200e9), lim.Bandwidth)
	require.True(t, users.paidTier[userID])
}

func TestApplyDuePlanSwitchesAndInvoice(t *testing.T) {
	ctx := context.Background()
	resellerID, err := uuid.New()
	require.NoError(t, err)
	userID, err := uuid.New()
	require.NoError(t, err)
	tenant := resellerID.String()

	store := &billingTestDB{
		plans:         &memPlans{byID: map[uuid.UUID]*seller.SellerPlan{}},
		assignments:   &memAssignments{},
		invoices:      &memInvoices{},
		notifications: &memNotifications{},
		resellers:     &memResellers{byID: map[uuid.UUID]*seller.Reseller{resellerID: {ID: resellerID}}},
	}
	users := &memUsers{
		byID: map[uuid.UUID]*console.User{
			userID: {ID: userID, Email: "u@test.com", TenantID: &tenant, Status: console.Active},
		},
		limits:   map[uuid.UUID]console.UsageLimits{},
		paidTier: map[uuid.UUID]bool{},
	}
	svc := newBillingService(t, store, users)

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	svc.TestSetNow(func() time.Time { return now })

	planA, err := svc.CreatePlan(ctx, seller.CreateSellerPlanRequest{
		Name: "A", TierKey: "a", BillingPeriod: seller.BillingPeriodMonth,
		StorageBytes: 1, BandwidthBytes: 1, RetailAmount: 1000, WholesaleAmount: 800,
	})
	require.NoError(t, err)
	planB, err := svc.CreatePlan(ctx, seller.CreateSellerPlanRequest{
		Name: "B", TierKey: "b", BillingPeriod: seller.BillingPeriodMonth,
		StorageBytes: 2, BandwidthBytes: 2, RetailAmount: 2500, WholesaleAmount: 2000,
	})
	require.NoError(t, err)

	ctx = seller.WithReseller(ctx, &seller.Reseller{ID: resellerID})
	_, _, err = svc.AssignPlan(ctx, userID, seller.AssignPlanRequest{
		PlanID: planA.ID, FuturePlanID: &planB.ID, AutoSwitchOnEnd: true, NotifyBeforeEnd: true, UserPaid: true,
	})
	require.NoError(t, err)

	// Second user assigned in the same month (before switch).
	user2, err := uuid.New()
	require.NoError(t, err)
	users.byID[user2] = &console.User{ID: user2, Email: "u2@test.com", TenantID: &tenant, Status: console.Active}
	_, _, err = svc.AssignPlan(ctx, user2, seller.AssignPlanRequest{PlanID: planA.ID, UserPaid: true})
	require.NoError(t, err)

	// Cannot change paid plan.
	_, _, err = svc.AssignPlan(ctx, userID, seller.AssignPlanRequest{PlanID: planB.ID})
	require.True(t, seller.ErrValidation.Has(err))

	// Jump past end so scheduled becomes due.
	later := now.AddDate(0, 1, 1) // 2 Oct
	svc.TestSetNow(func() time.Time { return later })
	applied, err := svc.ApplyDuePlanSwitches(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, applied, 1)

	active, err := store.assignments.GetByUserAndStatus(ctx, userID, seller.AssignmentStatusActive)
	require.NoError(t, err)
	require.Equal(t, planB.ID, active.PlanID)
	require.Equal(t, int64(2), users.limits[userID].Storage)

	notes, err := store.notifications.ListByResellerID(ctx, resellerID)
	require.NoError(t, err)
	require.NotEmpty(t, notes)

	// Last completed month relative to 2 Oct = September.
	inv, err := svc.GenerateLastMonthInvoice(ctx, resellerID, later, "")
	require.NoError(t, err)
	require.Equal(t, seller.InvoiceStatusPending, inv.Status)
	require.Equal(t, int64(1600), inv.TotalAmount) // user1 A 800 + user2 A 800

	_, err = svc.GenerateLastMonthInvoice(ctx, resellerID, later, "")
	require.True(t, seller.ErrValidation.Has(err), "duplicate period must be rejected")

	updated, err := svc.UpdateInvoiceStatus(ctx, inv.ID, seller.UpdateInvoiceStatusRequest{Status: seller.InvoiceStatusPaymentReceived})
	require.NoError(t, err)
	require.Equal(t, seller.InvoiceStatusPaymentReceived, updated.Status)
	require.NotNil(t, updated.PaidAt)
}
