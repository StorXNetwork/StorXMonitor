// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"errors"

	"github.com/StorXNetwork/StorXMonitor/satellite/payments/gateway"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/common/uuid"
)

type paymentCustomers struct{ db dbx.DriverMethods }
type paymentMethods struct{ db dbx.DriverMethods }
type paymentAttempts struct{ db dbx.DriverMethods }
type paymentSubscriptions struct{ db dbx.DriverMethods }
type paymentEvents struct{ db dbx.DriverMethods }

func (p *paymentCustomers) Upsert(ctx context.Context, customer gateway.Customer) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = p.db.Get_PaymentCustomers_By_UserId_And_Provider(ctx,
		dbx.PaymentCustomers_UserId(customer.UserID[:]),
		dbx.PaymentCustomers_Provider(customer.Provider),
	)
	if err == nil {
		_, _ = p.db.Delete_PaymentCustomers_By_UserId_And_Provider(ctx,
			dbx.PaymentCustomers_UserId(customer.UserID[:]),
			dbx.PaymentCustomers_Provider(customer.Provider),
		)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = p.db.Create_PaymentCustomers(ctx,
		dbx.PaymentCustomers_UserId(customer.UserID[:]),
		dbx.PaymentCustomers_Provider(customer.Provider),
		dbx.PaymentCustomers_ProviderCustomerId(customer.ProviderCustomerID),
	)
	return err
}

func (p *paymentCustomers) GetByUserID(ctx context.Context, userID uuid.UUID, provider string) (_ *gateway.Customer, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentCustomers_By_UserId_And_Provider(ctx,
		dbx.PaymentCustomers_UserId(userID[:]),
		dbx.PaymentCustomers_Provider(provider),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentCustomer(row)
}

func (p *paymentCustomers) GetByProviderCustomerID(ctx context.Context, provider, providerCustomerID string) (_ *gateway.Customer, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentCustomers_By_Provider_And_ProviderCustomerId(ctx,
		dbx.PaymentCustomers_Provider(provider),
		dbx.PaymentCustomers_ProviderCustomerId(providerCustomerID),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentCustomer(row)
}

func fromDBXPaymentCustomer(row *dbx.PaymentCustomers) (*gateway.Customer, error) {
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}
	return &gateway.Customer{
		UserID:             userID,
		Provider:           row.Provider,
		ProviderCustomerID: row.ProviderCustomerId,
		CreatedAt:          row.CreatedAt,
	}, nil
}

func (p *paymentMethods) Insert(ctx context.Context, method gateway.PaymentMethod) (_ *gateway.PaymentMethod, err error) {
	defer mon.Task()(&ctx)(&err)
	if method.ID.IsZero() {
		method.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	row, err := p.db.Create_PaymentMethods(ctx,
		dbx.PaymentMethods_Id(method.ID[:]),
		dbx.PaymentMethods_UserId(method.UserID[:]),
		dbx.PaymentMethods_Provider(method.Provider),
		dbx.PaymentMethods_ProviderMethodId(method.ProviderMethodID),
		dbx.PaymentMethods_Brand(method.Brand),
		dbx.PaymentMethods_Last4(method.Last4),
		dbx.PaymentMethods_ExpMonth(method.ExpMonth),
		dbx.PaymentMethods_ExpYear(method.ExpYear),
		dbx.PaymentMethods_IsDefault(method.IsDefault),
	)
	if err != nil {
		return nil, err
	}
	return fromDBXPaymentMethod(row)
}

func (p *paymentMethods) ListByUserID(ctx context.Context, userID uuid.UUID, provider string) (methods []gateway.PaymentMethod, err error) {
	defer mon.Task()(&ctx)(&err)
	rows, err := p.db.All_PaymentMethods_By_UserId_And_Provider(ctx,
		dbx.PaymentMethods_UserId(userID[:]),
		dbx.PaymentMethods_Provider(provider),
	)
	if err != nil {
		return nil, err
	}
	methods = make([]gateway.PaymentMethod, 0, len(rows))
	for _, row := range rows {
		m, err := fromDBXPaymentMethod(row)
		if err != nil {
			return nil, err
		}
		methods = append(methods, *m)
	}
	return methods, nil
}

func (p *paymentMethods) GetByID(ctx context.Context, id uuid.UUID) (_ *gateway.PaymentMethod, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentMethods_By_Id(ctx, dbx.PaymentMethods_Id(id[:]))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentMethod(row)
}

func (p *paymentMethods) GetByProviderMethodID(ctx context.Context, provider, providerMethodID string) (_ *gateway.PaymentMethod, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentMethods_By_Provider_And_ProviderMethodId(ctx,
		dbx.PaymentMethods_Provider(provider),
		dbx.PaymentMethods_ProviderMethodId(providerMethodID),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentMethod(row)
}

func (p *paymentMethods) GetDefault(ctx context.Context, userID uuid.UUID, provider string) (_ *gateway.PaymentMethod, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentMethods_By_UserId_And_Provider_And_IsDefault(ctx,
		dbx.PaymentMethods_UserId(userID[:]),
		dbx.PaymentMethods_Provider(provider),
		dbx.PaymentMethods_IsDefault(true),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentMethod(row)
}

func (p *paymentMethods) SetDefault(ctx context.Context, userID uuid.UUID, provider string, methodID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	methods, err := p.ListByUserID(ctx, userID, provider)
	if err != nil {
		return err
	}
	found := false
	for _, m := range methods {
		isDefault := m.ID == methodID
		if isDefault {
			found = true
		}
		_, err = p.db.Update_PaymentMethods_By_Id(ctx,
			dbx.PaymentMethods_Id(m.ID[:]),
			dbx.PaymentMethods_Update_Fields{
				IsDefault: dbx.PaymentMethods_IsDefault(isDefault),
			},
		)
		if err != nil {
			return err
		}
	}
	if !found {
		return gateway.ErrNotFound
	}
	return nil
}

func (p *paymentMethods) Delete(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = p.db.Delete_PaymentMethods_By_Id(ctx, dbx.PaymentMethods_Id(id[:]))
	return err
}

func fromDBXPaymentMethod(row *dbx.PaymentMethods) (*gateway.PaymentMethod, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}
	return &gateway.PaymentMethod{
		ID:               id,
		UserID:           userID,
		Provider:         row.Provider,
		ProviderMethodID: row.ProviderMethodId,
		Brand:            row.Brand,
		Last4:            row.Last4,
		ExpMonth:         row.ExpMonth,
		ExpYear:          row.ExpYear,
		IsDefault:        row.IsDefault,
		CreatedAt:        row.CreatedAt,
	}, nil
}

func (p *paymentAttempts) Insert(ctx context.Context, attempt gateway.Attempt) (_ *gateway.Attempt, err error) {
	defer mon.Task()(&ctx)(&err)
	if attempt.ID.IsZero() {
		attempt.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	fields := dbx.PaymentAttempts_Create_Fields{}
	if attempt.CouponCode != nil {
		fields.CouponCode = dbx.PaymentAttempts_CouponCode(*attempt.CouponCode)
	}
	if attempt.Metadata != nil {
		fields.Metadata = dbx.PaymentAttempts_Metadata(attempt.Metadata)
	}
	row, err := p.db.Create_PaymentAttempts(ctx,
		dbx.PaymentAttempts_Id(attempt.ID[:]),
		dbx.PaymentAttempts_UserId(attempt.UserID[:]),
		dbx.PaymentAttempts_PlanId(attempt.PlanID),
		dbx.PaymentAttempts_Provider(attempt.Provider),
		dbx.PaymentAttempts_ProviderRef(attempt.ProviderRef),
		dbx.PaymentAttempts_AmountMinor(attempt.AmountMinor),
		dbx.PaymentAttempts_Currency(attempt.Currency),
		dbx.PaymentAttempts_Status(string(attempt.Status)),
		fields,
	)
	if err != nil {
		return nil, err
	}
	return fromDBXPaymentAttempt(row)
}

func (p *paymentAttempts) UpdateProviderRef(ctx context.Context, id uuid.UUID, providerRef string) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = p.db.Update_PaymentAttempts_By_Id(ctx,
		dbx.PaymentAttempts_Id(id[:]),
		dbx.PaymentAttempts_Update_Fields{
			ProviderRef: dbx.PaymentAttempts_ProviderRef(providerRef),
		},
	)
	return err
}

func (p *paymentAttempts) UpdateStatus(ctx context.Context, id uuid.UUID, status gateway.AttemptStatus) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = p.db.Update_PaymentAttempts_By_Id(ctx,
		dbx.PaymentAttempts_Id(id[:]),
		dbx.PaymentAttempts_Update_Fields{
			Status: dbx.PaymentAttempts_Status(string(status)),
		},
	)
	return err
}

func (p *paymentAttempts) GetByID(ctx context.Context, id uuid.UUID) (_ *gateway.Attempt, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentAttempts_By_Id(ctx, dbx.PaymentAttempts_Id(id[:]))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentAttempt(row)
}

func (p *paymentAttempts) GetByProviderRef(ctx context.Context, provider, providerRef string) (_ *gateway.Attempt, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentAttempts_By_Provider_And_ProviderRef(ctx,
		dbx.PaymentAttempts_Provider(provider),
		dbx.PaymentAttempts_ProviderRef(providerRef),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentAttempt(row)
}

func fromDBXPaymentAttempt(row *dbx.PaymentAttempts) (*gateway.Attempt, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}
	a := &gateway.Attempt{
		ID:          id,
		UserID:      userID,
		PlanID:      row.PlanId,
		Provider:    row.Provider,
		ProviderRef: row.ProviderRef,
		AmountMinor: row.AmountMinor,
		Currency:    row.Currency,
		Status:      gateway.AttemptStatus(row.Status),
		Metadata:    row.Metadata,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	if row.CouponCode != nil {
		a.CouponCode = row.CouponCode
	}
	return a, nil
}

func (p *paymentSubscriptions) Insert(ctx context.Context, sub gateway.LocalSubscription) (_ *gateway.LocalSubscription, err error) {
	defer mon.Task()(&ctx)(&err)
	if sub.ID.IsZero() {
		sub.ID, err = uuid.New()
		if err != nil {
			return nil, err
		}
	}
	fields := dbx.PaymentSubscriptions_Create_Fields{}
	if sub.CurrentPeriodEnd != nil {
		fields.CurrentPeriodEnd = dbx.PaymentSubscriptions_CurrentPeriodEnd(*sub.CurrentPeriodEnd)
	}
	if sub.DefaultMethodID != nil {
		fields.DefaultMethodId = dbx.PaymentSubscriptions_DefaultMethodId(sub.DefaultMethodID[:])
	}
	if sub.CouponCode != nil {
		fields.CouponCode = dbx.PaymentSubscriptions_CouponCode(*sub.CouponCode)
	}
	row, err := p.db.Create_PaymentSubscriptions(ctx,
		dbx.PaymentSubscriptions_Id(sub.ID[:]),
		dbx.PaymentSubscriptions_UserId(sub.UserID[:]),
		dbx.PaymentSubscriptions_PlanId(sub.PlanID),
		dbx.PaymentSubscriptions_Provider(sub.Provider),
		dbx.PaymentSubscriptions_ProviderSubId(sub.ProviderSubID),
		dbx.PaymentSubscriptions_ProviderPlanId(sub.ProviderPlanID),
		dbx.PaymentSubscriptions_Status(string(sub.Status)),
		dbx.PaymentSubscriptions_CancelAtPeriodEnd(sub.CancelAtPeriodEnd),
		fields,
	)
	if err != nil {
		return nil, err
	}
	return fromDBXPaymentSubscription(row)
}

func (p *paymentSubscriptions) Update(ctx context.Context, sub gateway.LocalSubscription) (err error) {
	defer mon.Task()(&ctx)(&err)
	uf := dbx.PaymentSubscriptions_Update_Fields{
		Status:            dbx.PaymentSubscriptions_Status(string(sub.Status)),
		CancelAtPeriodEnd: dbx.PaymentSubscriptions_CancelAtPeriodEnd(sub.CancelAtPeriodEnd),
	}
	if sub.CurrentPeriodEnd != nil {
		uf.CurrentPeriodEnd = dbx.PaymentSubscriptions_CurrentPeriodEnd(*sub.CurrentPeriodEnd)
	} else {
		uf.CurrentPeriodEnd = dbx.PaymentSubscriptions_CurrentPeriodEnd_Null()
	}
	if sub.DefaultMethodID != nil {
		uf.DefaultMethodId = dbx.PaymentSubscriptions_DefaultMethodId(sub.DefaultMethodID[:])
	}
	_, err = p.db.Update_PaymentSubscriptions_By_Id(ctx, dbx.PaymentSubscriptions_Id(sub.ID[:]), uf)
	return err
}

func (p *paymentSubscriptions) GetByID(ctx context.Context, id uuid.UUID) (_ *gateway.LocalSubscription, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentSubscriptions_By_Id(ctx, dbx.PaymentSubscriptions_Id(id[:]))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentSubscription(row)
}

func (p *paymentSubscriptions) GetByProviderSubID(ctx context.Context, provider, providerSubID string) (_ *gateway.LocalSubscription, err error) {
	defer mon.Task()(&ctx)(&err)
	row, err := p.db.Get_PaymentSubscriptions_By_Provider_And_ProviderSubId(ctx,
		dbx.PaymentSubscriptions_Provider(provider),
		dbx.PaymentSubscriptions_ProviderSubId(providerSubID),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, gateway.ErrNotFound
		}
		return nil, err
	}
	return fromDBXPaymentSubscription(row)
}

func (p *paymentSubscriptions) GetActiveByUserID(ctx context.Context, userID uuid.UUID, provider string) (_ *gateway.LocalSubscription, err error) {
	defer mon.Task()(&ctx)(&err)
	rows, err := p.db.All_PaymentSubscriptions_By_UserId_And_Provider(ctx,
		dbx.PaymentSubscriptions_UserId(userID[:]),
		dbx.PaymentSubscriptions_Provider(provider),
	)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		sub, err := fromDBXPaymentSubscription(row)
		if err != nil {
			return nil, err
		}
		switch sub.Status {
		case gateway.SubActive, gateway.SubCreated, gateway.SubPastDue:
			return sub, nil
		}
	}
	return nil, gateway.ErrNotFound
}

func fromDBXPaymentSubscription(row *dbx.PaymentSubscriptions) (*gateway.LocalSubscription, error) {
	id, err := uuid.FromBytes(row.Id)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromBytes(row.UserId)
	if err != nil {
		return nil, err
	}
	sub := &gateway.LocalSubscription{
		ID:                id,
		UserID:            userID,
		PlanID:            row.PlanId,
		Provider:          row.Provider,
		ProviderSubID:     row.ProviderSubId,
		ProviderPlanID:    row.ProviderPlanId,
		Status:            gateway.SubscriptionStatus(row.Status),
		CurrentPeriodEnd:  row.CurrentPeriodEnd,
		CancelAtPeriodEnd: row.CancelAtPeriodEnd,
		CouponCode:        row.CouponCode,
		CreatedAt:         row.CreatedAt,
		UpdatedAt:         row.UpdatedAt,
	}
	if row.DefaultMethodId != nil {
		mid, err := uuid.FromBytes(row.DefaultMethodId)
		if err != nil {
			return nil, err
		}
		sub.DefaultMethodID = &mid
	}
	return sub, nil
}

func (p *paymentEvents) Insert(ctx context.Context, event gateway.Event) (err error) {
	defer mon.Task()(&ctx)(&err)
	if event.ID.IsZero() {
		event.ID, err = uuid.New()
		if err != nil {
			return err
		}
	}
	fields := dbx.PaymentEvents_Create_Fields{}
	if event.AttemptID != nil {
		fields.AttemptId = dbx.PaymentEvents_AttemptId(event.AttemptID[:])
	}
	if event.SubscriptionID != nil {
		fields.SubscriptionId = dbx.PaymentEvents_SubscriptionId(event.SubscriptionID[:])
	}
	_, err = p.db.Create_PaymentEvents(ctx,
		dbx.PaymentEvents_Id(event.ID[:]),
		dbx.PaymentEvents_Provider(event.Provider),
		dbx.PaymentEvents_ProviderEventId(event.ProviderEventID),
		dbx.PaymentEvents_EventType(event.EventType),
		dbx.PaymentEvents_Payload(event.Payload),
		fields,
	)
	if err != nil {
		if dbx.IsConstraintError(err) {
			return gateway.ErrConflict
		}
		return err
	}
	return nil
}

func (p *paymentEvents) Exists(ctx context.Context, provider, providerEventID string) (exists bool, err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = p.db.Get_PaymentEvents_Id_By_Provider_And_ProviderEventId(ctx,
		dbx.PaymentEvents_Provider(provider),
		dbx.PaymentEvents_ProviderEventId(providerEventID),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
