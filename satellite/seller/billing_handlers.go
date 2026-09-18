// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/common/uuid"
)

// SellerBilling exposes seller billing HTTP endpoints.
type SellerBilling struct {
	log     *zap.Logger
	service *Service
}

// NewSellerBilling creates seller billing handlers.
func NewSellerBilling(log *zap.Logger, service *Service) *SellerBilling {
	if log == nil {
		log = zap.NewNop()
	}
	return &SellerBilling{log: log, service: service}
}

// ListUsers GET /users
func (b *SellerBilling) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	cursor := console.UserCursor{Limit: 50, Page: 1}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			cursor.Limit = uint(n)
		}
	}
	if v := r.URL.Query().Get("page"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			cursor.Page = uint(n)
		}
	}

	users, page, err := b.service.ListTenantUsers(ctx, cursor)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"users":       users,
		"limit":       page.Limit,
		"page":        page.CurrentPage,
		"pageCount":   page.PageCount,
		"totalCount":  page.TotalCount,
	})
}

// ListPlans GET /plans
func (b *SellerBilling) ListPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	plans, err := b.service.ListActivePlans(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	_ = json.NewEncoder(w).Encode(plans)
}

// AssignPlan POST /users/{userId}/assign-plan
func (b *SellerBilling) AssignPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	userID, err := uuid.FromString(mux.Vars(r)["userId"])
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid userId"))
		return
	}
	var req AssignPlanRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	active, scheduled, err := b.service.AssignPlan(ctx, userID, req)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrValidation.Has(err) {
			status = http.StatusBadRequest
		} else if ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"active":    active,
		"scheduled": scheduled,
	})
}

// UpdateFuturePlan PATCH /users/{userId}/future-plan
func (b *SellerBilling) UpdateFuturePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	userID, err := uuid.FromString(mux.Vars(r)["userId"])
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid userId"))
		return
	}
	var req UpdateFuturePlanRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	scheduled, err := b.service.UpdateFuturePlan(ctx, userID, req)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrValidation.Has(err) {
			status = http.StatusBadRequest
		} else if ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"scheduled": scheduled})
}

// ListAssignments GET /assignments
func (b *SellerBilling) ListAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	list, err := b.service.ListAssignments(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	_ = json.NewEncoder(w).Encode(list)
}

// ListInvoices GET /invoices
func (b *SellerBilling) ListInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	list, err := b.service.ListInvoices(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	_ = json.NewEncoder(w).Encode(list)
}

// GetInvoice GET /invoices/{id}
func (b *SellerBilling) GetInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid id"))
		return
	}
	inv, err := b.service.GetInvoice(ctx, id)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}
	_ = json.NewEncoder(w).Encode(inv)
}

// ListNotifications GET /billing-notifications
func (b *SellerBilling) ListNotifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	list, err := b.service.ListNotifications(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	_ = json.NewEncoder(w).Encode(list)
}
