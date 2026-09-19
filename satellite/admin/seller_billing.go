// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

func (server *Server) listSellerPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	plans, err := server.sellerService.ListAllPlans(ctx)
	if err != nil {
		sendJSONError(w, "failed to list plans", err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.Marshal(plans)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) createSellerPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body", err.Error(), http.StatusBadRequest)
		return
	}
	var req seller.CreateSellerPlanRequest
	if err = json.Unmarshal(body, &req); err != nil {
		sendJSONError(w, "invalid request", err.Error(), http.StatusBadRequest)
		return
	}
	plan, err := server.sellerService.CreatePlan(ctx, req)
	if err != nil {
		status := http.StatusInternalServerError
		if seller.ErrValidation.Has(err) {
			status = http.StatusBadRequest
		}
		sendJSONError(w, "failed to create plan", err.Error(), status)
		return
	}
	data, _ := json.Marshal(plan)
	sendJSONData(w, http.StatusCreated, data)
}

func (server *Server) updateSellerPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	planID, err := uuid.FromString(mux.Vars(r)["planId"])
	if err != nil {
		sendJSONError(w, "invalid planId", err.Error(), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body", err.Error(), http.StatusBadRequest)
		return
	}
	var input struct {
		Name            *string   `json:"name"`
		TierKey         *string   `json:"tierKey"`
		BillingPeriod   *string   `json:"billingPeriod"`
		StorageBytes    *int64    `json:"storageBytes"`
		BandwidthBytes  *int64    `json:"bandwidthBytes"`
		RetailAmount    *int64    `json:"retailAmount"`
		WholesaleAmount *int64    `json:"wholesaleAmount"`
		Currency        *string   `json:"currency"`
		Description     *string   `json:"description"`
		Features        *[]string `json:"features"`
		Recommended     *bool     `json:"recommended"`
		Active          *bool     `json:"active"`
	}
	if err = json.Unmarshal(body, &input); err != nil {
		sendJSONError(w, "invalid request", err.Error(), http.StatusBadRequest)
		return
	}
	plan, err := server.sellerService.UpdatePlan(ctx, planID, seller.UpdateSellerPlanRequest{
		Name:            input.Name,
		TierKey:         input.TierKey,
		BillingPeriod:   input.BillingPeriod,
		StorageBytes:    input.StorageBytes,
		BandwidthBytes:  input.BandwidthBytes,
		RetailAmount:    input.RetailAmount,
		WholesaleAmount: input.WholesaleAmount,
		Currency:        input.Currency,
		Description:     input.Description,
		Features:        input.Features,
		Recommended:     input.Recommended,
		Active:          input.Active,
		UpdatedAt:       time.Now().UTC(),
	})
	if err != nil {
		status := http.StatusInternalServerError
		if seller.ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to update plan", err.Error(), status)
		return
	}
	data, _ := json.Marshal(plan)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) deactivateSellerPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	planID, err := uuid.FromString(mux.Vars(r)["planId"])
	if err != nil {
		sendJSONError(w, "invalid planId", err.Error(), http.StatusBadRequest)
		return
	}
	if err = server.sellerService.DeactivatePlan(ctx, planID); err != nil {
		status := http.StatusInternalServerError
		if seller.ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to deactivate plan", err.Error(), status)
		return
	}
	sendJSONData(w, http.StatusOK, []byte(`{"ok":true}`))
}

func (server *Server) listResellers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	summaries, err := server.sellerService.ListResellerSummaries(ctx)
	if err != nil {
		sendJSONError(w, "failed to list resellers", err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.Marshal(summaries)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) getReseller(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
	reseller, err := server.sellerService.GetResellerDetail(ctx, id)
	if err != nil {
		status := http.StatusInternalServerError
		if seller.ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to get reseller", err.Error(), status)
		return
	}
	data, _ := json.Marshal(reseller)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) listResellerUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
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
	users, page, err := server.sellerService.ListTenantUsersForReseller(ctx, id, cursor)
	if err != nil {
		sendJSONError(w, "failed to list users", err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.Marshal(map[string]any{
		"users":      users,
		"limit":      page.Limit,
		"page":       page.CurrentPage,
		"pageCount":  page.PageCount,
		"totalCount": page.TotalCount,
	})
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) listResellerAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
	list, err := server.sellerService.ListAssignmentsForReseller(ctx, id)
	if err != nil {
		sendJSONError(w, "failed to list assignments", err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.Marshal(list)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) listResellerInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
	list, err := server.sellerService.ListInvoicesForReseller(ctx, id)
	if err != nil {
		sendJSONError(w, "failed to list invoices", err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.Marshal(list)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) generateResellerInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body", err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		PeriodStart *time.Time `json:"periodStart"`
		PeriodEnd   *time.Time `json:"periodEnd"`
		AsOf        *time.Time `json:"asOf"`
		BillingDay  *int       `json:"billingDay"`
		Hour        *int       `json:"hour"`
		Minute      *int       `json:"minute"`
		AdminNote   string     `json:"adminNote"`
	}
	if len(body) > 0 {
		if err = json.Unmarshal(body, &req); err != nil {
			sendJSONError(w, "invalid request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	var inv *seller.SellerInvoice
	var created []seller.SellerInvoice
	// Manual default: last completed period only. Optional overrides for day/time or explicit bounds.
	switch {
	case req.PeriodStart != nil && req.PeriodEnd != nil:
		inv, err = server.sellerService.GenerateInvoice(ctx, id, seller.GenerateInvoiceRequest{
			PeriodStart: *req.PeriodStart,
			PeriodEnd:   *req.PeriodEnd,
			AdminNote:   req.AdminNote,
		})
		if err == nil && inv != nil {
			created = []seller.SellerInvoice{*inv}
		}
	case req.BillingDay != nil:
		clock := seller.BillingClock{Day: *req.BillingDay}
		if req.Hour != nil {
			clock.Hour = *req.Hour
		}
		if req.Minute != nil {
			clock.Minute = *req.Minute
		}
		inv, err = server.sellerService.GenerateLastCompletedInvoice(ctx, id, clock, req.AdminNote)
		if err == nil && inv != nil {
			created = []seller.SellerInvoice{*inv}
		}
	case req.AsOf != nil:
		created, err = server.sellerService.GenerateAllInvoicesUpToAsOf(ctx, id, req.AsOf.UTC(), req.AdminNote)
	default:
		// Manual button: current date → last completed period if not yet generated.
		inv, err = server.sellerService.GenerateLastCompletedInvoice(ctx, id, seller.BillingClock{}, req.AdminNote)
		if err == nil && inv != nil {
			created = []seller.SellerInvoice{*inv}
		}
	}
	if err != nil {
		status := http.StatusInternalServerError
		if seller.ErrValidation.Has(err) {
			status = http.StatusBadRequest
		}
		sendJSONError(w, "failed to generate invoice", err.Error(), status)
		return
	}
	// Keep single-invoice clients working: return latest created, plus full list.
	resp := struct {
		Invoice  *seller.SellerInvoice  `json:"invoice,omitempty"`
		Invoices []seller.SellerInvoice `json:"invoices"`
		Count    int                    `json:"count"`
	}{
		Invoices: created,
		Count:    len(created),
	}
	if len(created) > 0 {
		last := created[0]
		resp.Invoice = &last
	}
	data, _ := json.Marshal(resp)
	sendJSONData(w, http.StatusCreated, data)
}

func (server *Server) getSellerInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
	inv, err := server.sellerService.GetInvoiceAdmin(ctx, id)
	if err != nil {
		status := http.StatusInternalServerError
		if seller.ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to get invoice", err.Error(), status)
		return
	}
	data, _ := json.Marshal(inv)
	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) updateSellerInvoiceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if server.sellerService == nil {
		sendJSONError(w, "seller service unavailable", "", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.FromString(mux.Vars(r)["id"])
	if err != nil {
		sendJSONError(w, "invalid id", err.Error(), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body", err.Error(), http.StatusBadRequest)
		return
	}
	var req seller.UpdateInvoiceStatusRequest
	if err = json.Unmarshal(body, &req); err != nil {
		sendJSONError(w, "invalid request", err.Error(), http.StatusBadRequest)
		return
	}
	inv, err := server.sellerService.UpdateInvoiceStatus(ctx, id, req)
	if err != nil {
		status := http.StatusInternalServerError
		if seller.ErrValidation.Has(err) {
			status = http.StatusBadRequest
		} else if seller.ErrNotFound.Has(err) {
			status = http.StatusNotFound
		}
		sendJSONError(w, "failed to update invoice", err.Error(), status)
		return
	}
	data, _ := json.Marshal(inv)
	sendJSONData(w, http.StatusOK, data)
}
