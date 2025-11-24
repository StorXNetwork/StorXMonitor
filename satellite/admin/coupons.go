// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"storj.io/storj/satellite/payments/billing"
)

// createCoupon handles POST /api/coupons - Create a new coupon (Admin-only).
func (server *Server) createCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Code           string    `json:"code"`
		Discount       float64   `json:"discount"`
		DiscountType   string    `json:"discount_type"`
		MaxDiscount    float64   `json:"max_discount"`
		MinOrderAmount float64   `json:"min_order_amount"`
		ValidFrom      time.Time `json:"valid_from"`
		ValidTo        time.Time `json:"valid_to"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if input.Code == "" {
		sendJSONError(w, "code is required", "", http.StatusBadRequest)
		return
	}
	if input.DiscountType != "percentage" && input.DiscountType != "fixed" {
		sendJSONError(w, "discount_type must be 'percentage' or 'fixed'", "", http.StatusBadRequest)
		return
	}
	if input.ValidFrom.IsZero() {
		sendJSONError(w, "valid_from is required", "", http.StatusBadRequest)
		return
	}
	if input.ValidTo.IsZero() {
		sendJSONError(w, "valid_to is required", "", http.StatusBadRequest)
		return
	}
	if input.ValidTo.Before(input.ValidFrom) {
		sendJSONError(w, "valid_to must be after valid_from", "", http.StatusBadRequest)
		return
	}

	// Create coupon
	newCoupon := billing.Coupons{
		Code:           input.Code,
		Discount:       input.Discount,
		DiscountType:   input.DiscountType,
		MaxDiscount:    input.MaxDiscount,
		MinOrderAmount: input.MinOrderAmount,
		ValidFrom:      input.ValidFrom,
		ValidTo:        input.ValidTo,
		CreatedAt:      time.Now(),
	}

	createdCoupon, err := server.db.Billing().CreateCoupon(ctx, newCoupon)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "already exists") {
			sendJSONError(w, "coupon already exists",
				errMsg, http.StatusConflict)
			return
		}
		sendJSONError(w, "failed to create coupon",
			errMsg, http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(createdCoupon)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusCreated, data)
}

// getCoupon handles GET /api/coupons/{code} - Get coupon by code (Admin-only).
func (server *Server) getCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	code, ok := vars["code"]
	if !ok || code == "" {
		sendJSONError(w, "code is required", "", http.StatusBadRequest)
		return
	}

	coupon, err := server.db.Billing().GetCouponByCode(ctx, code)
	if err != nil {
		sendJSONError(w, "failed to get coupon",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(coupon)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// listCoupons handles GET /api/coupons - List all coupons with filters and pagination (Admin-only).
func (server *Server) listCoupons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Parse query parameters
	filters := billing.CouponFilters{}

	// Status filter: 1=active, 2=expired, 3=upcoming
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		if status, err := strconv.Atoi(statusStr); err == nil && (status == 1 || status == 2 || status == 3) {
			filters.Status = &status
		}
	}

	// DiscountType filter
	if discountType := r.URL.Query().Get("discount_type"); discountType != "" {
		filters.DiscountType = &discountType
	}

	// Parse date range filters (only custom dates, no preset ranges)
	query := r.URL.Query()
	validAfterStr := query.Get("valid_after")   // Start date (format: 2006-01-02)
	validBeforeStr := query.Get("valid_before") // End date (format: 2006-01-02)

	var validAfter, validBefore *time.Time

	if validAfterStr != "" {
		parsedTime, err := time.Parse("2006-01-02", validAfterStr)
		if err != nil {
			sendJSONError(w, "Bad request", fmt.Sprintf("invalid valid_after date format: %v", err), http.StatusBadRequest)
			return
		}
		startOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 0, 0, 0, 0, parsedTime.Location())
		validAfter = &startOfDay
	}

	if validBeforeStr != "" {
		parsedTime, err := time.Parse("2006-01-02", validBeforeStr)
		if err != nil {
			sendJSONError(w, "Bad request", fmt.Sprintf("invalid valid_before date format: %v", err), http.StatusBadRequest)
			return
		}
		endOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 23, 59, 59, 999999999, parsedTime.Location())
		validBefore = &endOfDay
	}

	// Set overlap filter if both dates are provided
	if validAfter != nil && validBefore != nil {
		filters.ValidDuringStart = validAfter
		filters.ValidDuringEnd = validBefore
	}

	// Code filter (partial match)
	if code := r.URL.Query().Get("code"); code != "" {
		filters.Code = &code
	}

	// Pagination
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filters.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filters.Offset = offset
		}
	}

	// Ordering
	if orderBy := r.URL.Query().Get("order_by"); orderBy != "" {
		filters.OrderBy = orderBy
	}
	if orderDirection := r.URL.Query().Get("order_direction"); orderDirection != "" {
		filters.OrderDirection = orderDirection
	}

	// Get coupons with filters and pagination
	coupons, total, err := server.db.Billing().GetCouponsWithFilters(ctx, filters)
	if err != nil {
		sendJSONError(w, "failed to list coupons",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Calculate has_more only if pagination is used
	var hasMore *bool
	if filters.Limit > 0 {
		hasMoreValue := int64(filters.Offset+filters.Limit) < total
		hasMore = &hasMoreValue
	}

	// Build response with pagination metadata
	response := struct {
		Coupons []billing.Coupons `json:"coupons"`
		Total   int64             `json:"total"`
		Limit   *int              `json:"limit,omitempty"`
		Offset  *int              `json:"offset,omitempty"`
		HasMore *bool             `json:"has_more,omitempty"`
	}{
		Coupons: coupons,
		Total:   total,
	}

	// Only include pagination fields if pagination is used
	if filters.Limit > 0 {
		response.Limit = &filters.Limit
		response.Offset = &filters.Offset
		response.HasMore = hasMore
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// getCouponStats handles GET /api/coupons/stats - Get coupon statistics (Admin-only).
func (server *Server) getCouponStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	stats, err := server.db.Billing().GetCouponStats(ctx)
	if err != nil {
		sendJSONError(w, "failed to get coupon stats",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(stats)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// updateCoupon handles PUT /api/coupons/{code} - Update coupon (Admin-only).
func (server *Server) updateCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	code, ok := vars["code"]
	if !ok || code == "" {
		sendJSONError(w, "code is required", "", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Discount       *float64   `json:"discount,omitempty"`
		DiscountType   *string    `json:"discount_type,omitempty"`
		MaxDiscount    *float64   `json:"max_discount,omitempty"`
		MinOrderAmount *float64   `json:"min_order_amount,omitempty"`
		ValidFrom      *time.Time `json:"valid_from,omitempty"`
		ValidTo        *time.Time `json:"valid_to,omitempty"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Get existing coupon
	existingCoupon, err := server.db.Billing().GetCouponByCode(ctx, code)
	if err != nil {
		sendJSONError(w, "coupon not found",
			err.Error(), http.StatusNotFound)
		return
	}

	// Update fields if provided
	updateCoupon := *existingCoupon
	if input.Discount != nil {
		updateCoupon.Discount = *input.Discount
	}
	if input.DiscountType != nil {
		if *input.DiscountType != "percentage" && *input.DiscountType != "fixed" {
			sendJSONError(w, "discount_type must be 'percentage' or 'fixed'", "", http.StatusBadRequest)
			return
		}
		updateCoupon.DiscountType = *input.DiscountType
	}
	if input.MaxDiscount != nil {
		updateCoupon.MaxDiscount = *input.MaxDiscount
	}
	if input.MinOrderAmount != nil {
		updateCoupon.MinOrderAmount = *input.MinOrderAmount
	}
	if input.ValidFrom != nil {
		updateCoupon.ValidFrom = *input.ValidFrom
	}
	if input.ValidTo != nil {
		updateCoupon.ValidTo = *input.ValidTo
	}

	// Validate dates
	if updateCoupon.ValidTo.Before(updateCoupon.ValidFrom) {
		sendJSONError(w, "valid_to must be after valid_from", "", http.StatusBadRequest)
		return
	}

	updatedCoupon, err := server.db.Billing().UpdateCoupon(ctx, code, updateCoupon)
	if err != nil {
		sendJSONError(w, "failed to update coupon",
			err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(updatedCoupon)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// deleteCoupon handles DELETE /api/coupons/{code} - Delete coupon (Admin-only).
func (server *Server) deleteCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	code, ok := vars["code"]
	if !ok || code == "" {
		sendJSONError(w, "code is required", "", http.StatusBadRequest)
		return
	}

	err = server.db.Billing().DeleteCoupon(ctx, code)
	if err != nil {
		sendJSONError(w, "failed to delete coupon",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusNoContent, nil)
}
