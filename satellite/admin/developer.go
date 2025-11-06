// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"storj.io/common/uuid"
)

// Developer represents a developer in the API response
type Developer struct {
	ID                 uuid.UUID  `json:"id"`
	FullName           string     `json:"fullName"`
	Email              string     `json:"email"`
	Status             int        `json:"status"`
	CreatedAt          time.Time  `json:"createdAt"`
	LastSessionExpiry  *time.Time `json:"lastSessionExpiry"`
	FirstSessionExpiry *time.Time `json:"firstSessionExpiry"`
	TotalSessionCount  int        `json:"totalSessionCount"`
	OAuthClientCount   int        `json:"oauthClientCount"` // Number of OAuth clients created by this developer
}

// DeveloperListParams holds parsed query parameters for developer listing
type DeveloperListParams struct {
	Limit         uint64
	Page          uint64
	FetchAll      bool
	Search        string
	StatusFilter  *int
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
}

func (server *Server) getAllDevelopers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Add context timeout for database query safety (5 seconds)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	params, err := parseDeveloperParams(r)
	if err != nil {
		sendJSONError(w, "Bad request", err.Error(), http.StatusBadRequest)
		return
	}

	// Calculate pagination
	var limit, offset int
	if params.FetchAll {
		// For "fetch all", use a practical limit to avoid memory pressure
		// PostgreSQL handles large limits well, but we cap at 100k for safety
		limit = 100000
		offset = 0
	} else {
		limit = int(params.Limit)
		offset = int((params.Page - 1) * params.Limit)
	}

	// Parse session-related filters
	query := r.URL.Query()
	hasActiveSessionFilter := query.Get("has_active_session") // "true", "false", or ""
	var hasActiveSessionFilterBool *bool
	if hasActiveSessionFilter == "true" {
		val := true
		hasActiveSessionFilterBool = &val
	} else if hasActiveSessionFilter == "false" {
		val := false
		hasActiveSessionFilterBool = &val
	}

	lastSessionAfterParam := query.Get("last_session_after")
	var lastSessionAfter *time.Time
	if lastSessionAfterParam != "" {
		parsedTime, err := time.Parse("2006-01-02", lastSessionAfterParam)
		if err == nil {
			lastSessionAfter = &parsedTime
		}
	}

	lastSessionBeforeParam := query.Get("last_session_before")
	var lastSessionBefore *time.Time
	if lastSessionBeforeParam != "" {
		parsedTime, err := time.Parse("2006-01-02", lastSessionBeforeParam)
		if err == nil {
			// Set to end of day for inclusive filtering
			endOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 23, 59, 59, 999999999, parsedTime.Location())
			lastSessionBefore = &endOfDay
		}
	}

	sessionCountMinParam := query.Get("session_count_min")
	var sessionCountMin *int
	if sessionCountMinParam != "" {
		minVal, err := strconv.Atoi(sessionCountMinParam)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'session_count_min' must be a valid number", http.StatusBadRequest)
			return
		}
		sessionCountMin = &minVal
	}

	sessionCountMaxParam := query.Get("session_count_max")
	var sessionCountMax *int
	if sessionCountMaxParam != "" {
		maxVal, err := strconv.Atoi(sessionCountMaxParam)
		if err != nil {
			sendJSONError(w, "Bad request", "parameter 'session_count_max' must be a valid number", http.StatusBadRequest)
			return
		}
		sessionCountMax = &maxVal
	}

	// Fetch developers with stats using optimized query
	developers, lastSessionExpiry, firstSessionExpiry, totalSessionCounts, oauthClientCounts, totalCount, err := server.db.Console().Developers().GetAllDevelopersWithStats(
		ctx,
		limit,
		offset,
		params.StatusFilter,
		params.CreatedAfter,
		params.CreatedBefore,
		params.Search,
		hasActiveSessionFilterBool,
		lastSessionAfter,
		lastSessionBefore,
		sessionCountMin,
		sessionCountMax,
	)
	if err != nil {
		sendJSONError(w, "failed to get developers", err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format - preallocated slice for better performance
	responseDevelopers := make([]Developer, len(developers))
	for i, dev := range developers {
		responseDevelopers[i] = Developer{
			ID:                 dev.ID,
			FullName:           dev.FullName,
			Email:              dev.Email,
			Status:             int(dev.Status),
			CreatedAt:          dev.CreatedAt,
			LastSessionExpiry:  lastSessionExpiry[i],
			FirstSessionExpiry: firstSessionExpiry[i],
			TotalSessionCount:  totalSessionCounts[i],
			OAuthClientCount:   oauthClientCounts[i],
		}
	}

	// Calculate pagination metadata
	var totalPages uint64
	var actualLimit uint64
	var actualOffset uint64

	if params.FetchAll {
		totalPages = 1
		actualLimit = uint64(totalCount)
		actualOffset = 0
	} else {
		actualLimit = params.Limit
		actualOffset = (params.Page - 1) * params.Limit
		// Simplified pagination calculation
		if params.Limit > 0 {
			totalPages = uint64(math.Ceil(float64(totalCount) / float64(params.Limit)))
		}
	}

	response := struct {
		Developers  []Developer `json:"developers"`
		PageCount   uint        `json:"pageCount"`
		CurrentPage uint        `json:"currentPage"`
		TotalCount  uint64      `json:"totalCount"`
		HasMore     bool        `json:"hasMore"`
		Limit       uint        `json:"limit"`
		Offset      uint64      `json:"offset"`
	}{
		Developers:  responseDevelopers,
		PageCount:   uint(totalPages),
		CurrentPage: uint(params.Page),
		TotalCount:  uint64(totalCount),
		HasMore:     actualOffset+actualLimit < uint64(totalCount),
		Limit:       uint(actualLimit),
		Offset:      actualOffset,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// parseDeveloperParams parses and validates query parameters for developer listing
func parseDeveloperParams(r *http.Request) (*DeveloperListParams, error) {
	query := r.URL.Query()
	params := &DeveloperListParams{}

	// Parse limit
	limitParam := query.Get("limit")
	if limitParam == "" {
		limitParam = "50" // Default limit
	}

	if limitParam == "-1" || limitParam == "0" {
		params.FetchAll = true
	} else {
		var err error
		params.Limit, err = strconv.ParseUint(limitParam, 10, 32)
		if err != nil {
			return nil, err
		}
	}

	// Parse page
	pageParam := query.Get("page")
	if pageParam == "" {
		pageParam = "1"
	}
	var err error
	params.Page, err = strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		return nil, err
	}

	// Parse search
	params.Search = query.Get("search")

	// Parse status filter
	statusParam := parseStatusParam(query.Get("status"))
	if statusParam != nil {
		statusInt := int(*statusParam)
		params.StatusFilter = &statusInt
	} else if query.Get("status") != "" {
		return nil, err
	}

	// Parse date range
	createdAfter, createdBefore, err := parseDateRange(query.Get("created_range"), query.Get("created_after"), query.Get("created_before"))
	if err != nil {
		return nil, err
	}
	params.CreatedAfter = createdAfter
	params.CreatedBefore = createdBefore

	return params, nil
}

// parseDateRange parses date range parameters and returns createdAfter and createdBefore times
func parseDateRange(rangeParam, afterParam, beforeParam string) (*time.Time, *time.Time, error) {
	now := time.Now()
	loc := now.Location()

	var createdAfter *time.Time
	var createdBefore *time.Time

	if rangeParam != "" {
		switch rangeParam {
		case "today":
			startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfToday
			createdBefore = &endOfToday
		case "yesterday":
			yesterday := now.AddDate(0, 0, -1)
			startOfYesterday := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, loc)
			endOfYesterday := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfYesterday
			createdBefore = &endOfYesterday
		case "last_week":
			lastWeek := now.AddDate(0, 0, -7)
			startOfLastWeek := time.Date(lastWeek.Year(), lastWeek.Month(), lastWeek.Day(), 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfLastWeek
			createdBefore = &endOfToday
		case "last_month":
			lastMonth := now.AddDate(0, -1, 0)
			startOfLastMonth := time.Date(lastMonth.Year(), lastMonth.Month(), 1, 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfLastMonth
			createdBefore = &endOfToday
		case "last_year":
			lastYear := now.AddDate(-1, 0, 0)
			startOfLastYear := time.Date(lastYear.Year(), 1, 1, 0, 0, 0, 0, loc)
			endOfToday := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, loc)
			createdAfter = &startOfLastYear
			createdBefore = &endOfToday
		}
	} else {
		// Handle custom date range
		if afterParam != "" {
			parsedTime, err := time.Parse("2006-01-02", afterParam)
			if err == nil {
				startOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 0, 0, 0, 0, parsedTime.Location())
				createdAfter = &startOfDay
			}
		}

		if beforeParam != "" {
			parsedTime, err := time.Parse("2006-01-02", beforeParam)
			if err == nil {
				endOfDay := time.Date(parsedTime.Year(), parsedTime.Month(), parsedTime.Day(), 23, 59, 59, 999999999, parsedTime.Location())
				createdBefore = &endOfDay
			}
		}
	}

	return createdAfter, createdBefore, nil
}

// getDeveloperStats returns aggregated statistics about all developers
// This endpoint uses SQL aggregations for efficient counting
func (server *Server) getDeveloperStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Add context timeout for database query safety (5 seconds)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use optimized SQL aggregation to count developers by status
	// This is much faster than fetching all developers and counting in memory
	total, active, inactive, deleted, pendingDeletion, legalHold, pendingBotVerification, err := server.db.Console().Developers().GetDeveloperStats(ctx)
	if err != nil {
		sendJSONError(w, "failed to get developer statistics",
			err.Error(), http.StatusInternalServerError)
		return
	}

	stats := struct {
		TotalDevelopers        uint64 `json:"totalDevelopers"`
		Active                 uint64 `json:"active"`
		Inactive               uint64 `json:"inactive"`
		Deleted                uint64 `json:"deleted"`
		PendingDeletion        uint64 `json:"pendingDeletion"`
		LegalHold              uint64 `json:"legalHold"`
		PendingBotVerification uint64 `json:"pendingBotVerification"`
	}{
		TotalDevelopers:        uint64(total),
		Active:                 uint64(active),
		Inactive:               uint64(inactive),
		Deleted:                uint64(deleted),
		PendingDeletion:        uint64(pendingDeletion),
		LegalHold:              uint64(legalHold),
		PendingBotVerification: uint64(pendingBotVerification),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

type DeveloperDetails struct {
	Developer          Developer  `json:"developer"`
	LastSessionExpiry  *time.Time `json:"lastSessionCount"`
	FirstSessionExpiry *time.Time `json:"firstSessionCount"`
	TotalSessionCount  int        `json:"totalSessionCount"`
	OAuthClientCount   int        `json:"oauthClientCount"` // Number of OAuth clients created by this developer
}

func (server *Server) getDeveloperDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	developerEmail, ok := vars["developerEmail"]
	if !ok {
		sendJSONError(w, "developer-email missing", "", http.StatusBadRequest)
		return
	}

	// Get developer by email
	developer, err := server.db.Console().Developers().GetByEmail(ctx, developerEmail)
	if errors.Is(err, sql.ErrNoRows) {
		sendJSONError(w, "developer not found", "", http.StatusNotFound)
		return
	}
	if err != nil {
		sendJSONError(w, "failed to get developer", err.Error(), http.StatusInternalServerError)
		return
	}

	// Get all webapp sessions for this developer
	sessions, err := server.db.Console().WebappSessionDevelopers().GetAllByDeveloperId(ctx, developer.ID)
	if err != nil {
		sendJSONError(w, "failed to get developer login history", err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert sessions to response format
	type LoginHistoryEntry struct {
		ID        string    `json:"id"`
		IPAddress string    `json:"ipAddress"`
		Status    int       `json:"status"`
		LoginTime time.Time `json:"loginTime"`
		ExpiresAt time.Time `json:"expiresAt"`
		IsActive  bool      `json:"isActive"`
	}

	entries := make([]LoginHistoryEntry, 0, len(sessions))
	now := time.Now()

	for _, session := range sessions {
		entries = append(entries, LoginHistoryEntry{
			ID:        session.ID.String(),
			IPAddress: session.IP,
			Status:    session.Status,
			LoginTime: session.ExpiresAt,
			ExpiresAt: session.ExpiresAt,
			IsActive:  session.ExpiresAt.After(now),
		})
	}

	// Sort by login time (most recent first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LoginTime.After(entries[j].LoginTime)
	})

	// Create response
	response := struct {
		DeveloperEmail string              `json:"developerEmail"`
		Total          int                 `json:"total"`
		Sessions       []LoginHistoryEntry `json:"sessions"`
	}{
		DeveloperEmail: developerEmail,
		Total:          len(entries),
		Sessions:       entries,
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}
