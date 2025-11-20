// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/developer"
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
	TotalUsers         int        `json:"totalUsers"`       // Total unique users who accessed this developer's applications
	ActiveUsers        int        `json:"activeUsers"`      // Active users (last 30 days) who accessed this developer's applications
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
	SortColumn    string // Column name to sort by
	SortOrder     string // "asc" or "desc"
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

	var actualLimit, actualOffset int
	if params.FetchAll {
		// For "All", pass 0 as limit to skip LIMIT clause in SQL query
		// This allows fetching all records without hardcoded limits
		actualLimit = 0
		actualOffset = 0
	} else {
		actualLimit = int(params.Limit)
		actualOffset = int((params.Page - 1) * params.Limit)
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

	// Fetch developers with stats using service
	result, err := server.developerserviceService.GetAllDevelopersAdmin(
		ctx,
		actualLimit,
		actualOffset,
		params.StatusFilter,
		params.CreatedAfter,
		params.CreatedBefore,
		params.Search,
		hasActiveSessionFilterBool,
		lastSessionAfter,
		lastSessionBefore,
		sessionCountMin,
		sessionCountMax,
		params.SortColumn,
		params.SortOrder,
	)
	if err != nil {
		sendJSONError(w, "failed to get developers", err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format - preallocated slice for better performance
	responseDevelopers := make([]Developer, len(result.Developers))
	for i, devWithStats := range result.Developers {
		responseDevelopers[i] = Developer{
			ID:                 devWithStats.Developer.ID,
			FullName:           devWithStats.Developer.FullName,
			Email:              devWithStats.Developer.Email,
			Status:             int(devWithStats.Developer.Status),
			CreatedAt:          devWithStats.Developer.CreatedAt,
			LastSessionExpiry:  result.LastSessionExpiry[i],
			FirstSessionExpiry: result.FirstSessionExpiry[i],
			TotalSessionCount:  result.TotalSessionCounts[i],
			OAuthClientCount:   result.OAuthClientCounts[i],
			TotalUsers:         result.TotalUserCounts[i],
			ActiveUsers:        result.ActiveUserCounts[i],
		}
	}

	// Calculate pagination metadata
	var totalPages uint64

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
		TotalCount:  uint64(result.TotalCount),
		HasMore:     actualOffset+actualLimit < result.TotalCount,
		Limit:       uint(actualLimit),
		Offset:      uint64(actualOffset),
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

	// Parse sorting parameters
	params.SortColumn = query.Get("sort_column")
	params.SortOrder = query.Get("sort_order")

	// Validate and normalize sort order
	if params.SortOrder != "" {
		params.SortOrder = strings.ToLower(params.SortOrder)
		if params.SortOrder != "asc" && params.SortOrder != "desc" {
			return nil, fmt.Errorf("parameter 'sort_order' must be 'asc' or 'desc'")
		}
	} else {
		// Default to descending if column is specified but order is not
		if params.SortColumn != "" {
			params.SortOrder = "desc"
		}
	}

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

	// Use service to get developer statistics
	stats, err := server.developerserviceService.GetDeveloperStatsAdmin(ctx)
	if err != nil {
		sendJSONError(w, "failed to get developer statistics",
			err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		TotalDevelopers        uint64 `json:"totalDevelopers"`
		Active                 uint64 `json:"active"`
		Inactive               uint64 `json:"inactive"`
		Deleted                uint64 `json:"deleted"`
		PendingDeletion        uint64 `json:"pendingDeletion"`
		LegalHold              uint64 `json:"legalHold"`
		PendingBotVerification uint64 `json:"pendingBotVerification"`
	}{
		TotalDevelopers:        uint64(stats.Total),
		Active:                 uint64(stats.Active),
		Inactive:               uint64(stats.Inactive),
		Deleted:                uint64(stats.Deleted),
		PendingDeletion:        uint64(stats.PendingDeletion),
		LegalHold:              uint64(stats.LegalHold),
		PendingBotVerification: uint64(stats.PendingBotVerification),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
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

	// Get developer details with login history using service
	result, err := server.developerserviceService.GetDeveloperDetailsAdmin(ctx, developerEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, "developer not found", "", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get developer details", err.Error(), http.StatusInternalServerError)
		return
	}

	// Create response
	response := struct {
		DeveloperEmail string                        `json:"developerEmail"`
		Total          int                           `json:"total"`
		Sessions       []developer.LoginHistoryEntry `json:"sessions"`
	}{
		DeveloperEmail: developerEmail,
		Total:          len(result.Sessions),
		Sessions:       result.Sessions,
	}

	data, err := json.Marshal(response)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// addDeveloper creates a new developer
func (server *Server) addDeveloper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input console.CreateDeveloper

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	developer := console.CreateDeveloper{
		FullName:    input.FullName,
		Email:       input.Email,
		Password:    input.Password,
		CompanyName: input.CompanyName,
	}

	err = developer.IsValid(false)
	if err != nil {
		sendJSONError(w, "developer data is not valid",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Use service function to create developer
	newDeveloper, err := server.developerserviceService.CreateDeveloperAdmin(ctx, developer)
	if err != nil {
		if console.ErrEmailUsed.Has(err) {
			sendJSONError(w, fmt.Sprintf("developer with email already exists %s", input.Email),
				"", http.StatusConflict)
			return
		}
		sendJSONError(w, "failed to create developer",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Clear password hash from response
	newDeveloper.PasswordHash = nil

	data, err := json.Marshal(newDeveloper)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// updateDeveloper updates an existing developer
func (server *Server) updateDeveloper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	developerEmail, ok := vars["developerEmail"]
	if !ok {
		sendJSONError(w, "developer-email missing",
			"", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	type DeveloperUpdateInput struct {
		FullName *string `json:"fullName"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
		Status   *int    `json:"status"`
	}

	var input DeveloperUpdateInput

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	updateRequest := console.UpdateDeveloperRequest{}

	// Track if any fields are being updated
	hasUpdates := false

	if input.FullName != nil && *input.FullName != "" {
		updateRequest.FullName = input.FullName
		hasUpdates = true
	}
	if input.Email != nil && *input.Email != "" {
		updateRequest.Email = input.Email
		hasUpdates = true
	}
	if input.Password != nil && *input.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*input.Password), 0)
		if err != nil {
			sendJSONError(w, "unable to save password hash",
				"", http.StatusInternalServerError)
			return
		}
		updateRequest.PasswordHash = hash
		hasUpdates = true
	}
	if input.Status != nil {
		statusValue := console.UserStatus(*input.Status)
		updateRequest.Status = &statusValue
		hasUpdates = true
	}

	// Only perform update if there are actual changes
	if !hasUpdates {
		// No updates, just return current developer using service
		verified, unverified, err := server.developerserviceService.GetDeveloperByEmailWithUnverified(ctx, developerEmail)
		if err != nil {
			sendJSONError(w, "failed to get developer",
				err.Error(), http.StatusInternalServerError)
			return
		}
		var developer *console.Developer
		if verified != nil {
			developer = verified
		} else if len(unverified) > 0 {
			developer = &unverified[0]
		} else {
			sendJSONError(w, fmt.Sprintf("developer with email %q does not exist", developerEmail),
				"", http.StatusNotFound)
			return
		}
		developer.PasswordHash = nil
		data, err := json.Marshal(developer)
		if err != nil {
			sendJSONError(w, "json encoding failed",
				err.Error(), http.StatusInternalServerError)
			return
		}
		sendJSONData(w, http.StatusOK, data)
		return
	}

	// Use service function to update developer
	updatedDeveloper, err := server.developerserviceService.UpdateDeveloperAdmin(ctx, developerEmail, updateRequest)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, fmt.Sprintf("developer with email %q does not exist", developerEmail),
				"", http.StatusNotFound)
			return
		}
		if console.ErrEmailUsed.Has(err) {
			sendJSONError(w, fmt.Sprintf("developer with email already exists %s", *input.Email),
				"", http.StatusConflict)
			return
		}
		if console.ErrValidation.Has(err) {
			sendJSONError(w, "invalid request",
				err.Error(), http.StatusBadRequest)
			return
		}
		sendJSONError(w, "failed to update developer",
			err.Error(), http.StatusInternalServerError)
		return
	}

	updatedDeveloper.PasswordHash = nil

	data, err := json.Marshal(updatedDeveloper)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// deleteDeveloper deletes a developer (soft delete)
func (server *Server) deleteDeveloper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	developerEmail, ok := vars["developerEmail"]
	if !ok {
		sendJSONError(w, "developer-email missing", "", http.StatusBadRequest)
		return
	}

	// Use service function to delete developer
	err = server.developerserviceService.DeleteDeveloperAdmin(ctx, developerEmail)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, fmt.Sprintf("developer with email %q does not exist", developerEmail),
				"", http.StatusNotFound)
			return
		}
		sendJSONError(w, "unable to delete developer",
			err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// updateDeveloperStatus updates only the status of a developer
func (server *Server) updateDeveloperStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	developerEmail, ok := vars["developerEmail"]
	if !ok {
		sendJSONError(w, "developer-email missing",
			"", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	type StatusUpdateInput struct {
		Status int `json:"status"`
	}

	var input StatusUpdateInput

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	statusValue := console.UserStatus(input.Status)

	// Use service function to update developer status
	updatedDeveloper, err := server.developerserviceService.UpdateDeveloperStatusAdmin(ctx, developerEmail, statusValue)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, fmt.Sprintf("developer with email %q does not exist", developerEmail),
				"", http.StatusNotFound)
			return
		}
		if console.ErrValidation.Has(err) {
			sendJSONError(w, "invalid status value",
				err.Error(), http.StatusBadRequest)
			return
		}
		sendJSONError(w, "failed to update developer status",
			err.Error(), http.StatusInternalServerError)
		return
	}

	updatedDeveloper.PasswordHash = nil

	data, err := json.Marshal(updatedDeveloper)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// getDeveloperUserStatistics returns user access statistics for a developer
func (server *Server) getDeveloperUserStatistics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	developerEmail, ok := vars["developerEmail"]
	if !ok {
		sendJSONError(w, "developer-email missing", "", http.StatusBadRequest)
		return
	}

	// Get developer by email to get ID
	developer, err := server.developerserviceService.GetDeveloperByEmail(ctx, developerEmail)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, "developer not found", "", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get developer", err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse date range filters
	query := r.URL.Query()
	var startDate, endDate *time.Time

	if startDateStr := query.Get("start_date"); startDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, startDateStr)
		if err == nil {
			startDate = &parsed
		}
	}

	if endDateStr := query.Get("end_date"); endDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, endDateStr)
		if err == nil {
			endDate = &parsed
		}
	}

	// Get user statistics
	stats, err := server.developerserviceService.GetDeveloperUserStatistics(ctx, developer.ID, startDate, endDate)
	if err != nil {
		sendJSONError(w, "failed to get user statistics", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// getDeveloperUserAccessTrends returns user access trends for a developer
func (server *Server) getDeveloperUserAccessTrends(w http.ResponseWriter, r *http.Request) {
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
	developer, err := server.developerserviceService.GetDeveloperByEmail(ctx, developerEmail)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, "developer not found", "", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get developer", err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	period := query.Get("period")
	if period == "" {
		period = "daily"
	}

	var startDate, endDate *time.Time
	if startDateStr := query.Get("start_date"); startDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, startDateStr)
		if err == nil {
			startDate = &parsed
		}
	}

	if endDateStr := query.Get("end_date"); endDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, endDateStr)
		if err == nil {
			endDate = &parsed
		}
	}

	// Get trends
	trends, err := server.developerserviceService.GetDeveloperUserAccessTrends(ctx, developer.ID, period, startDate, endDate)
	if err != nil {
		sendJSONError(w, "failed to get user access trends", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(trends)
}

// getDeveloperUserAccessByApplication returns user access breakdown by application
func (server *Server) getDeveloperUserAccessByApplication(w http.ResponseWriter, r *http.Request) {
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
	developer, err := server.developerserviceService.GetDeveloperByEmail(ctx, developerEmail)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, "developer not found", "", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get developer", err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse date range filters
	query := r.URL.Query()
	var startDate, endDate *time.Time

	if startDateStr := query.Get("start_date"); startDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, startDateStr)
		if err == nil {
			startDate = &parsed
		}
	}

	if endDateStr := query.Get("end_date"); endDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, endDateStr)
		if err == nil {
			endDate = &parsed
		}
	}

	// Get application stats
	apps, err := server.developerserviceService.GetDeveloperUserAccessByApplication(ctx, developer.ID, startDate, endDate)
	if err != nil {
		sendJSONError(w, "failed to get application statistics", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(apps)
}

// exportDeveloperUserStatistics exports user statistics as CSV
func (server *Server) exportDeveloperUserStatistics(w http.ResponseWriter, r *http.Request) {
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
	developer, err := server.developerserviceService.GetDeveloperByEmail(ctx, developerEmail)
	if err != nil {
		if console.ErrEmailNotFound.Has(err) {
			sendJSONError(w, "developer not found", "", http.StatusNotFound)
			return
		}
		sendJSONError(w, "failed to get developer", err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse date range filters
	query := r.URL.Query()
	var startDate, endDate *time.Time

	if startDateStr := query.Get("start_date"); startDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, startDateStr)
		if err == nil {
			startDate = &parsed
		}
	}

	if endDateStr := query.Get("end_date"); endDateStr != "" {
		parsed, err := time.Parse(time.RFC3339, endDateStr)
		if err == nil {
			endDate = &parsed
		}
	}

	// Get all statistics
	stats, err := server.developerserviceService.GetDeveloperUserStatistics(ctx, developer.ID, startDate, endDate)
	if err != nil {
		sendJSONError(w, "failed to get user statistics", err.Error(), http.StatusInternalServerError)
		return
	}

	apps, err := server.developerserviceService.GetDeveloperUserAccessByApplication(ctx, developer.ID, startDate, endDate)
	if err != nil {
		sendJSONError(w, "failed to get application statistics", err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate CSV
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=user-statistics-%s-%s.csv", developerEmail, time.Now().Format("2006-01-02")))

	// Write CSV header
	w.Write([]byte("Metric,Value\n"))
	w.Write([]byte(fmt.Sprintf("Total Users,%d\n", stats.TotalUsers)))
	w.Write([]byte(fmt.Sprintf("Active Users,%d\n", stats.ActiveUsers)))
	w.Write([]byte(fmt.Sprintf("Total Requests,%d\n", stats.TotalRequests)))
	w.Write([]byte(fmt.Sprintf("Approved Requests,%d\n", stats.ApprovedRequests)))
	w.Write([]byte(fmt.Sprintf("Pending Requests,%d\n", stats.PendingRequests)))
	w.Write([]byte(fmt.Sprintf("Rejected Requests,%d\n", stats.RejectedRequests)))
	w.Write([]byte("\n"))
	w.Write([]byte("Application,Client ID,Total Users,Active Users,Total Requests\n"))

	// Write application data
	for _, app := range apps {
		line := fmt.Sprintf("%s,%s,%d,%d,%d\n",
			app.ClientName,
			app.ClientID,
			app.TotalUsers,
			app.ActiveUsers,
			app.TotalRequests,
		)
		w.Write([]byte(line))
	}
}
