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
	"sort"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
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

	// Fetch developers with stats using optimized query
	developers, lastSessionExpiry, firstSessionExpiry, totalSessionCounts, oauthClientCounts, totalCount, err := server.db.Console().Developers().GetAllDevelopersWithStats(
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
		HasMore:     actualOffset+actualLimit < totalCount,
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
		FullName: input.FullName,
		Email:    input.Email,
		Password: input.Password,
		Status:   input.Status,
	}

	err = developer.IsValid(false)
	if err != nil {
		sendJSONError(w, "developer data is not valid",
			err.Error(), http.StatusBadRequest)
		return
	}

	// Check if developer exists (including unverified/deleted)
	verified, unverified, err := server.db.Console().Developers().GetByEmailWithUnverified(ctx, input.Email)
	if err != nil {
		sendJSONError(w, "failed to check for developer email",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if verified != nil || len(unverified) > 0 {
		sendJSONError(w, fmt.Sprintf("developer with email already exists %s", input.Email),
			"", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), 0)
	if err != nil {
		sendJSONError(w, "unable to save password hash",
			"", http.StatusInternalServerError)
		return
	}

	developerID, err := uuid.New()
	if err != nil {
		sendJSONError(w, "unable to create UUID",
			"", http.StatusInternalServerError)
		return
	}

	// Set default status to Active if not provided
	status := console.UserStatus(developer.Status)
	if status == 0 {
		status = console.Active
	}

	newDeveloper, err := server.db.Console().Developers().Insert(ctx, &console.Developer{
		ID:           developerID,
		FullName:     developer.FullName,
		Email:        developer.Email,
		PasswordHash: hash,
		Status:       status,
	})
	if err != nil {
		sendJSONError(w, "failed to insert developer",
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

	// Get developer by email (including unverified/deleted for admin operations)
	verified, unverified, err := server.db.Console().Developers().GetByEmailWithUnverified(ctx, developerEmail)
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
		// Only update email if it's different from current
		if *input.Email != developer.Email {
			// Check if new email already exists (including unverified/deleted)
			existingVerified, existingUnverified, err := server.db.Console().Developers().GetByEmailWithUnverified(ctx, *input.Email)
			if err != nil {
				sendJSONError(w, "failed to check for developer email",
					err.Error(), http.StatusInternalServerError)
				return
			}
			// Check if email is taken by a different developer
			if existingVerified != nil && existingVerified.ID != developer.ID {
				sendJSONError(w, fmt.Sprintf("developer with email already exists %s", *input.Email),
					"", http.StatusConflict)
				return
			}
			if len(existingUnverified) > 0 {
				for _, unv := range existingUnverified {
					if unv.ID != developer.ID {
						sendJSONError(w, fmt.Sprintf("developer with email already exists %s", *input.Email),
							"", http.StatusConflict)
						return
					}
				}
			}
			updateRequest.Email = input.Email
			hasUpdates = true
		}
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
		// Validate status value (0-5 are valid statuses)
		if statusValue < 0 || statusValue > 5 {
			sendJSONError(w, "invalid status value",
				"status must be between 0 (Inactive) and 5 (Pending Bot Verification)", http.StatusBadRequest)
			return
		}
		// Only update status if it's different from current
		if statusValue != developer.Status {
			updateRequest.Status = &statusValue
			hasUpdates = true
		}
	}

	// Only perform update if there are actual changes
	if hasUpdates {
		err = server.db.Console().Developers().Update(ctx, developer.ID, updateRequest)
		if err != nil {
			sendJSONError(w, "failed to update developer",
				err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Return updated developer (always fetch fresh from database)
	// Determine which email to use for fallback lookup
	lookupEmail := developer.Email
	if updateRequest.Email != nil {
		lookupEmail = *updateRequest.Email
	}

	updatedDeveloper, err := server.db.Console().Developers().Get(ctx, developer.ID)
	if err != nil {
		// If Get fails (e.g., status was set to deleted), try GetByEmailWithUnverified
		verified, unverified, err2 := server.db.Console().Developers().GetByEmailWithUnverified(ctx, lookupEmail)
		if err2 != nil {
			sendJSONError(w, "failed to get updated developer",
				err.Error(), http.StatusInternalServerError)
			return
		}
		if verified != nil && verified.ID == developer.ID {
			updatedDeveloper = verified
		} else if len(unverified) > 0 {
			for _, unv := range unverified {
				if unv.ID == developer.ID {
					updatedDeveloper = &unv
					break
				}
			}
		}
		if updatedDeveloper == nil {
			sendJSONError(w, "failed to get updated developer",
				err.Error(), http.StatusInternalServerError)
			return
		}
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

	// Get developer by email (including unverified/deleted for admin operations)
	verified, unverified, err := server.db.Console().Developers().GetByEmailWithUnverified(ctx, developerEmail)
	if err != nil {
		sendJSONError(w, "failed to get developer details",
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

	// Note: We skip checking developer_user_mappings as there's no direct method
	// to access it through the console.DB interface. If needed, this check can be
	// added by extending the Developers interface with a method to check mappings.

	// Check if developer has OAuth clients
	oauthClients, err := server.db.Console().DeveloperOAuthClients().ListByDeveloperID(ctx, developer.ID)
	if err != nil {
		sendJSONError(w, "unable to list OAuth clients",
			err.Error(), http.StatusInternalServerError)
		return
	}
	if len(oauthClients) > 0 {
		// Delete all OAuth clients for this developer
		for _, client := range oauthClients {
			err := server.db.Console().DeveloperOAuthClients().Delete(ctx, client.ID)
			if err != nil {
				sendJSONError(w, fmt.Sprintf("unable to delete OAuth client %s", client.ID.String()),
					err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	// Delete all developer sessions
	_, err = server.db.Console().WebappSessionDevelopers().DeleteAllByDeveloperId(ctx, developer.ID)
	if err != nil {
		sendJSONError(w, "failed to delete developer sessions",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Soft delete: Update developer status to Deleted and anonymize email
	emptyName := ""
	deactivatedEmail := fmt.Sprintf("deactivated+%s@storj.io", developer.ID.String())
	status := console.Deleted

	err = server.db.Console().Developers().Update(ctx, developer.ID, console.UpdateDeveloperRequest{
		FullName: &emptyName,
		Email:    &deactivatedEmail,
		Status:   &status,
	})
	if err != nil {
		sendJSONError(w, "unable to delete developer",
			err.Error(), http.StatusInternalServerError)
		return
	}
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

	// Get developer by email (including unverified/deleted for admin operations)
	verified, unverified, err := server.db.Console().Developers().GetByEmailWithUnverified(ctx, developerEmail)
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

	// Validate status value (0-5 are valid statuses)
	statusValue := console.UserStatus(input.Status)
	if statusValue < 0 || statusValue > 5 {
		sendJSONError(w, "invalid status value",
			"status must be between 0 (Inactive) and 5 (Pending Bot Verification)", http.StatusBadRequest)
		return
	}

	updateRequest := console.UpdateDeveloperRequest{
		Status: &statusValue,
	}

	err = server.db.Console().Developers().Update(ctx, developer.ID, updateRequest)
	if err != nil {
		sendJSONError(w, "failed to update developer status",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Return updated developer
	updatedDeveloper, err := server.db.Console().Developers().Get(ctx, developer.ID)
	if err != nil {
		sendJSONError(w, "failed to get updated developer",
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
