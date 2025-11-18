// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"storj.io/common/storj"
	"storj.io/storj/satellite/nodeselection"
	"storj.io/storj/satellite/overlay"
)

const defaultOnlineWindow = 2 * time.Hour

// Node represents a storage node in the admin dashboard
type Node struct {
	ID                    string     `json:"id"`
	Address               string     `json:"address"`
	CountryCode           string     `json:"countryCode"`
	CreatedAt             time.Time  `json:"createdAt"`
	Status                string     `json:"status"`
	OperatorEmail         string     `json:"operatorEmail"`
	Wallet                string     `json:"wallet"`
	LastNet               string     `json:"lastNet"`
	LastIPPort            string     `json:"lastIPPort"`
	FreeDisk              int64      `json:"freeDisk"`
	Latency90             int64      `json:"latency90"`
	LastContactSuccess    *time.Time `json:"lastContactSuccess"`
	LastContactFailure    *time.Time `json:"lastContactFailure"`
	OfflineSuspended      *time.Time `json:"offlineSuspended"`
	UnknownAuditSuspended *time.Time `json:"unknownAuditSuspended"`
	Disqualified          *time.Time `json:"disqualified"`
	ExitInitiatedAt       *time.Time `json:"exitInitiatedAt"`
	ExitFinishedAt        *time.Time `json:"exitFinishedAt"`
}

// NodeResponse represents the paginated response for nodes
type NodeResponse struct {
	Nodes       []Node `json:"nodes"`
	PageCount   uint   `json:"pageCount"`
	CurrentPage uint   `json:"currentPage"`
	TotalCount  uint64 `json:"totalCount"`
	HasMore     bool   `json:"hasMore"`
	Limit       uint   `json:"limit"`
	Offset      uint64 `json:"offset"`
}

// getAllNodes returns all storage nodes with pagination and filtering.
// All filtering and pagination is done at the database level for optimal performance.
func (server *Server) getAllNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Parse query parameters
	queryParams := r.URL.Query()

	// Check if this is an export request first
	format := queryParams.Get("format")
	isExport := format == "csv" || format == "json"

	limitStr := queryParams.Get("limit")
	fetchAll := strings.ToLower(queryParams.Get("fetchAll")) == "true" ||
		strings.ToLower(limitStr) == "all" || limitStr == "0" || limitStr == "-1"

	var limit int
	var page int
	var offset int

	// For export requests, ignore pagination and fetch all matching records
	if isExport {
		fetchAll = true
		limit = 0
		page = 1
		offset = 0
	} else {
		if fetchAll {
			limit = 0
		} else if limitStr == "" {
			limit = 50
		} else if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			if l > 500 {
				limit = 500
			} else {
				limit = l
			}
		} else {
			limit = 50
		}

		page = 1
		if pageStr := queryParams.Get("page"); pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				page = p
			}
		}

		offset = 0
		if !fetchAll {
			offset = (page - 1) * limit
		}
	}

	// Parse filters
	filters := nodeselection.NodeQueryFilters{
		Status:    strings.ToLower(strings.TrimSpace(queryParams.Get("status"))),
		Email:     strings.TrimSpace(queryParams.Get("email")),
		Countries: parseCountriesFilter(queryParams.Get("country")),
		Search:    strings.TrimSpace(queryParams.Get("search")),
	}

	if createdAfterStr := queryParams.Get("created_after"); createdAfterStr != "" {
		if t, err := time.Parse("2006-01-02", createdAfterStr); err == nil {
			filters.CreatedAfter = &t
		}
	}
	if createdBeforeStr := queryParams.Get("created_before"); createdBeforeStr != "" {
		if t, err := time.Parse("2006-01-02", createdBeforeStr); err == nil {
			endOfDay := time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
			filters.CreatedBefore = &endOfDay
		}
	}

	// Parse sorting parameters
	sortColumn := queryParams.Get("sort_column")
	sortOrder := queryParams.Get("sort_order")

	// Validate and normalize sort order
	if sortOrder != "" {
		sortOrder = strings.ToLower(sortOrder)
		if sortOrder != "asc" && sortOrder != "desc" {
			sendJSONError(w, "Bad request", "parameter 'sort_order' must be 'asc' or 'desc'", http.StatusBadRequest)
			return
		}
	} else {
		// Default to descending if column is specified but order is not
		if sortColumn != "" {
			sortOrder = "desc"
		}
	}

	selectedNodes, totalCount, err := server.db.OverlayCache().GetAllNodesWithFilters(
		ctx,
		defaultOnlineWindow,
		0,
		filters,
		limit,
		offset,
		sortColumn,
		sortOrder,
	)
	if err != nil {
		sendJSONError(w, "Internal server error", fmt.Sprintf("failed to fetch nodes: %v", err), http.StatusInternalServerError)
		return
	}

	nodes := make([]Node, len(selectedNodes))
	for i := range selectedNodes {
		nodes[i] = convertToNode(&selectedNodes[i])
	}

	// For export requests, export all matching nodes and return early
	if isExport {
		server.exportNodesData(w, nodes, filters.Status, strings.Join(filters.Countries, ","), format)
		return
	}

	totalPages := uint64(1)
	if limit > 0 {
		totalPages = (uint64(totalCount) + uint64(limit) - 1) / uint64(limit)
	}
	hasMore := limit > 0 && page < int(totalPages)

	// Create response
	response := NodeResponse{
		Nodes:       nodes,
		PageCount:   uint(totalPages),
		CurrentPage: uint(page),
		TotalCount:  uint64(totalCount),
		HasMore:     hasMore,
		Limit:       uint(limit),
		Offset:      uint64(offset),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// parseCountriesFilter parses comma-separated country codes
func parseCountriesFilter(countryParam string) []string {
	if countryParam == "" {
		return nil
	}
	countries := strings.Split(countryParam, ",")
	result := make([]string, 0, len(countries))
	for _, country := range countries {
		country = strings.ToUpper(strings.TrimSpace(country))
		if country != "" {
			result = append(result, country)
		}
	}
	return result
}

func convertToNode(selectedNode *nodeselection.SelectedNodeWithExtendedData) Node {
	node := Node{
		ID:                    selectedNode.ID.String(),
		Address:               selectedNode.Address.Address,
		CountryCode:           selectedNode.CountryCode.String(),
		CreatedAt:             selectedNode.CreatedAt,
		Status:                getNodeStatusFromSelectedNode(selectedNode),
		OperatorEmail:         selectedNode.Email,
		Wallet:                selectedNode.Wallet,
		LastNet:               selectedNode.LastNet,
		LastIPPort:            selectedNode.LastIPPort,
		FreeDisk:              selectedNode.FreeDisk,
		Latency90:             selectedNode.Latency90,
		OfflineSuspended:      selectedNode.OfflineSuspended,
		UnknownAuditSuspended: selectedNode.UnknownAuditSuspended,
		Disqualified:          selectedNode.Disqualified,
		ExitInitiatedAt:       selectedNode.ExitInitiatedAt,
		ExitFinishedAt:        selectedNode.ExitFinishedAt,
	}

	if !selectedNode.LastContactSuccess.IsZero() {
		node.LastContactSuccess = &selectedNode.LastContactSuccess
	}
	if !selectedNode.LastContactFailure.IsZero() {
		node.LastContactFailure = &selectedNode.LastContactFailure
	}

	return node
}

func getNodeStatusFromSelectedNode(node *nodeselection.SelectedNodeWithExtendedData) string {
	if node.Disqualified != nil {
		return "disqualified"
	}
	if node.ExitFinishedAt != nil {
		return "exited"
	}
	if node.ExitInitiatedAt != nil {
		return "exiting"
	}
	if node.OfflineSuspended != nil || node.UnknownAuditSuspended != nil {
		return "suspended"
	}
	if node.LastContactSuccess.After(time.Now().Add(-defaultOnlineWindow)) {
		return "online"
	}
	return "offline"
}

// getNodeDetails returns detailed information about a specific node
func (server *Server) getNodeDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	nodeIDStr := vars["nodeId"]

	if nodeIDStr == "" {
		sendJSONError(w, "Bad request", "node ID is required", http.StatusBadRequest)
		return
	}

	nodeID, err := storj.NodeIDFromString(nodeIDStr)
	if err != nil {
		sendJSONError(w, "Bad request", "invalid node ID format", http.StatusBadRequest)
		return
	}

	// Get node details from overlay
	nodeDossier, err := server.db.OverlayCache().Get(ctx, nodeID)
	if err != nil {
		sendJSONError(w, "failed to get node details",
			err.Error(), http.StatusNotFound)
		return
	}

	status := getNodeStatus(nodeDossier)

	// Map all fields from NodeDossier to Node struct
	node := Node{
		ID:                    nodeDossier.Id.String(),
		Address:               nodeDossier.Address.Address,
		CountryCode:           nodeDossier.CountryCode.String(),
		CreatedAt:             nodeDossier.CreatedAt,
		Status:                status,
		OperatorEmail:         nodeDossier.Operator.Email,
		Wallet:                nodeDossier.Operator.Wallet,
		LastNet:               nodeDossier.LastNet,
		LastIPPort:            nodeDossier.LastIPPort,
		FreeDisk:              nodeDossier.Capacity.FreeDisk,
		Latency90:             nodeDossier.Reputation.Latency90,
		Disqualified:          nodeDossier.Disqualified,
		OfflineSuspended:      nodeDossier.OfflineSuspended,
		UnknownAuditSuspended: nodeDossier.UnknownAuditSuspended,
		ExitInitiatedAt:       nodeDossier.ExitStatus.ExitInitiatedAt,
		ExitFinishedAt:        nodeDossier.ExitStatus.ExitFinishedAt,
	}

	// Map LastContactSuccess and LastContactFailure from Reputation
	if !nodeDossier.Reputation.LastContactSuccess.IsZero() {
		node.LastContactSuccess = &nodeDossier.Reputation.LastContactSuccess
	}
	if !nodeDossier.Reputation.LastContactFailure.IsZero() {
		node.LastContactFailure = &nodeDossier.Reputation.LastContactFailure
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(node)
}

// getNodeStats returns statistics about nodes using optimized SQL aggregation query
func (server *Server) getNodeStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Use optimized SQL aggregation query instead of fetching all nodes
	stats, err := server.db.OverlayCache().GetNodeStats(ctx, defaultOnlineWindow)
	if err != nil {
		sendJSONError(w, "failed to get node stats",
			err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// Helper functions

func getNodeStatus(node *overlay.NodeDossier) string {
	if node.Disqualified != nil {
		return "disqualified"
	}
	if node.UnknownAuditSuspended != nil || node.OfflineSuspended != nil {
		return "suspended"
	}
	if node.ExitStatus.ExitInitiatedAt != nil && node.ExitStatus.ExitFinishedAt == nil {
		return "exiting"
	}
	if node.Reputation.LastContactSuccess.After(time.Now().Add(-defaultOnlineWindow)) {
		return "online"
	}
	return "offline"
}

// exportNodesData exports node data in CSV format
func (server *Server) exportNodesData(w http.ResponseWriter, nodes []Node, statusFilter, countryFilter, format string) {
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=nodes_export.csv")

		// Write CSV header
		csvWriter := csv.NewWriter(w)
		defer csvWriter.Flush()

		headers := []string{
			"Node ID", "Status", "Address", "Country Code", "Created At",
			"Operator Email", "Wallet", "Last Net", "Last IP Port",
			"Free Disk", "Latency (90th)", "Last Contact Success",
			"Last Contact Failure", "Offline Suspended", "Unknown Audit Suspended",
			"Disqualified", "Exit Initiated At", "Exit Finished At",
		}
		csvWriter.Write(headers)

		for _, node := range nodes {
			formatTime := func(t *time.Time) string {
				if t != nil {
					return t.Format("2006-01-02 15:04:05")
				}
				return ""
			}

			row := []string{
				node.ID,
				node.Status,
				node.Address,
				node.CountryCode,
				node.CreatedAt.Format("2006-01-02 15:04:05"),
				node.OperatorEmail,
				node.Wallet,
				node.LastNet,
				node.LastIPPort,
				fmt.Sprintf("%d", node.FreeDisk),
				fmt.Sprintf("%d", node.Latency90),
				formatTime(node.LastContactSuccess),
				formatTime(node.LastContactFailure),
				formatTime(node.OfflineSuspended),
				formatTime(node.UnknownAuditSuspended),
				formatTime(node.Disqualified),
				formatTime(node.ExitInitiatedAt),
				formatTime(node.ExitFinishedAt),
			}
			csvWriter.Write(row)
		}
	} else {
		// JSON format
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=nodes_export.json")

		response := struct {
			TotalNodes int               `json:"totalNodes"`
			Filters    map[string]string `json:"filters"`
			Nodes      []Node            `json:"nodes"`
		}{
			TotalNodes: len(nodes),
			Filters: map[string]string{
				"status":  statusFilter,
				"country": countryFilter,
			},
			Nodes: nodes,
		}

		json.NewEncoder(w).Encode(response)
	}
}

// NodeStatusUpdateRequest represents a request to update a single node's status
// Status values based on getNodeStatusFromSelectedNode logic:
// - "disqualified" - sets disqualified timestamp
// - "exited" - sets exit_finished_at timestamp
// - "exiting" - sets exit_initiated_at timestamp (clears exit_finished_at)
// - "suspended" - sets offline_suspended or unknown_audit_suspended
// - "online" - updates last_contact_success to current time
// - "offline" - sets last_contact_success to epoch
// - "clear_disqualified" - clears disqualified
// - "clear_exited" - clears exit_finished_at
// - "clear_exiting" - clears exit_initiated_at
// - "clear_suspended" - clears both suspension fields
type NodeStatusUpdateRequest struct {
	Status string `json:"status"` // Status to set (see above)
	Reason string `json:"reason"` // Optional reason for disqualification (audit_failure, suspension, node_offline)
}

// NodeStatusUpdateResponse represents the response from node status update
type NodeStatusUpdateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// updateNodeStatus updates the status of a single node with full security and validation
func (server *Server) updateNodeStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Get admin user for audit logging
	adminUser, err := GetAdminUser(ctx)
	if err != nil {
		sendJSONError(w, "Unauthorized", "admin authentication required", http.StatusUnauthorized)
		return
	}

	// Get node ID from URL path
	vars := mux.Vars(r)
	nodeIDStr := vars["nodeId"]
	if nodeIDStr == "" {
		sendJSONError(w, "Bad request", "node ID is required in URL path", http.StatusBadRequest)
		return
	}

	// Parse and validate node ID
	nodeIDStr = strings.TrimSpace(nodeIDStr)
	nodeID, err := storj.NodeIDFromString(nodeIDStr)
	if err != nil {
		sendJSONError(w, "Bad request", "invalid node ID format: "+err.Error(), http.StatusBadRequest)
		return
	}

	if nodeID.IsZero() {
		sendJSONError(w, "Bad request", "node ID cannot be zero", http.StatusBadRequest)
		return
	}

	// Parse request body
	var req NodeStatusUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		server.log.Warn("Failed to decode node status update request", zap.Error(err))
		sendJSONError(w, "Bad request", "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate status - based on getNodeStatusFromSelectedNode calculation logic
	validStatuses := map[string]bool{
		"disqualified":       true, // Sets disqualified timestamp
		"exited":             true, // Sets exit_finished_at timestamp
		"exiting":            true, // Sets exit_initiated_at timestamp, clears exit_finished_at
		"suspended":          true, // Sets offline_suspended (default) or unknown_audit_suspended if reason specified
		"online":             true, // Updates last_contact_success to current time
		"offline":            true, // Sets last_contact_success to epoch
		"clear_disqualified": true, // Clears disqualified
		"clear_exited":       true, // Clears exit_finished_at
		"clear_exiting":      true, // Clears exit_initiated_at
		"clear_suspended":    true, // Clears both suspension fields
		// Legacy support
		"disqualify":              true,
		"suspend_unknown_audit":   true,
		"suspend_offline":         true,
		"unsuspend_unknown_audit": true,
		"unsuspend_offline":       true,
	}
	if !validStatuses[req.Status] {
		sendJSONError(w, "Bad request",
			fmt.Sprintf("invalid status: %s. Valid statuses: disqualified, exited, exiting, suspended, online, offline, clear_disqualified, clear_exited, clear_exiting, clear_suspended", req.Status),
			http.StatusBadRequest)
		return
	}

	// Audit log the action
	server.log.Info("Node status update initiated",
		zap.String("admin_email", adminUser.Email),
		zap.String("node_id", nodeID.String()),
		zap.String("status", req.Status),
		zap.String("reason", req.Reason),
		zap.String("ip", getClientIP(r)))

	// Perform status update based on database columns that control status
	now := time.Now().UTC()
	var updateErr error

	switch req.Status {
	// Set statuses - modify database columns to achieve desired status
	case "disqualified", "disqualify":
		// Sets disqualified timestamp -> status becomes "disqualified"
		reason := overlay.DisqualificationReasonUnknown
		if req.Reason != "" {
			switch strings.ToLower(req.Reason) {
			case "audit_failure":
				reason = overlay.DisqualificationReasonAuditFailure
			case "suspension":
				reason = overlay.DisqualificationReasonSuspension
			case "node_offline":
				reason = overlay.DisqualificationReasonNodeOffline
			}
		}
		_, updateErr = server.db.OverlayCache().DisqualifyNode(ctx, nodeID, now, reason)

	case "exited":
		// Sets exit_finished_at timestamp -> status becomes "exited"
		// Also clears exit_initiated_at if set
		_, updateErr = server.db.OverlayCache().UpdateExitStatus(ctx, &overlay.ExitStatusRequest{
			NodeID:          nodeID,
			ExitFinishedAt:  now,
			ExitSuccess:     true,
			ExitInitiatedAt: time.Time{}, // Zero time to clear if was set
		})

	case "exiting":
		// Sets exit_initiated_at timestamp, clears exit_finished_at -> status becomes "exiting"
		_, updateErr = server.db.OverlayCache().UpdateExitStatus(ctx, &overlay.ExitStatusRequest{
			NodeID:          nodeID,
			ExitInitiatedAt: now,
			ExitFinishedAt:  time.Time{}, // Zero time to clear
			ExitSuccess:     false,
		})

	case "suspended":
		// Sets suspension timestamp -> status becomes "suspended"
		// Default to offline_suspended, use unknown_audit if reason specified
		if req.Reason == "unknown_audit" {
			updateErr = server.db.OverlayCache().TestSuspendNodeUnknownAudit(ctx, nodeID, now)
		} else {
			updateErr = server.db.OverlayCache().TestSuspendNodeOffline(ctx, nodeID, now)
		}

	case "online":
		// Updates last_contact_success to current time -> status becomes "online"
		updateErr = server.db.OverlayCache().UpdateLastContactSuccess(ctx, nodeID, now)

	case "offline":
		// Sets last_contact_success to epoch -> status becomes "offline"
		epoch := time.Time{} // Zero time = epoch
		updateErr = server.db.OverlayCache().UpdateLastContactSuccess(ctx, nodeID, epoch)

	// Clear statuses - set database columns to NULL/zero
	case "clear_disqualified":
		// Clears disqualified -> status calculation will check other fields
		updateErr = server.db.OverlayCache().UpdateReputation(ctx, nodeID, overlay.ReputationUpdate{
			Disqualified: nil,
		})

	case "clear_exited":
		// Clears exit_finished_at -> status calculation will check other fields
		_, updateErr = server.db.OverlayCache().UpdateExitStatus(ctx, &overlay.ExitStatusRequest{
			NodeID:         nodeID,
			ExitFinishedAt: time.Time{}, // Zero time to clear
			ExitSuccess:    false,
		})

	case "clear_exiting":
		// Clears exit_initiated_at -> status calculation will check other fields
		_, updateErr = server.db.OverlayCache().UpdateExitStatus(ctx, &overlay.ExitStatusRequest{
			NodeID:          nodeID,
			ExitInitiatedAt: time.Time{}, // Zero time to clear
			ExitSuccess:     false,
		})

	case "clear_suspended":
		// Clears both suspension fields -> status calculation will check other fields
		updateErr = server.db.OverlayCache().UpdateReputation(ctx, nodeID, overlay.ReputationUpdate{
			OfflineSuspended:      nil,
			UnknownAuditSuspended: nil,
		})

	// Legacy support for old status names
	case "suspend_unknown_audit":
		updateErr = server.db.OverlayCache().TestSuspendNodeUnknownAudit(ctx, nodeID, now)

	case "suspend_offline":
		updateErr = server.db.OverlayCache().TestSuspendNodeOffline(ctx, nodeID, now)

	case "unsuspend_unknown_audit":
		updateErr = server.db.OverlayCache().TestUnsuspendNodeUnknownAudit(ctx, nodeID)

	case "unsuspend_offline":
		updateErr = server.db.OverlayCache().UpdateReputation(ctx, nodeID, overlay.ReputationUpdate{
			OfflineSuspended: nil,
		})
	}

	if updateErr != nil {
		server.log.Warn("Failed to update node status",
			zap.String("node_id", nodeID.String()),
			zap.String("status", req.Status),
			zap.Error(updateErr))

		sendJSONError(w, "Failed to update node status",
			fmt.Sprintf("failed to update node %s: %v", nodeID.String(), updateErr),
			http.StatusInternalServerError)
		return
	}

	// Final audit log
	server.log.Info("Node status update completed",
		zap.String("admin_email", adminUser.Email),
		zap.String("node_id", nodeID.String()),
		zap.String("status", req.Status),
		zap.Bool("success", true))

	// Prepare response
	response := NodeStatusUpdateResponse{
		Success: true,
		Message: fmt.Sprintf("Node %s status updated to %s successfully", nodeID.String(), req.Status),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
