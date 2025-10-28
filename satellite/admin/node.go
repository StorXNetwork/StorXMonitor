// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"storj.io/common/storj"
	"storj.io/storj/satellite/overlay"
)

// Node represents a storage node in the admin dashboard (detailed view)
type Node struct {
	ID            string    `json:"id"`
	Address       string    `json:"address"`
	CountryCode   string    `json:"countryCode"`
	CreatedAt     time.Time `json:"createdAt"`
	Status        string    `json:"status"` // online, offline, disqualified, suspended, exiting
	FreeDisk      int64     `json:"freeDisk"`
	Latency90     int64     `json:"latency90"`
	Version       string    `json:"version"`
	OperatorEmail string    `json:"operatorEmail"`
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

// getAllNodes returns all storage nodes with pagination and filtering
func (server *Server) getAllNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Parse query parameters
	query := r.URL.Query()

	// Parse limit
	limit := uint64(50)
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.ParseUint(limitStr, 10, 32); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	// Parse page
	page := uint64(1)
	if pageStr := query.Get("page"); pageStr != "" {
		if p, err := strconv.ParseUint(pageStr, 10, 32); err == nil && p > 0 {
			page = p
		}
	}

	// Parse filters
	statusFilter := strings.ToLower(strings.TrimSpace(query.Get("status")))
	countryFilter := strings.ToUpper(strings.TrimSpace(query.Get("country")))

	// Parse sort
	sortBy := query.Get("sort_by")
	if sortBy == "" {
		sortBy = "createdAt"
	}
	sortOrder := query.Get("sort_order")
	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Get all participating nodes from overlay
	onlineWindow := 2 * time.Hour
	selectedNodes, err := server.db.OverlayCache().GetParticipatingNodes(ctx, onlineWindow, 0)
	if err != nil {
		sendJSONError(w, "Internal server error", "failed to fetch nodes", http.StatusInternalServerError)
		return
	}

	// Convert to NodeDossier format and filter
	var nodes []Node
	for _, selectedNode := range selectedNodes {
		nodeDossier, err := server.db.OverlayCache().Get(ctx, selectedNode.ID)
		if err != nil {
			server.log.Warn("failed to fetch node dossier",
				zap.String("nodeID", selectedNode.ID.String()),
				zap.Error(err))
			continue
		}

		// Apply status filter
		status := getNodeStatus(nodeDossier, onlineWindow)
		if statusFilter != "" && status != statusFilter {
			continue
		}

		// Apply country filter
		if countryFilter != "" && nodeDossier.CountryCode.String() != countryFilter {
			continue
		}

		nodes = append(nodes, Node{
			ID:          nodeDossier.Id.String(),
			Address:     nodeDossier.Address.Address,
			CountryCode: nodeDossier.CountryCode.String(),
			CreatedAt:   nodeDossier.CreatedAt,
			Status:      status,
			FreeDisk:    nodeDossier.Capacity.FreeDisk,

			Latency90:     nodeDossier.Reputation.Latency90,
			OperatorEmail: nodeDossier.Operator.Email,
		})
	}

	// Apply sorting
	sort.Slice(nodes, func(i, j int) bool {
		var result bool
		switch sortBy {
		case "latency":
			result = nodes[i].Latency90 < nodes[j].Latency90
		case "freeDisk":
			result = nodes[i].FreeDisk > nodes[j].FreeDisk
		default:
			result = nodes[i].CreatedAt.After(nodes[j].CreatedAt)
		}
		if sortOrder == "asc" {
			return !result
		}
		return result
	})

	// Apply pagination
	totalCount := uint64(len(nodes))
	totalPages := (totalCount + limit - 1) / limit
	offset := (page - 1) * limit

	var paginatedNodes []Node
	if offset < totalCount {
		end := offset + limit
		if end > totalCount {
			end = totalCount
		}
		paginatedNodes = nodes[offset:end]
	}

	// Check if this is an export request
	format := query.Get("format")
	if format == "csv" {
		server.exportNodesData(w, nodes, statusFilter, countryFilter, format)
		return
	}

	// Create response
	response := NodeResponse{
		Nodes:       paginatedNodes,
		PageCount:   uint(totalPages),
		CurrentPage: uint(page),
		TotalCount:  totalCount,
		HasMore:     page < totalPages,
		Limit:       uint(limit),
		Offset:      offset,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
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

	onlineWindow := 2 * time.Hour
	status := getNodeStatus(nodeDossier, onlineWindow)

	node := Node{
		ID:          nodeDossier.Id.String(),
		Address:     nodeDossier.Address.Address,
		CountryCode: nodeDossier.CountryCode.String(),
		CreatedAt:   nodeDossier.CreatedAt,
		Status:      status,
		FreeDisk:    nodeDossier.Capacity.FreeDisk,

		Latency90:     nodeDossier.Reputation.Latency90,
		OperatorEmail: nodeDossier.Operator.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(node)
}

// getNodeStats returns statistics about nodes
func (server *Server) getNodeStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Get all participating nodes to calculate statistics
	onlineWindow := 2 * time.Hour
	asOfSystemInterval := 0 * time.Second

	selectedNodes, err := server.db.OverlayCache().GetParticipatingNodes(ctx, onlineWindow, asOfSystemInterval)
	if err != nil {
		sendJSONError(w, "failed to get participating nodes",
			err.Error(), http.StatusInternalServerError)
		return
	}

	// Calculate statistics
	var totalNodes, onlineNodes, offlineNodes, disqualifiedNodes, suspendedNodes, exitingNodes int
	var totalLatency, usedCapacity int64

	for _, selectedNode := range selectedNodes {
		nodeDossier, err := server.db.OverlayCache().Get(ctx, selectedNode.ID)
		if err != nil {
			continue // Skip nodes we can't get details for
		}

		totalNodes++
		status := getNodeStatus(nodeDossier, onlineWindow)

		switch status {
		case "online":
			onlineNodes++
		case "offline":
			offlineNodes++
		case "disqualified":
			disqualifiedNodes++
		case "suspended":
			suspendedNodes++
		case "exiting":
			exitingNodes++
		}

		// Calculate latency statistics
		totalLatency += nodeDossier.Reputation.Latency90
		usedCapacity += nodeDossier.Capacity.FreeDisk
	}

	// Calculate average latency
	var averageLatency int64
	if totalNodes > 0 {
		averageLatency = totalLatency / int64(totalNodes)
	}

	stats := struct {
		TotalNodes        int   `json:"totalNodes"`
		OnlineNodes       int   `json:"onlineNodes"`
		OfflineNodes      int   `json:"offlineNodes"`
		DisqualifiedNodes int   `json:"disqualifiedNodes"`
		SuspendedNodes    int   `json:"suspendedNodes"`
		ExitingNodes      int   `json:"exitingNodes"`
		UsedCapacity      int64 `json:"usedCapacity"`
		AverageLatency    int64 `json:"averageLatency"`
	}{
		TotalNodes:        totalNodes,
		OnlineNodes:       onlineNodes,
		OfflineNodes:      offlineNodes,
		DisqualifiedNodes: disqualifiedNodes,
		SuspendedNodes:    suspendedNodes,
		ExitingNodes:      exitingNodes,
		UsedCapacity:      usedCapacity,
		AverageLatency:    averageLatency,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// Helper functions

// getNodeStatus determines the status of a node based on its properties
func getNodeStatus(node *overlay.NodeDossier, onlineWindow time.Duration) string {
	now := time.Now()

	// Check if node is disqualified
	if node.Disqualified != nil {
		return "disqualified"
	}

	// Check if node is suspended
	if node.UnknownAuditSuspended != nil || node.OfflineSuspended != nil {
		return "suspended"
	}

	// Check if node is exiting
	if node.ExitStatus.ExitInitiatedAt != nil && node.ExitStatus.ExitFinishedAt == nil {
		return "exiting"
	}

	// Check if node is online (last contact within online window)
	if node.Reputation.LastContactSuccess.After(now.Add(-onlineWindow)) {
		return "online"
	}

	// Node is offline
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

		// Write header row
		headers := []string{
			"Node ID", "Status", "Address", "Country Code", "Free Disk",
			"Latency (90th)", "Version", "Created At", "Operator Email",
		}
		csvWriter.Write(headers)

		// Write data rows
		for _, node := range nodes {
			row := []string{
				node.ID,
				node.Status,
				node.Address,
				node.CountryCode,
				fmt.Sprintf("%d", node.FreeDisk),
				fmt.Sprintf("%d", node.Latency90),
				node.Version,
				node.CreatedAt.Format("2006-01-02 15:04:05"),
				node.OperatorEmail,
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
