// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package nodeselection

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"golang.org/x/exp/slices"

	"storj.io/common/pb"
	"storj.io/common/storj"
	"storj.io/common/storj/location"
)

// NodeTag is a tag associated with a node (approved by signer).
type NodeTag struct {
	NodeID   storj.NodeID
	SignedAt time.Time
	Signer   storj.NodeID
	Name     string
	Value    []byte
}

// NodeTags is a collection of multiple NodeTag.
type NodeTags []NodeTag

// FindBySignerAndName selects first tag with same name / NodeID.
func (n NodeTags) FindBySignerAndName(signer storj.NodeID, name string) (NodeTag, error) {
	for _, tag := range n {
		if tag.Name == name && signer == tag.Signer {
			return tag, nil
		}
	}
	return NodeTag{}, errs.New("tags not found")
}

// SelectedNode is used as a result for creating orders limits.
type SelectedNode struct {
	ID          storj.NodeID
	Address     *pb.NodeAddress
	Email       string
	Wallet      string
	LastNet     string
	LastIPPort  string
	CountryCode location.CountryCode
	Exiting     bool
	Suspended   bool
	Online      bool
	Vetted      bool
	Tags        NodeTags
}

// SelectedNodeWithExtendedData is a SelectedNode with extended data.
type SelectedNodeWithExtendedData struct {
	SelectedNode
	CreatedAt             time.Time
	FreeDisk              int64
	Latency90             int64
	LastContactSuccess    time.Time
	LastContactFailure    time.Time
	OfflineSuspended      *time.Time
	UnknownAuditSuspended *time.Time
	Disqualified          *time.Time
	ExitInitiatedAt       *time.Time
	ExitFinishedAt        *time.Time
}

// NodeQueryFilters contains filter parameters for database-level node queries.
// All filters are applied at the SQL level for optimal performance.
type NodeQueryFilters struct {
	// Status filter: "online", "offline", "suspended", "disqualified", "exiting", "exited", or empty for all
	Status string
	// Email filter: partial match (case-insensitive LIKE)
	Email string
	// Countries: list of country codes to filter by (IN clause)
	Countries []string
	// CreatedAfter: filter nodes created after this time
	CreatedAfter *time.Time
	// CreatedBefore: filter nodes created before this time
	CreatedBefore *time.Time
	// Search: general search across multiple fields (email, address, wallet, node ID, last_net, last_ip_port)
	Search string
}

func (filters NodeQueryFilters) ToSQLWhereClause(args *[]interface{}, argIndex *int, onlineThreshold time.Time) (string, error) {
	var conditions []string

	if filters.Status != "" {
		switch strings.ToLower(filters.Status) {
		case "online":
			conditions = append(conditions, fmt.Sprintf("last_contact_success > $%d", *argIndex))
			*args = append(*args, onlineThreshold)
			(*argIndex)++
		case "offline":
			conditions = append(conditions, fmt.Sprintf("last_contact_success <= $%d", *argIndex))
			*args = append(*args, onlineThreshold)
			(*argIndex)++
		case "suspended":
			conditions = append(conditions, "(offline_suspended IS NOT NULL OR unknown_audit_suspended IS NOT NULL)")
		case "disqualified":
			conditions = append(conditions, "disqualified IS NOT NULL")
		case "exiting":
			conditions = append(conditions, "exit_initiated_at IS NOT NULL AND exit_finished_at IS NULL")
		case "exited":
			conditions = append(conditions, "exit_finished_at IS NOT NULL")
		}
	}

	if filters.Email != "" {
		emailPattern := "%" + strings.ToLower(filters.Email) + "%"
		conditions = append(conditions, fmt.Sprintf("LOWER(email) LIKE $%d", *argIndex))
		*args = append(*args, emailPattern)
		(*argIndex)++
	}

	if len(filters.Countries) > 0 {
		countryPlaceholders := make([]string, len(filters.Countries))
		for i, country := range filters.Countries {
			countryPlaceholders[i] = fmt.Sprintf("$%d", *argIndex)
			*args = append(*args, strings.ToUpper(country))
			(*argIndex)++
		}
		conditions = append(conditions, fmt.Sprintf("UPPER(country_code) IN (%s)", strings.Join(countryPlaceholders, ", ")))
	}

	if filters.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", *argIndex))
		*args = append(*args, *filters.CreatedAfter)
		(*argIndex)++
	}

	if filters.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", *argIndex))
		*args = append(*args, *filters.CreatedBefore)
		(*argIndex)++
	}

	// General search across multiple fields: email, address, wallet, last_net, last_ip_port
	// For node ID, we need to check if the search string is a valid NodeID format
	if filters.Search != "" {
		searchPattern := "%" + strings.ToLower(filters.Search) + "%"
		searchConditions := []string{
			fmt.Sprintf("LOWER(email) LIKE $%d", *argIndex),
			fmt.Sprintf("LOWER(address) LIKE $%d", *argIndex),
			fmt.Sprintf("LOWER(wallet) LIKE $%d", *argIndex),
			fmt.Sprintf("LOWER(last_net) LIKE $%d", *argIndex),
			fmt.Sprintf("LOWER(last_ip_port) LIKE $%d", *argIndex),
		}

		// Try to parse as NodeID - if valid, also search by node ID
		if nodeID, err := storj.NodeIDFromString(filters.Search); err == nil && !nodeID.IsZero() {
			(*argIndex)++
			searchConditions = append(searchConditions, fmt.Sprintf("id = $%d", *argIndex))
			*args = append(*args, nodeID.Bytes())
		}

		*args = append(*args, searchPattern)
		(*argIndex)++

		// Combine search conditions with OR
		conditions = append(conditions, "("+strings.Join(searchConditions, " OR ")+")")
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), nil
}

// Clone returns a deep clone of the selected node.
func (node *SelectedNode) Clone() *SelectedNode {
	newNode := *node
	newNode.Address = pb.CopyNodeAddress(node.Address)
	newNode.Tags = slices.Clone(node.Tags)
	return &newNode
}

// NodeAttribute returns a string (like last_net or tag value) for each SelectedNode.
type NodeAttribute func(SelectedNode) string

// LastNetAttribute is used for subnet based declumping/selection.
var LastNetAttribute = mustCreateNodeAttribute("last_net")

func mustCreateNodeAttribute(attr string) NodeAttribute {
	nodeAttr, err := CreateNodeAttribute(attr)
	if err != nil {
		panic(err)
	}
	return nodeAttr
}

// NodeTagAttribute selects a tag value from node.
func NodeTagAttribute(signer storj.NodeID, tagName string) NodeAttribute {
	return func(node SelectedNode) string {
		tag, err := node.Tags.FindBySignerAndName(signer, tagName)
		if err != nil {
			return ""
		}
		return string(tag.Value)
	}
}

// AnyNodeTagAttribute selects a tag value from node, accepts any signer.
func AnyNodeTagAttribute(tagName string) NodeAttribute {
	return func(node SelectedNode) string {
		for _, tag := range node.Tags {
			if tag.Name == tagName {
				return string(tag.Value)
			}
		}
		return ""
	}
}

// CreateNodeAttribute creates the NodeAttribute selected based on a string definition.
func CreateNodeAttribute(attr string) (NodeAttribute, error) {
	if strings.HasPrefix(attr, "tag:") {
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(attr, "tag:")), "/")
		switch len(parts) {
		case 1:
			return AnyNodeTagAttribute(parts[0]), nil
		case 2:
			id, err := storj.NodeIDFromString(parts[0])
			if err != nil {
				return nil, errs.New("node attribute definition (%s) has invalid NodeID: %s", attr, err.Error())
			}
			return NodeTagAttribute(id, parts[1]), nil
		default:
			return nil, errs.New("tag attribute should be defined as `tag:key` (any signer) or `tag:signer/key`")
		}
	}
	switch attr {
	case "last_net":
		return func(node SelectedNode) string {
			return node.LastNet
		}, nil
	case "wallet":
		return func(node SelectedNode) string {
			return node.Wallet
		}, nil
	case "email":
		return func(node SelectedNode) string {
			return node.Email
		}, nil
	case "country":
		return func(node SelectedNode) string {
			return node.CountryCode.String()
		}, nil
	case "vetted":
		return func(node SelectedNode) string {
			return fmt.Sprintf("%t", node.Vetted)
		}, nil
	default:
		return nil, errors.New("Unsupported node attribute: " + attr)
	}
}
