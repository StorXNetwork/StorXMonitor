// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"strconv"
	"strings"

	"github.com/jackc/pglogrepl"
)

const optionKeySkipPendingCleanup = "skip_pending_cleanup"

const pendingCleanupStatus int64 = 1

func tableOptionSkipPendingCleanup(opts map[string]string) bool {
	if opts == nil {
		return false
	}
	v := strings.TrimSpace(strings.ToLower(opts[optionKeySkipPendingCleanup]))
	switch v {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func isPendingCleanupStatus(v interface{}) bool {
	return smallIntFromReplicationValue(v) == pendingCleanupStatus
}

func shouldSkipPendingCleanupDelete(rel *pglogrepl.RelationMessage, tuple *pglogrepl.TupleData, oldData map[string]interface{}) bool {
	if rel == nil {
		return false
	}
	if v, ok := mapStatusValue(oldData); ok {
		return isPendingCleanupStatus(v)
	}
	return walStatusColumnIsPending(rel, tuple)
}

func mapStatusValue(oldData map[string]interface{}) (interface{}, bool) {
	if oldData == nil {
		return nil, false
	}
	v, ok := oldData["status"]
	if !ok || v == nil {
		return nil, false
	}
	return v, true
}

func smallIntFromReplicationValue(v interface{}) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int32:
		return int64(x)
	case int:
		return int64(x)
	case int16:
		return int64(x)
	case uint8:
		return int64(x)
	case uint16:
		return int64(x)
	case uint32:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		if x == "" {
			return 0
		}
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func walStatusColumnIsPending(rel *pglogrepl.RelationMessage, tuple *pglogrepl.TupleData) bool {
	if tuple == nil {
		return false
	}
	for i, rc := range rel.Columns {
		if rc.Name != "status" {
			continue
		}
		if i >= len(tuple.Columns) {
			return false
		}
		tc := tuple.Columns[i]
		switch tc.DataType {
		case 'n':
			return false
		case 'u':
			return false
		case 't', 'b':
			v := convertValueByOID(rc.DataType, tc.DataType, tc.Data)
			return isPendingCleanupStatus(v)
		default:
			return false
		}
	}
	return false
}
