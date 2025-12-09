// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"encoding/binary"
	"time"

	"github.com/jackc/pglogrepl"
)

var (
	postgresEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
)

// parseTimestamp parses a PostgreSQL TIMESTAMPTZ value from binary data.
func parseTimestamp(data []byte) *time.Time {
	if len(data) < 8 {
		return nil
	}
	microseconds := int64(binary.BigEndian.Uint64(data))
	t := postgresEpoch.Add(time.Duration(microseconds) * time.Microsecond)
	return &t
}

// extractTableData extracts table data from a WAL tuple generically.
func extractTableData(rel *pglogrepl.RelationMessage, tuple *pglogrepl.TupleData) (map[string]interface{}, error) {
	if rel == nil || tuple == nil {
		return nil, Error.New("relation or tuple is nil")
	}

	data := make(map[string]interface{})

	for i, col := range tuple.Columns {
		if i >= len(rel.Columns) {
			continue
		}

		colName := rel.Columns[i].Name
		colOID := rel.Columns[i].DataType

		if col.DataType == 'n' {
			data[colName] = nil
			continue
		}

		value := convertValueByOID(colOID, col.DataType, col.Data)
		data[colName] = value
	}

	return data, nil
}

// convertValueByOID converts a PostgreSQL value based on OID and data format.
func convertValueByOID(oid uint32, dataFormat byte, data []byte) interface{} {
	if dataFormat == 't' {
		switch oid {
		case 16:
			if len(data) > 0 && (data[0] == 't' || data[0] == 'T') {
				return true
			}
			return false
		case 20, 21, 23:
			return string(data)
		default:
			return string(data)
		}
	}

	switch oid {
	case 20:
		if len(data) >= 8 {
			return int64(binary.BigEndian.Uint64(data))
		}
	case 21:
		if len(data) >= 2 {
			return int16(binary.BigEndian.Uint16(data))
		}
	case 23:
		if len(data) >= 4 {
			return int32(binary.BigEndian.Uint32(data))
		}
	case 16:
		if len(data) >= 1 {
			return data[0] != 0
		}
	case 25, 1043:
		return string(data)
	case 1114, 1184:
		if t := parseTimestamp(data); t != nil {
			return *t
		}
	case 17:
		return data
	case 700, 701:
		if len(data) >= 8 {
			bits := binary.BigEndian.Uint64(data)
			return bits
		}
	default:
		return data
	}

	return nil
}
