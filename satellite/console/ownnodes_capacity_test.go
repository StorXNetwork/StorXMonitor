// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMinOwnNodesRequired(t *testing.T) {
	require.Equal(t, 10, MinOwnNodesRequired)
}

func TestMergeOwnNodesIntoJSONObject(t *testing.T) {
	status := &OwnNodesCapacityStatus{
		Mode:      StorageDestinationOwnNodes,
		Required:  true,
		NodeCount: 3,
		MinNodes:  10,
		Ready:     false,
		Message:   "need more nodes",
	}
	body := []byte(`{"re_auth_required":{"count":0,"items":[]}}`)
	out := mergeOwnNodesIntoJSONObject(body, "own_nodes", status)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Contains(t, parsed, "own_nodes")
	require.Contains(t, parsed, "re_auth_required")

	var own OwnNodesCapacityStatus
	require.NoError(t, json.Unmarshal(parsed["own_nodes"], &own))
	require.Equal(t, 3, own.NodeCount)
	require.False(t, own.Ready)
}

func TestMergeOwnNodesCreateFlags(t *testing.T) {
	body := []byte(`{"ok":true}`)
	out := mergeOwnNodesCreateFlags(body, true)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Equal(t, true, parsed["jobs_created_inactive"])
}
