// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satstore

import (
	"testing"

	"github.com/zeebo/assert"

	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testrand"
)

func TestSatStore(t *testing.T) {
	ctx := t.Context()

	dir := t.TempDir()
	s1 := NewSatelliteStore(dir, "ext1")
	s2 := NewSatelliteStore(dir, "ext2")

	sat1 := testrand.NodeID()
	sat2 := testrand.NodeID()

	// set and get should work and not collide
	b := func(x string) []byte { return []byte(x) }

	assert.NoError(t, s1.Set(ctx, sat1, b("s1 sat1")))
	assert.NoError(t, s1.Set(ctx, sat2, b("s1 sat2")))
	assert.NoError(t, s2.Set(ctx, sat1, b("s2 sat1")))
	assert.NoError(t, s2.Set(ctx, sat2, b("s2 sat2")))

	check := func(s *SatelliteStore, sat storxnetwork.NodeID, exp string) {
		t.Helper()
		got, err := s.Get(ctx, sat)
		assert.NoError(t, err)
		assert.Equal(t, exp, string(got))
	}

	check(s1, sat1, "s1 sat1")
	check(s1, sat2, "s1 sat2")
	check(s2, sat1, "s2 sat1")
	check(s2, sat2, "s2 sat2")

	// range should work
	collect := func(s *SatelliteStore) map[storxnetwork.NodeID]string {
		out := make(map[storxnetwork.NodeID]string)
		assert.NoError(t, s.Range(func(sat storxnetwork.NodeID, data []byte) error {
			if _, ok := out[sat]; ok {
				t.Fatal("duplicate satellite")
			}
			out[sat] = string(data)
			return nil
		}))
		return out
	}

	assert.DeepEqual(t, collect(s1), map[storxnetwork.NodeID]string{
		sat1: "s1 sat1",
		sat2: "s1 sat2",
	})
	assert.DeepEqual(t, collect(s2), map[storxnetwork.NodeID]string{
		sat1: "s2 sat1",
		sat2: "s2 sat2",
	})

	// update should work
	assert.NoError(t, s1.Set(ctx, sat1, b("s1 sat1 updated")))
	check(s1, sat1, "s1 sat1 updated")
	assert.DeepEqual(t, collect(s1), map[storxnetwork.NodeID]string{
		sat1: "s1 sat1 updated",
		sat2: "s1 sat2",
	})
}
