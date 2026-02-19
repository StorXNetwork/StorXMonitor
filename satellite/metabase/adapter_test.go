// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package metabase_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/metabasetest"
)

func TestAdapterBeginObject(t *testing.T) {
	metabasetest.Run(t, func(ctx *testcontext.Context, t *testing.T, db *metabase.DB) {
		// spanner if available, default DB if not
		adapter := db.ChooseAdapter(testrand.UUID())

		uuid := testrand.UUID()
		o := &metabase.Object{}
		err := adapter.BeginObjectNextVersion(ctx, metabase.BeginObjectNextVersion{
			ObjectStream: metabase.ObjectStream{
				ProjectID: uuid,
			},
		}, o)
		require.NoError(t, err)
		require.Equal(t, metabase.Version(1), o.Version)

		err = adapter.BeginObjectNextVersion(ctx, metabase.BeginObjectNextVersion{
			ObjectStream: metabase.ObjectStream{
				ProjectID: uuid,
			},
		}, o)
		require.NoError(t, err)
		require.Equal(t, metabase.Version(2), o.Version)
	})
}
