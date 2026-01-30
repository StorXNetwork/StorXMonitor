// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package contact

import (
	"testing"

	"github.com/StorXNetwork/common/pb"
	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
)

func TestEmitEventkitEvent(t *testing.T) {
	ctx := testcontext.New(t)
	emitEventkitEvent(ctx, &pb.CheckInRequest{
		Address: "127.0.0.1:234",
	}, false, false, overlay.NodeCheckInInfo{})
}
