// Copyright (C) 2026 StorXNetwork Labs, Inc.
// See LICENSE for copying information.

package orders

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/common/identity/testidentity"
	"github.com/StorXNetwork/common/pb"
	"github.com/StorXNetwork/common/signing"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/testcontext"
	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
)

// trackingOrdersDB records UpdateBucketBandwidthAllocation calls for live-accounting assertions.
type trackingOrdersDB struct {
	DB
	allocations []allocationCall
}

type allocationCall struct {
	projectID  uuid.UUID
	bucketName []byte
	action     pb.PieceAction
	amount     int64
}

func (db *trackingOrdersDB) UpdateBucketBandwidthAllocation(ctx context.Context, projectID uuid.UUID, bucketName []byte, action pb.PieceAction, amount int64, intervalStart time.Time) error {
	db.allocations = append(db.allocations, allocationCall{
		projectID:  projectID,
		bucketName: append([]byte(nil), bucketName...),
		action:     action,
		amount:     amount,
	})
	return db.DB.UpdateBucketBandwidthAllocation(ctx, projectID, bucketName, action, amount, intervalStart)
}

func TestCreateGetOrderLimits_UserBandwidthTracking(t *testing.T) {
	ctx := testcontext.New(t)
	ctrl := gomock.NewController(t)

	bucket := metabase.BucketLocation{ProjectID: testrand.UUID(), BucketName: "bucket1"}

	pieces := metabase.Pieces{}
	nodes := map[storxnetwork.NodeID]*nodeselection.SelectedNode{}
	for i := 0; i < 8; i++ {
		nodeID := testrand.NodeID()
		nodes[nodeID] = &nodeselection.SelectedNode{
			ID: nodeID,
			Address: &pb.NodeAddress{
				Address: fmt.Sprintf("host%d.com", i),
			},
		}
		pieces = append(pieces, metabase.Piece{
			Number:      uint16(i),
			StorageNode: nodeID,
		})
	}

	testIdentity, err := testidentity.PregeneratedIdentity(0, storxnetwork.LatestIDVersion())
	require.NoError(t, err)
	k := signing.SignerFromFullIdentity(testIdentity)

	uplinkIdentity, err := testidentity.PregeneratedIdentity(0, storxnetwork.LatestIDVersion())
	require.NoError(t, err)

	overlayService := NewMockOverlayForOrders(ctrl)
	overlayService.
		EXPECT().
		CachedGetOnlineNodesForGet(gomock.Any(), gomock.Any()).
		Return(nodes, nil).AnyTimes()

	segment := metabase.Segment{
		StreamID:  testrand.UUID(),
		CreatedAt: time.Now(),
		Redundancy: storxnetwork.RedundancyScheme{
			Algorithm:      storxnetwork.ReedSolomon,
			ShareSize:      256,
			RequiredShares: 4,
			RepairShares:   5,
			OptimalShares:  6,
			TotalShares:    10,
		},
		Pieces:       pieces,
		EncryptedKey: []byte{1, 2, 3, 4},
		RootPieceID:  testrand.PieceID(),
	}

	for _, tt := range []struct {
		name                string
		create              func(*Service) ([]*pb.AddressedOrderLimit, storxnetwork.PiecePrivateKey, error)
		wantAction          pb.PieceAction
		wantAllocationCalls int
	}{
		{
			name: "billable GET increments live allocation",
			create: func(service *Service) ([]*pb.AddressedOrderLimit, storxnetwork.PiecePrivateKey, error) {
				return service.CreateGetOrderLimits(ctx, uplinkIdentity.PeerIdentity(), bucket, segment, 0, 0)
			},
			wantAction:          pb.PieceAction_GET,
			wantAllocationCalls: 1,
		},
		{
			name: "GET_INTERNAL skips live allocation",
			create: func(service *Service) ([]*pb.AddressedOrderLimit, storxnetwork.PiecePrivateKey, error) {
				return service.CreateInternalGetOrderLimits(ctx, uplinkIdentity.PeerIdentity(), bucket, segment, 0, 0)
			},
			wantAction:          pb.PieceAction_GET_INTERNAL,
			wantAllocationCalls: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracking := &trackingOrdersDB{DB: NewNoopDB()}
			service, err := NewService(zaptest.NewLogger(t), k, overlayService, tracking,
				func(constraint storxnetwork.PlacementConstraint) (nodeselection.NodeFilter, nodeselection.DownloadSelector) {
					return nodeselection.AnyFilter{}, nodeselection.DefaultDownloadSelector
				},
				Config{
					EncryptionKeys: EncryptionKeys{
						Default: EncryptionKey{
							ID:  EncryptionKeyID{1, 2, 3, 4, 5, 6, 7, 8},
							Key: testrand.Key(),
						},
					},
				})
			require.NoError(t, err)

			limits, _, err := tt.create(service)
			require.NoError(t, err)
			require.NotEmpty(t, limits)

			var seenAction pb.PieceAction
			for _, limit := range limits {
				if limit != nil && limit.Limit != nil {
					seenAction = limit.Limit.Action
					require.Equal(t, tt.wantAction, limit.Limit.Action)
				}
			}
			require.Equal(t, tt.wantAction, seenAction)
			require.Len(t, tracking.allocations, tt.wantAllocationCalls)
		})
	}
}

func TestIsUserBandwidthAction(t *testing.T) {
	for _, tt := range []struct {
		action pb.PieceAction
		want   bool
	}{
		{pb.PieceAction_GET, true},
		{pb.PieceAction_PUT, true},
		{pb.PieceAction_GET_INTERNAL, false},
		{pb.PieceAction_GET_REPAIR, false},
		{pb.PieceAction_GET_AUDIT, false},
		{pb.PieceAction_PUT_REPAIR, false},
		{pb.PieceAction_DELETE, false},
		{pb.PieceAction_INVALID, false},
	} {
		t.Run(tt.action.String(), func(t *testing.T) {
			require.Equal(t, tt.want, IsUserBandwidthAction(tt.action))
		})
	}
}
