// // Copyright (C) 2019 Storj Labs, Inc.
// // See LICENSE for copying information.
package overlay_test

// import (
// 	"context"
// 	"fmt"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"

// 	"github.com/StorXNetwork/common/pb"
// 	"github.com/StorXNetwork/common/storxnetwork"
// 	"github.com/StorXNetwork/common/testcontext"
// 	"github.com/StorXNetwork/StorXMonitor/satellite"
// 	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
// 	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
// 	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/satellitedbtest"
// 	"github.com/StorXNetwork/StorXMonitor/shared/location"
// )

// func TestStatDB(t *testing.T) {
// 	satellitedbtest.Run(t, func(ctx *testcontext.Context, t *testing.T, db satellite.DB) {
// 		testDatabase(ctx, t, db.OverlayCache())
// 	})
// }

// func testDatabase(ctx context.Context, t *testing.T, cache overlay.DB) {
// 	for i, tt := range []struct {
// 		nodeID                storxnetwork.NodeID
// 		unknownAuditSuspended bool
// 		offlineSuspended      bool
// 		disqualified          bool
// 		offline               bool
// 		gracefullyExited      bool
// 		countryCode           string
// 	}{
// 		{storxnetwork.NodeID{1}, false, false, false, false, false, "DE"}, // good
// 		{storxnetwork.NodeID{2}, false, false, true, false, false, "DE"},  // disqualified
// 		{storxnetwork.NodeID{3}, true, false, false, false, false, "DE"},  // unknown audit suspended
// 		{storxnetwork.NodeID{4}, false, false, false, true, false, "DE"},  // offline
// 		{storxnetwork.NodeID{5}, false, false, false, false, true, "DE"},  // gracefully exited
// 		{storxnetwork.NodeID{6}, false, true, false, false, false, "DE"},  // offline suspended
// 		{storxnetwork.NodeID{7}, false, false, false, false, false, "FR"}, // excluded country
// 		{storxnetwork.NodeID{8}, false, false, false, false, false, ""},   // good
// 	} {
// 		addr := fmt.Sprintf("127.0.%d.0:8080", i)
// 		lastNet := fmt.Sprintf("127.0.%d", i)
// 		d := overlay.NodeCheckInInfo{
// 			NodeID:      tt.nodeID,
// 			Address:     &pb.NodeAddress{Address: addr},
// 			LastIPPort:  addr,
// 			LastNet:     lastNet,
// 			Version:     &pb.NodeVersion{Version: "v1.0.0"},
// 			Capacity:    &pb.NodeCapacity{},
// 			IsUp:        true,
// 			CountryCode: location.ToCountryCode(tt.countryCode),
// 		}
// 		err := cache.UpdateCheckIn(ctx, d, time.Now().UTC(), overlay.NodeSelectionConfig{})
// 		require.NoError(t, err)

// 		if tt.unknownAuditSuspended {
// 			err = cache.TestSuspendNodeUnknownAudit(ctx, tt.nodeID, time.Now())
// 			require.NoError(t, err)
// 		}

// 		if tt.offlineSuspended {
// 			err = cache.TestSuspendNodeOffline(ctx, tt.nodeID, time.Now())
// 			require.NoError(t, err)
// 		}

// 		if tt.disqualified {
// 			_, err = cache.DisqualifyNode(ctx, tt.nodeID, time.Now(), overlay.DisqualificationReasonUnknown)
// 			require.NoError(t, err)
// 		}
// 		if tt.offline {
// 			checkInInfo := getNodeInfo(tt.nodeID)
// 			checkInInfo.CountryCode = location.ToCountryCode(tt.countryCode)
// 			err = cache.UpdateCheckIn(ctx, checkInInfo, time.Now().Add(-2*time.Hour), overlay.NodeSelectionConfig{})
// 			require.NoError(t, err)
// 		}
// 		if tt.gracefullyExited {
// 			req := &overlay.ExitStatusRequest{
// 				NodeID:              tt.nodeID,
// 				ExitInitiatedAt:     time.Now(),
// 				ExitLoopCompletedAt: time.Now(),
// 				ExitFinishedAt:      time.Now(),
// 			}
// 			_, err := cache.UpdateExitStatus(ctx, req)
// 			require.NoError(t, err)
// 		}
// 	}

// 	nodeIds := storxnetwork.NodeIDList{
// 		storxnetwork.NodeID{1}, storxnetwork.NodeID{2},
// 		storxnetwork.NodeID{3}, storxnetwork.NodeID{4},
// 		storxnetwork.NodeID{5}, storxnetwork.NodeID{6},
// 		storxnetwork.NodeID{7}, storxnetwork.NodeID{8},
// 		storxnetwork.NodeID{9},
// 	}

// 	t.Run("GetParticipatingNodes", func(t *testing.T) {
// 		selectedNodes, err := cache.GetParticipatingNodes(ctx, nodeIds, time.Hour, 0)
// 		require.NoError(t, err)
// 		require.Len(t, selectedNodes, len(nodeIds))

// 		// disqualified/exited/unknown nodes should be returned as a zero-value SelectedNode in results
// 		require.Zero(t, selectedNodes[1].ID) // #2 is disqualified
// 		require.False(t, selectedNodes[1].Online)
// 		require.Zero(t, selectedNodes[4].ID) // #5 gracefully exited
// 		require.False(t, selectedNodes[4].Online)
// 		require.Zero(t, selectedNodes[8].ID) // #9 is not in db
// 		require.False(t, selectedNodes[8].Online)

// 		require.Equal(t, nodeIds[0], selectedNodes[0].ID) // #1 is online
// 		require.True(t, selectedNodes[0].Online)
// 		require.Equal(t, "DE", selectedNodes[0].CountryCode.String())
// 		require.Equal(t, nodeIds[2], selectedNodes[2].ID) // #3 is unknown-audit-suspended
// 		require.True(t, selectedNodes[2].Online)
// 		require.Equal(t, "DE", selectedNodes[2].CountryCode.String())
// 		require.Equal(t, nodeIds[3], selectedNodes[3].ID) // #4 is offline
// 		require.False(t, selectedNodes[3].Online)
// 		require.Equal(t, "DE", selectedNodes[3].CountryCode.String())
// 		require.Equal(t, nodeIds[5], selectedNodes[5].ID) // #6 is offline-suspended
// 		require.True(t, selectedNodes[5].Online)
// 		require.Equal(t, "DE", selectedNodes[5].CountryCode.String())
// 		require.Equal(t, nodeIds[6], selectedNodes[6].ID) // #7 is in an excluded country
// 		require.True(t, selectedNodes[6].Online)
// 		require.Equal(t, "FR", selectedNodes[6].CountryCode.String())
// 		require.Equal(t, nodeIds[7], selectedNodes[7].ID) // #8 is online but has no country code
// 		require.True(t, selectedNodes[7].Online)
// 		require.Equal(t, "", selectedNodes[7].CountryCode.String())
// 	})

// 	t.Run("GetAllParticipatingNodes", func(t *testing.T) {
// 		allNodes, err := cache.GetAllParticipatingNodes(ctx, time.Hour, 0)
// 		require.NoError(t, err)

// 		expectOnline := func(t *testing.T, nodeList []nodeselection.SelectedNode, nodeID storxnetwork.NodeID, shouldBeOnline bool) {
// 			for _, n := range nodeList {
// 				if n.ID == nodeID {
// 					if n.Online != shouldBeOnline {
// 						require.Failf(t, "invalid Onlineness", "node %x was found in list, but Online=%v, whereas we expected Online=%v", n.ID[:], n.Online, shouldBeOnline)
// 					}
// 					return
// 				}
// 			}
// 			require.Fail(t, "node not found in list", "node ID %x not found in list. list: %v", nodeID[:], nodeList)
// 		}

// 		expectOnline(t, allNodes, storxnetwork.NodeID{1}, true)  // normal and online
// 		expectOnline(t, allNodes, storxnetwork.NodeID{3}, true)  // unknown audit suspended
// 		expectOnline(t, allNodes, storxnetwork.NodeID{4}, false) // offline
// 		expectOnline(t, allNodes, storxnetwork.NodeID{6}, true)  // offline suspended
// 		expectOnline(t, allNodes, storxnetwork.NodeID{7}, true)  // excluded country
// 		expectOnline(t, allNodes, storxnetwork.NodeID{8}, true)  // normal and online, no country code

// 		expectNotInList := func(t *testing.T, nodeList []nodeselection.SelectedNode, nodeID storxnetwork.NodeID) {
// 			for index, n := range nodeList {
// 				if n.ID == nodeID {
// 					require.Failf(t, "not found in list", "node %x should not have been found in list, but it was found at index [%d].", nodeID[:], index)
// 				}
// 			}
// 		}

// 		expectNotInList(t, allNodes, storxnetwork.NodeID{2}) // disqualified
// 		expectNotInList(t, allNodes, storxnetwork.NodeID{5}) // gracefully exited
// 		expectNotInList(t, allNodes, storxnetwork.NodeID{9}) // not in db

// 		require.Len(t, allNodes, 6)
// 	})

// 	t.Run("TestUpdateOperator", func(t *testing.T) {
// 		nodeID := storxnetwork.NodeID{10}
// 		addr := "127.0.1.0:8080"
// 		lastNet := "127.0.1"
// 		d := overlay.NodeCheckInInfo{
// 			NodeID:     nodeID,
// 			Address:    &pb.NodeAddress{Address: addr},
// 			LastIPPort: addr,
// 			LastNet:    lastNet,
// 			Version:    &pb.NodeVersion{Version: "v1.0.0"},
// 			Capacity:   &pb.NodeCapacity{},
// 		}
// 		err := cache.UpdateCheckIn(ctx, d, time.Now().UTC(), overlay.NodeSelectionConfig{})
// 		require.NoError(t, err)

// 		update, err := cache.UpdateNodeInfo(ctx, nodeID, &overlay.InfoResponse{
// 			Operator: &pb.NodeOperator{
// 				Wallet:         "0x1111111111111111111111111111111111111111",
// 				Email:          "abc123@mail.test",
// 				WalletFeatures: []string{"wallet_features"},
// 			},
// 		})
// 		require.NoError(t, err)
// 		require.NotNil(t, update)
// 		require.Equal(t, "0x1111111111111111111111111111111111111111", update.Operator.Wallet)
// 		require.Equal(t, "abc123@mail.test", update.Operator.Email)
// 		require.Equal(t, []string{"wallet_features"}, update.Operator.WalletFeatures)

// 		found, err := cache.Get(ctx, nodeID)
// 		require.NoError(t, err)
// 		require.NotNil(t, found)
// 		require.Equal(t, "0x1111111111111111111111111111111111111111", found.Operator.Wallet)
// 		require.Equal(t, "abc123@mail.test", found.Operator.Email)
// 		require.Equal(t, []string{"wallet_features"}, found.Operator.WalletFeatures)

// 		updateEmail, err := cache.UpdateNodeInfo(ctx, nodeID, &overlay.InfoResponse{
// 			Operator: &pb.NodeOperator{
// 				Wallet:         update.Operator.Wallet,
// 				Email:          "def456@mail.test",
// 				WalletFeatures: update.Operator.WalletFeatures,
// 			},
// 		})
// 		require.NoError(t, err)
// 		assert.NotNil(t, updateEmail)
// 		assert.Equal(t, "0x1111111111111111111111111111111111111111", updateEmail.Operator.Wallet)
// 		assert.Equal(t, "def456@mail.test", updateEmail.Operator.Email)
// 		assert.Equal(t, []string{"wallet_features"}, updateEmail.Operator.WalletFeatures)

// 		updateWallet, err := cache.UpdateNodeInfo(ctx, nodeID, &overlay.InfoResponse{
// 			Operator: &pb.NodeOperator{
// 				Wallet:         "0x2222222222222222222222222222222222222222",
// 				Email:          updateEmail.Operator.Email,
// 				WalletFeatures: update.Operator.WalletFeatures,
// 			},
// 		})
// 		require.NoError(t, err)
// 		assert.NotNil(t, updateWallet)
// 		assert.Equal(t, "0x2222222222222222222222222222222222222222", updateWallet.Operator.Wallet)
// 		assert.Equal(t, "def456@mail.test", updateWallet.Operator.Email)
// 		assert.Equal(t, []string{"wallet_features"}, updateWallet.Operator.WalletFeatures)

// 		updateWalletFeatures, err := cache.UpdateNodeInfo(ctx, nodeID, &overlay.InfoResponse{
// 			Operator: &pb.NodeOperator{
// 				Wallet:         updateWallet.Operator.Wallet,
// 				Email:          updateEmail.Operator.Email,
// 				WalletFeatures: []string{"wallet_features_updated"},
// 			},
// 		})
// 		require.NoError(t, err)
// 		assert.NotNil(t, updateWalletFeatures)
// 		assert.Equal(t, "0x2222222222222222222222222222222222222222", updateWalletFeatures.Operator.Wallet)
// 		assert.Equal(t, "def456@mail.test", updateWalletFeatures.Operator.Email)
// 		assert.Equal(t, []string{"wallet_features_updated"}, updateWalletFeatures.Operator.WalletFeatures)
// 	})

// 	// test UpdateCheckIn updates the reputation correctly when the node is offline/online
// 	t.Run("UpdateCheckIn", func(t *testing.T) {
// 		nodeID := storxnetwork.NodeID{1}

// 		// get the existing node info that is stored in nodes table
// 		_, err := cache.Get(ctx, nodeID)
// 		require.NoError(t, err)

// 		info := overlay.NodeCheckInInfo{
// 			NodeID: nodeID,
// 			Address: &pb.NodeAddress{
// 				Address: "1.2.3.4",
// 			},
// 			IsUp: false,
// 			Version: &pb.NodeVersion{
// 				Version:    "v0.0.0",
// 				CommitHash: "",
// 				Timestamp:  time.Time{},
// 				Release:    false,
// 			},
// 		}
// 		// update check-in when node is offline
// 		err = cache.UpdateCheckIn(ctx, info, time.Now(), overlay.NodeSelectionConfig{})
// 		require.NoError(t, err)
// 		_, err = cache.Get(ctx, nodeID)
// 		require.NoError(t, err)

// 		info.IsUp = true
// 		// update check-in when node is online
// 		err = cache.UpdateCheckIn(ctx, info, time.Now(), overlay.NodeSelectionConfig{})
// 		require.NoError(t, err)
// 		_, err = cache.Get(ctx, nodeID)
// 		require.NoError(t, err)
// 	})
// }
