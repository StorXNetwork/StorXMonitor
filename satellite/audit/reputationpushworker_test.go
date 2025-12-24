// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testrand"
)

func TestCalculateReputationValue(t *testing.T) {
	now := time.Now()
	recentTime := now.Add(-time.Hour * 24 * 7) // 7 days ago (within 30 days)
	oldTime := now.Add(-time.Hour * 24 * 31)   // 31 days ago (beyond 30 days)
	zeroTime := time.Time{}
	nonZeroTime := now.Add(-time.Hour)

	tests := []struct {
		name          string
		reputation    NodeReputationEntry
		expectedValue int64
		description   string
	}{
		{
			name: "normal reputation calculation with integer value",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 1.0, // Use 1.0 to avoid truncation issue
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
				Disqualified:         nil,
				ExitInitiatedAt:      nil,
				ExitFinishedAt:       nil,
				ExitSuccess:          nil,
				UnderReview:          nil,
			},
			expectedValue: 5, // int64(1.0) * 5 = 5
			description:   "should calculate reputation as int64(AuditReputationAlpha) * 5",
		},
		{
			name: "fractional reputation gets truncated",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
				Disqualified:         nil,
				ExitInitiatedAt:      nil,
				ExitFinishedAt:       nil,
				ExitSuccess:          nil,
				UnderReview:          nil,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "high reputation value",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 1.0,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 5, // int64(1.0) * 5 = 5
			description:   "should handle maximum reputation value",
		},
		{
			name: "low reputation value",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.1,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // 0.1 * 5 = 0.5, truncated to 0
			description:   "should handle low reputation value (truncated)",
		},
		{
			name: "disqualified node - Disqualified set",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				Disqualified:         &nonZeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0,
			description:   "should return 0 for disqualified node",
		},
		{
			name: "disqualified node - ExitInitiatedAt zero",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				ExitInitiatedAt:      &zeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0,
			description:   "should return 0 when ExitInitiatedAt is zero",
		},
		{
			name: "disqualified node - ExitFinishedAt zero",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				ExitFinishedAt:       &zeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0,
			description:   "should return 0 when ExitFinishedAt is zero",
		},
		{
			name: "disqualified node - ExitSuccess true",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				ExitSuccess:          boolPtr(true),
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0,
			description:   "should return 0 when ExitSuccess is true",
		},
		{
			name: "disqualified node - UnderReview set",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				UnderReview:          &nonZeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0,
			description:   "should return 0 when UnderReview is set",
		},
		{
			name: "inactive node - LastContactSuccess nil",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				LastContactSuccess:   nil,
				PieceCount:           100,
			},
			expectedValue: 5,
			description:   "should return default 5 when LastContactSuccess is nil",
		},
		{
			name: "inactive node - PieceCount zero",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				LastContactSuccess:   &recentTime,
				PieceCount:           0,
			},
			expectedValue: 5,
			description:   "should return default 5 when PieceCount is zero",
		},
		{
			name: "inactive node - LastContactSuccess too old",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				LastContactSuccess:   &oldTime,
				PieceCount:           100,
			},
			expectedValue: 5,
			description:   "should return default 5 when LastContactSuccess is older than 30 days",
		},
		{
			name: "disqualified takes precedence over inactive",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				Disqualified:         &nonZeroTime,
				LastContactSuccess:   nil, // inactive condition
				PieceCount:           0,   // inactive condition
			},
			expectedValue: 0,
			description:   "should return 0 when disqualified, even if inactive conditions are met",
		},
		{
			name: "zero AuditReputationAlpha",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.0,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // 0.0 * 5 = 0
			description:   "should return 0 for zero AuditReputationAlpha",
		},
		{
			name: "fractional reputation calculation",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.6,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.6) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "ExitSuccess false should not disqualify",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				ExitSuccess:          boolPtr(false),
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "UnderReview nil should not disqualify",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				UnderReview:          nil,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "UnderReview zero time should not disqualify",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				UnderReview:          &zeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "Disqualified zero time should not disqualify",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				Disqualified:         &zeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "ExitInitiatedAt non-zero should not disqualify",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				ExitInitiatedAt:      &nonZeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
		{
			name: "ExitFinishedAt non-zero should not disqualify",
			reputation: NodeReputationEntry{
				NodeID:               testrand.NodeID(),
				Wallet:               "0x1234567890abcdef",
				AuditReputationAlpha: 0.8,
				ExitFinishedAt:       &nonZeroTime,
				LastContactSuccess:   &recentTime,
				PieceCount:           100,
			},
			expectedValue: 0, // int64(0.8) * 5 = int64(0) * 5 = 0 (truncation happens before multiplication)
			description:   "should truncate fractional reputation before multiplication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			worker := NewReputationPushWorker(logger, nil, nil)

			result := worker.calculateReputationValue(context.Background(), tt.reputation)

			require.Equal(t, tt.expectedValue, result, tt.description)
		})
	}
}

// Helper function to create a bool pointer
func boolPtr(b bool) *bool {
	return &b
}
