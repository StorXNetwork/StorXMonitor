// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestApplyCouponPercentage(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	price, err := ApplyCoupon(100, 10, 50, 0, "percentage", now.Add(-time.Hour), now.Add(time.Hour), now)
	require.NoError(t, err)
	require.Equal(t, 90.0, price)
}

func TestApplyCouponFixedMax(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	price, err := ApplyCoupon(100, 80, 50, 0, "fixed", now.Add(-time.Hour), now.Add(time.Hour), now)
	require.NoError(t, err)
	require.Equal(t, 50.0, price)
}

func TestApplyCouponExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err := ApplyCoupon(100, 10, 50, 0, "percentage", now.Add(-2*time.Hour), now.Add(-time.Hour), now)
	require.Error(t, err)
}

func TestAmountToMinorUnits(t *testing.T) {
	amount, err := AmountToMinorUnits(10.5)
	require.NoError(t, err)
	require.Equal(t, int64(1050), amount)
	require.Equal(t, "10.50", FormatAmountMajor(1050))
}
