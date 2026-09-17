// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

import (
	"fmt"
	"time"
)

// ApplyCoupon discounts a plan price using billing coupon rules.
// discountType is "percentage" or "fixed".
func ApplyCoupon(price, discount, maxDiscount, minOrderAmount float64, discountType string, validFrom, validTo, now time.Time) (newPrice float64, err error) {
	if now.Before(validFrom) || now.After(validTo) {
		return price, Error.New("coupon is not valid")
	}
	if price < minOrderAmount {
		return price, Error.New("order amount below coupon minimum")
	}

	var discountAmount float64
	switch discountType {
	case "percentage":
		discountAmount = price * (discount / 100)
	case "fixed":
		discountAmount = discount
	default:
		return price, Error.New("unsupported discount type: %s", discountType)
	}
	if maxDiscount > 0 && discountAmount > maxDiscount {
		discountAmount = maxDiscount
	}
	newPrice = price - discountAmount
	if newPrice < 0 {
		newPrice = 0
	}
	return newPrice, nil
}

// AmountToMinorUnits converts a major-unit price to integer minor units.
func AmountToMinorUnits(price float64) (int64, error) {
	if price < 0 {
		return 0, Error.New("price must be non-negative")
	}
	amount := int64(price*100 + 0.5)
	if amount <= 0 && price > 0 {
		return 0, Error.New("price too small for currency subunits")
	}
	return amount, nil
}

// FormatAmountMajor formats minor units as a major-unit decimal string.
func FormatAmountMajor(amountMinor int64) string {
	return fmt.Sprintf("%0.2f", float64(amountMinor)/100)
}
