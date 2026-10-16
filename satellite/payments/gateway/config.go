// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package gateway

// Config holds checkout gateway orchestration settings.
type Config struct {
	DefaultProvider  string `help:"default payment provider name" default:"razorpay"`
	EnabledProviders string `help:"comma-separated enabled payment provider names" default:"razorpay"`
}
