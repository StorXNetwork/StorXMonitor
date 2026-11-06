// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import "testing"

func TestAccountDeleteReauthKind(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{name: "empty is google", provider: "", want: "google"},
		{name: "google explicit", provider: "google", want: "google"},
		{name: "microsoft", provider: "microsoft", want: "microsoft"},
		{name: "microsoft case and space", provider: " Microsoft ", want: "microsoft"},
		{name: "unknown stays google", provider: "apple", want: "google"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accountDeleteReauthKind(tt.provider); got != tt.want {
				t.Fatalf("accountDeleteReauthKind(%q) = %q, want %q", tt.provider, got, tt.want)
			}
		})
	}
}
