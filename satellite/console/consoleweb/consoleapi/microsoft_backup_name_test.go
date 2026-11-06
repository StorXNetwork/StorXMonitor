// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"testing"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestRegistrationFullName(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		email       string
		want        string
	}{
		{
			name:        "two word display name is kept",
			displayName: "Sagar Prajapati",
			email:       "sagar@outlook.com",
			want:        "Sagar Prajapati",
		},
		{
			name:        "one word display name is kept",
			displayName: "Sagar",
			email:       "sagar.prajapati@outlook.com",
			want:        "Sagar",
		},
		{
			name:        "digits in the display name are removed",
			displayName: "Sagar1812",
			email:       "sagarprks1812@outlook.com",
			want:        "Sagar",
		},
		{
			name:        "email used as the display name is cleaned",
			displayName: "sagarprks1812@outlook.com",
			email:       "sagarprks1812@outlook.com",
			want:        "sagarprks outlook.com",
		},
		{
			name:        "empty name and email falls back",
			displayName: "",
			email:       "",
			want:        "Invited User",
		},
		{
			name:        "apostrophe is dropped so both words remain",
			displayName: "John O'Brien",
			email:       "john@outlook.com",
			want:        "John O Brien",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := registrationFullName(tt.displayName, tt.email)
			if got != tt.want {
				t.Fatalf("registrationFullName(%q, %q) = %q, want %q", tt.displayName, tt.email, got, tt.want)
			}
			if !console.Regex_NameValidation.MatchString(got) {
				t.Fatalf("registrationFullName(%q, %q) = %q, which CreateUser would reject", tt.displayName, tt.email, got)
			}
		})
	}
}
