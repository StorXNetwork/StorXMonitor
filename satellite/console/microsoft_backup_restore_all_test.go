// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import "testing"

func TestNormalizeMicrosoftBackupRestoreService_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{in: "mail", want: "outlook"},
		{in: "Outlook", want: "outlook"},
		{in: "calendar", want: "outlook_calendar"},
		{in: "contacts", want: "outlook_contacts"},
		{in: "onedrive", want: "outlook_onedrive"},
		{in: "sharepoint", want: "outlook_sharepoint"},
		{in: "teams", want: "outlook_teams"},
		{in: "groups", want: "outlook_groups"},
		{in: "outlook_calendar", want: "outlook_calendar"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := normalizeMicrosoftBackupRestoreService(tt.in); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestMicrosoftBackupRestoreAllRequest_Validate_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     MicrosoftBackupRestoreAllRequest
		wantErr bool
	}{
		{
			name: "valid outlook",
			req:  MicrosoftBackupRestoreAllRequest{Service: "mail", ProjectID: "p1", LoginID: "a@b.com"},
		},
		{
			name:    "missing project",
			req:     MicrosoftBackupRestoreAllRequest{Service: "outlook", ProjectID: "", LoginID: "a@b.com"},
			wantErr: true,
		},
		{
			name:    "unsupported service",
			req:     MicrosoftBackupRestoreAllRequest{Service: "gmail", ProjectID: "p1", LoginID: "a@b.com"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := (&tt.req).Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.wantErr && tt.req.Service != "outlook" && tt.name == "valid outlook" {
				t.Fatalf("service not normalized: %q", tt.req.Service)
			}
		})
	}
}
