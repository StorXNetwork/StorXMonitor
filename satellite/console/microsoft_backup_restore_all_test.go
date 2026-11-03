// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"encoding/json"
	"testing"
)

func TestNormalizeMicrosoftBackupRestoreService_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{in: "mail", want: "outlook"},
		{in: "Outlook", want: "outlook"},
		{in: "gmail", want: "outlook"},
		{in: "calendar", want: "outlook_calendar"},
		{in: "contacts", want: "outlook_contacts"},
		{in: "onedrive", want: "outlook_onedrive"},
		{in: "sharepoint", want: "outlook_sharepoint"},
		{in: "teams", want: "outlook_teams"},
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
			req:     MicrosoftBackupRestoreAllRequest{Service: "photos", ProjectID: "p1", LoginID: "a@b.com"},
			wantErr: true,
		},
		{
			name: "gmail tab alias maps to outlook",
			req:  MicrosoftBackupRestoreAllRequest{Service: "gmail", ProjectID: "p1", LoginID: "a@b.com"},
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

func TestMicrosoftBackupRestoreAllRequest_backupToolsPayload_keys_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		req      MicrosoftBackupRestoreAllRequest
		wantKeys []string
		wantLen  int
	}{
		{
			name: "no keys omits field",
			req: MicrosoftBackupRestoreAllRequest{
				Service: "outlook", ProjectID: "p1", LoginID: "a@b.com",
			},
			wantLen: 0,
		},
		{
			name: "selected keys forwarded and deduped",
			req: MicrosoftBackupRestoreAllRequest{
				Service: "outlook", ProjectID: "p1", LoginID: "a@b.com",
				Keys: []string{
					" a@b.com/outlook/inbox/1.eml ",
					"a@b.com/outlook/inbox/1.eml",
					"a@b.com/outlook/inbox/2.eml",
					"",
				},
			},
			wantKeys: []string{
				"a@b.com/outlook/inbox/1.eml",
				"a@b.com/outlook/inbox/2.eml",
			},
			wantLen: 2,
		},
		{
			name: "tenant_id and target kept with keys",
			req: MicrosoftBackupRestoreAllRequest{
				Service: "outlook", ProjectID: "p1", LoginID: "a@b.com",
				TargetEmail: "dest@b.com", TenantID: "TENANT-1",
				Keys: []string{"a@b.com/outlook/inbox/1.eml"},
			},
			wantKeys: []string{"a@b.com/outlook/inbox/1.eml"},
			wantLen:  1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, err := (&tt.req).backupToolsPayload()
			if err != nil {
				t.Fatalf("payload: %v", err)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if out["service"] != "outlook" || out["project_id"] != "p1" || out["login_id"] != "a@b.com" {
				t.Fatalf("base fields wrong: %#v", out)
			}
			rawKeys, ok := out["keys"]
			if tt.wantLen == 0 {
				if ok {
					t.Fatalf("expected keys omitted, got %#v", rawKeys)
				}
				return
			}
			if !ok {
				t.Fatal("expected keys in payload")
			}
			arr, ok := rawKeys.([]interface{})
			if !ok {
				t.Fatalf("keys type: %T", rawKeys)
			}
			if len(arr) != tt.wantLen {
				t.Fatalf("keys len %d want %d", len(arr), tt.wantLen)
			}
			for i, want := range tt.wantKeys {
				got, _ := arr[i].(string)
				if got != want {
					t.Fatalf("keys[%d]=%q want %q", i, got, want)
				}
			}
			if tt.req.TargetEmail != "" && out["target_email"] != tt.req.TargetEmail {
				t.Fatalf("target_email=%v", out["target_email"])
			}
			if tt.req.TenantID != "" {
				if out["tenant_id"] != "tenant-1" {
					t.Fatalf("tenant_id=%v", out["tenant_id"])
				}
			}
		})
	}
}
