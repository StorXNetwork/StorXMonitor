// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package auditlog

import "testing"

func TestRedactBrand(t *testing.T) {
	got := RedactBrand("storx access grant not found: no backup job for support@salestalker.com")
	want := "access grant not found: no backup job for support@salestalker.com"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	got = RedactBrand(`{"error":"StorX access grant not found"}`)
	want = `{"error":"access grant not found"}`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	got = RedactBrand(`{"storx_token":"keep-key"}`)
	want = `{"storx_token":"keep-key"}`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
