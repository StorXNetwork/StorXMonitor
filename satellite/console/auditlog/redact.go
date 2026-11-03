// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package auditlog

import (
	"regexp"
	"strings"
)

// storxBrand matches the product name as a word. It does not match field names such as storx_token.
var storxBrand = regexp.MustCompile(`(?i)\bstorx\b\s*`)

// RedactBrand removes the StorX product name from text shown in audit logs and API bodies.
func RedactBrand(s string) string {
	cleaned := storxBrand.ReplaceAllString(s, "")
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	return strings.TrimSpace(cleaned)
}
