// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"strings"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

// registrationFullName returns a full name CreateUser will accept.
// Microsoft display names are often one word, contain digits, or fall back to an email.
// CreateUser requires 2 to 6 words of letters.
func registrationFullName(displayName, email string) string {
	if name := personNameWords(displayName); console.Regex_NameValidation.MatchString(name) {
		return name
	}

	local := email
	if at := strings.IndexByte(email, '@'); at > 0 {
		local = email[:at]
	}
	local = strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(local)
	if name := personNameWords(local); console.Regex_NameValidation.MatchString(name) {
		return name
	}
	if name := personNameWords(local); name != "" {
		candidate := name + " User"
		if console.Regex_NameValidation.MatchString(candidate) {
			return candidate
		}
	}
	return "Invited User"
}

func personNameWords(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == ',', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	fields := strings.Fields(b.String())
	if len(fields) > 6 {
		fields = fields[:6]
	}
	return strings.Join(fields, " ")
}
