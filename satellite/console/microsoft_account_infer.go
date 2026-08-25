// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"net/mail"
	"strings"
)

// InferMicrosoftAccountTypeFromEmail returns personal for known Microsoft consumer mail hosts.
func InferMicrosoftAccountTypeFromEmail(email string) string {
	if IsMicrosoftConsumerEmail(email) {
		return "personal"
	}
	return ""
}

// MicrosoftPersonalBackupDomainUsers is a minimal domain-users payload for consumer MSA accounts.
func MicrosoftPersonalBackupDomainUsers(email string) map[string]interface{} {
	return map[string]interface{}{
		"account_type": "personal",
		"email":        strings.TrimSpace(email),
	}
}

func IsMicrosoftConsumerEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	if addr, err := mail.ParseAddress(email); err == nil {
		email = addr.Address
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	switch strings.ToLower(email[at+1:]) {
	case "outlook.com", "hotmail.com", "live.com", "msn.com",
		"hotmail.co.uk", "outlook.co.uk", "live.co.uk":
		return true
	}
	return false
}
