// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"strings"
)

// Microsoft account types. Satellite never derives them locally: personal vs work/school comes from
// Backup-Tools account detection, and admin_workspace from the admin-consent / workspace status result.
const (
	// MicrosoftAccountTypePersonal is a personal Microsoft account (MSA).
	MicrosoftAccountTypePersonal = "personal"
	// MicrosoftAccountTypeWorkAccount is any work or school account, admins included, until
	// organization onboarding has app-only authorization and the list_users capability.
	// It says nothing about the user's role; see is_admin.
	MicrosoftAccountTypeWorkAccount = "work_account"
	// microsoftAccountTypeLegacyEmployeeWorkspace is the previous name of
	// MicrosoftAccountTypeWorkAccount, still present in stored credentials.
	microsoftAccountTypeLegacyEmployeeWorkspace = "employee_workspace"
	// MicrosoftAccountTypeAdminWorkspace is a work or school account whose tenant granted admin
	// consent with list_users. It is only a label and never authorizes anything by itself.
	MicrosoftAccountTypeAdminWorkspace = "admin_workspace"
)

// microsoftAccountTypeFromDetection merges a delegated detection result with the stored account type.
// Detection (sign-in, domain-users) can only classify personal vs work/school: it never promotes
// to admin_workspace and never demotes an existing admin_workspace. Only the admin-consent result
// and the Backup-Tools workspace status, which reflect app-only authorization, change that label.
func microsoftAccountTypeFromDetection(detected, existing string) string {
	detected = strings.TrimSpace(detected)
	existing = strings.TrimSpace(existing)
	if existing == microsoftAccountTypeLegacyEmployeeWorkspace {
		existing = MicrosoftAccountTypeWorkAccount
	}
	switch detected {
	case "":
		return existing
	case MicrosoftAccountTypePersonal:
		return MicrosoftAccountTypePersonal
	case MicrosoftAccountTypeWorkAccount, microsoftAccountTypeLegacyEmployeeWorkspace, MicrosoftAccountTypeAdminWorkspace:
		if existing == MicrosoftAccountTypeAdminWorkspace {
			return MicrosoftAccountTypeAdminWorkspace
		}
		return MicrosoftAccountTypeWorkAccount
	default:
		return detected
	}
}

// MicrosoftPersonalBackupDomainUsers is a minimal domain-users payload for personal MSA accounts.
func MicrosoftPersonalBackupDomainUsers(email string) map[string]interface{} {
	return map[string]interface{}{
		"account_type": MicrosoftAccountTypePersonal,
		"email":        strings.TrimSpace(email),
	}
}
