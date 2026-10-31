// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMicrosoftAccountTypeFromDetection(t *testing.T) {
	tests := []struct {
		name     string
		detected string
		existing string
		want     string
	}{
		{name: "detection never promotes to admin_workspace", detected: MicrosoftAccountTypeAdminWorkspace, existing: "", want: MicrosoftAccountTypeWorkAccount},
		{name: "detection never demotes admin_workspace", detected: MicrosoftAccountTypeWorkAccount, existing: MicrosoftAccountTypeAdminWorkspace, want: MicrosoftAccountTypeAdminWorkspace},
		{name: "work account stays work account", detected: MicrosoftAccountTypeWorkAccount, existing: MicrosoftAccountTypeWorkAccount, want: MicrosoftAccountTypeWorkAccount},
		{name: "legacy detection becomes work account", detected: "employee_workspace", existing: "", want: MicrosoftAccountTypeWorkAccount},
		{name: "legacy stored value becomes work account", detected: "", existing: "employee_workspace", want: MicrosoftAccountTypeWorkAccount},
		{name: "personal", detected: MicrosoftAccountTypePersonal, existing: "", want: MicrosoftAccountTypePersonal},
		{name: "empty detection keeps existing", detected: "", existing: MicrosoftAccountTypeAdminWorkspace, want: MicrosoftAccountTypeAdminWorkspace},
		{name: "unknown stays unknown", detected: "", existing: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, microsoftAccountTypeFromDetection(tt.detected, tt.existing))
		})
	}
}
