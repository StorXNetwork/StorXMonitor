package console_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestInviteeOwnerAuditMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		base  string
		email string
		want  string
	}{
		{name: "restore with invitee", base: "Restore initiated", email: "employee@company.com", want: "Restore initiated by invited user employee@company.com"},
		{name: "download with invitee", base: "Manual restore completed", email: "a@x.com", want: "Manual restore completed by invited user a@x.com"},
		{name: "empty email keeps base", base: "Restore job cancelled", email: "  ", want: "Restore job cancelled"},
		{name: "empty base", base: " ", email: "a@x.com", want: "Invited user operation by invited user a@x.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, console.InviteeOwnerAuditMessage(tt.base, tt.email))
		})
	}
}
