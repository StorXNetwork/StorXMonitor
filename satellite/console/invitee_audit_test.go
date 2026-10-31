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
		{name: "vault download", base: "Download completed", email: "a@x.com", want: "Download completed by invited user a@x.com"},
		{name: "empty email keeps base", base: "Restore job cancelled", email: "  ", want: "Restore job cancelled"},
		{name: "empty base", base: " ", email: "a@x.com", want: "Invited user operation by invited user a@x.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, console.InviteeOwnerAuditMessage(tt.base, tt.email))
		})
	}
}

func TestInvitationDeclineAuditMessage(t *testing.T) {
	t.Parallel()

	require.Equal(t, "Invitation to My Project declined", console.InvitationDeclineAuditMessage("My Project", "invitee@example.com", false))
	require.Equal(t, "Invitation to My Project declined by invited user invitee@example.com", console.InvitationDeclineAuditMessage(" My Project ", "invitee@example.com", true))
	require.Equal(t, "Invitation to the project declined", console.InvitationDeclineAuditMessage("  ", "", false))
	require.Equal(t, "Invitation to My Project accepted", console.InvitationAcceptAuditMessage("My Project", "invitee@example.com", false))
	require.Equal(t, "Invitation to My Project accepted by invited user invitee@example.com", console.InvitationAcceptAuditMessage("My Project", "invitee@example.com", true))
	require.Equal(t, "Left the invitation to My Project", console.InvitationLeaveAuditMessage("My Project", "invitee@example.com", false))
	require.Equal(t, "Invited user invitee@example.com left the invitation to My Project", console.InvitationLeaveAuditMessage("My Project", "invitee@example.com", true))
}
