// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

func TestParseProjectMemberRoleQuery(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    console.ProjectMemberRole
		wantErr bool
	}{
		{name: "admin word", input: "admin", want: console.RoleAdmin},
		{name: "ADMIN upper", input: "ADMIN", want: console.RoleAdmin},
		{name: "admin zero", input: "0", want: console.RoleAdmin},
		{name: "member word", input: "member", want: console.RoleMember},
		{name: "member one", input: "1", want: console.RoleMember},
		{name: "invalid", input: "owner", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProjectMemberRoleQuery(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
