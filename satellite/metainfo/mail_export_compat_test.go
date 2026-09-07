// Copyright (C) 2026 StorXNetwork Labs, Inc.
// See LICENSE for copying information.

package metainfo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Compatibility / rollout matrix for mail-export non-billable build downloads.
// Deploy order: common proto → storagenode → satellite → GMT → enable flags.
func TestMailExportNonBillableCompatMatrix(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		satelliteNonBillableFlag bool
		gmtNonBillableFlag       bool
		trustedUplink            bool
		userAgent                string
		wantInternalGet          bool
		note                     string
	}{
		{
			name:                     "flag off identical to today",
			satelliteNonBillableFlag: false,
			gmtNonBillableFlag:       true,
			trustedUplink:            true,
			userAgent:                "StorX-MailExport",
			wantInternalGet:          false,
			note:                     "Satellite flag default false keeps billable GET",
		},
		{
			name:                     "old GMT + new Satellite",
			satelliteNonBillableFlag: true,
			gmtNonBillableFlag:       false,
			trustedUplink:            true,
			userAgent:                "Gateway-MT/1.0",
			wantInternalGet:          false,
			note:                     "Build still billable unless GMT uses StorX-MailExport UA",
		},
		{
			name:                     "new GMT + old Satellite (flag off)",
			satelliteNonBillableFlag: false,
			gmtNonBillableFlag:       true,
			trustedUplink:            true,
			userAgent:                "StorX-MailExport",
			wantInternalGet:          false,
			note:                     "Soft fallback to billable GET; no half-broken exempt",
		},
		{
			name:                     "new GMT + new Satellite enabled",
			satelliteNonBillableFlag: true,
			gmtNonBillableFlag:       true,
			trustedUplink:            true,
			userAgent:                "StorX-MailExport",
			wantInternalGet:          true,
			note:                     "Export build uses GET_INTERNAL",
		},
		{
			name:                     "downloadUrl path stays billable",
			satelliteNonBillableFlag: true,
			gmtNonBillableFlag:       true,
			trustedUplink:            true,
			userAgent:                "Gateway-MT/1.0",
			wantInternalGet:          false,
			note:                     "Presigned downloadUrl uses Gateway-MT agent → billable GET",
		},
		{
			name:                     "untrusted uplink cannot force internal",
			satelliteNonBillableFlag: true,
			gmtNonBillableFlag:       true,
			trustedUplink:            false,
			userAgent:                "StorX-MailExport",
			wantInternalGet:          false,
			note:                     "Client cannot choose GET_INTERNAL without trusted uplink",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// GMT flag only controls whether worker sets StorX-MailExport UA.
			ua := tt.userAgent
			if !tt.gmtNonBillableFlag && ua == "StorX-MailExport" {
				ua = "uplink/1.0"
			}
			endpoint := &Endpoint{config: Config{MailExport: MailExportConfig{
				NonBillableBuildDownloads: tt.satelliteNonBillableFlag,
				InternalDownloadUserAgent: "StorX-MailExport",
			}}}
			got := endpoint.useInternalGetDownload(tt.trustedUplink, []byte(ua))
			require.Equal(t, tt.wantInternalGet, got, tt.note)
		})
	}
}
