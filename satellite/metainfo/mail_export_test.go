// Copyright (C) 2026 StorXNetwork Labs, Inc.
// See LICENSE for copying information.

package metainfo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUseInternalGetDownload(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cfg       MailExportConfig
		trusted   bool
		userAgent string
		want      bool
	}{
		{
			name:      "flag off",
			cfg:       MailExportConfig{NonBillableBuildDownloads: false, InternalDownloadUserAgent: "StorX-MailExport"},
			trusted:   true,
			userAgent: "StorX-MailExport uplink/1.0",
			want:      false,
		},
		{
			name:      "untrusted uplink",
			cfg:       MailExportConfig{NonBillableBuildDownloads: true, InternalDownloadUserAgent: "StorX-MailExport"},
			trusted:   false,
			userAgent: "StorX-MailExport uplink/1.0",
			want:      false,
		},
		{
			name:      "wrong user agent",
			cfg:       MailExportConfig{NonBillableBuildDownloads: true, InternalDownloadUserAgent: "StorX-MailExport"},
			trusted:   true,
			userAgent: "Gateway-MT/1.0 uplink/1.0",
			want:      false,
		},
		{
			name:      "flag on trusted mail-export agent",
			cfg:       MailExportConfig{NonBillableBuildDownloads: true, InternalDownloadUserAgent: "StorX-MailExport"},
			trusted:   true,
			userAgent: "StorX-MailExport uplink/1.0",
			want:      true,
		},
		{
			name:      "default product name when config empty",
			cfg:       MailExportConfig{NonBillableBuildDownloads: true},
			trusted:   true,
			userAgent: "StorX-MailExport",
			want:      true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := &Endpoint{config: Config{MailExport: tt.cfg}}
			got := endpoint.useInternalGetDownload(tt.trusted, []byte(tt.userAgent))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUserAgentHasProduct(t *testing.T) {
	for _, tt := range []struct {
		name      string
		userAgent string
		product   string
		want      bool
	}{
		{name: "empty", userAgent: "", product: "StorX-MailExport", want: false},
		{name: "exact product", userAgent: "StorX-MailExport", product: "StorX-MailExport", want: true},
		{name: "with uplink suffix", userAgent: "StorX-MailExport uplink/v1.13.4", product: "StorX-MailExport", want: true},
		{name: "gateway only", userAgent: "Gateway-MT/1.2.3", product: "StorX-MailExport", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, userAgentHasProduct([]byte(tt.userAgent), tt.product))
		})
	}
}
