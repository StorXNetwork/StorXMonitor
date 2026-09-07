// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChargeMailExportDownloadBandwidthValidation_table(t *testing.T) {
	svc := &Service{}
	ctx := context.Background()

	tests := []struct {
		name    string
		req     ChargeMailExportDownloadBandwidthRequest
		wantErr string
	}{
		{
			name:    "missing accessGrant",
			req:     ChargeMailExportDownloadBandwidthRequest{Bytes: 1, JobID: "j", ChargeID: "c"},
			wantErr: "accessGrant",
		},
		{
			name:    "missing jobId",
			req:     ChargeMailExportDownloadBandwidthRequest{AccessGrant: "g", Bytes: 1, ChargeID: "c"},
			wantErr: "jobId",
		},
		{
			name:    "missing chargeId",
			req:     ChargeMailExportDownloadBandwidthRequest{AccessGrant: "g", Bytes: 1, JobID: "j"},
			wantErr: "chargeId",
		},
		{
			name:    "bytes zero",
			req:     ChargeMailExportDownloadBandwidthRequest{AccessGrant: "g", Bytes: 0, JobID: "j", ChargeID: "c"},
			wantErr: "bytes",
		},
		{
			name:    "bytes negative",
			req:     ChargeMailExportDownloadBandwidthRequest{AccessGrant: "g", Bytes: -5, JobID: "j", ChargeID: "c"},
			wantErr: "bytes",
		},
		{
			name:    "orders DB not configured",
			req:     ChargeMailExportDownloadBandwidthRequest{AccessGrant: "g", Bytes: 1, JobID: "j", ChargeID: "c"},
			wantErr: "orders DB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ChargeMailExportDownloadBandwidth(ctx, tt.req)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
