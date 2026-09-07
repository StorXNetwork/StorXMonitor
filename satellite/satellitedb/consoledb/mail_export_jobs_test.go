// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

func TestMailExportJobFromDBX(t *testing.T) {
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	started := now.Add(time.Minute)
	prefix := "inbox/"
	grant := "1accessgrant"
	chargeID := "charge-1"
	chargedBytes := int64(12345)
	keysJSON := []byte(`["a.gmail","b.gmail"]`)

	tests := []struct {
		name string
		row  *dbx.MailExportJob
		want *console.MailExportJob
	}{
		{
			name: "nil row",
			row:  nil,
			want: nil,
		},
		{
			name: "selected mode with keys_json",
			row: &dbx.MailExportJob{
				Id:                       "job-1",
				UserId:                   "user-1",
				ProjectId:                "proj-1",
				AccessKeyId:              "AKIA",
				Bucket:                   "gmail",
				Format:                   "pst",
				Mode:                     "selected",
				Prefix:                   &prefix,
				KeysJson:                 keysJSON,
				AccessGrant:              &grant,
				Status:                   console.MailExportStatusQueued,
				RetryCount:               1,
				Progress:                 10,
				ProcessedFiles:           2,
				TotalFiles:               2,
				ProcessedBytes:           100,
				TotalBytes:               200,
				LastDownloadChargeId:     &chargeID,
				LastDownloadChargedBytes: &chargedBytes,
				CreatedAt:                now,
				StartedAt:                &started,
			},
			want: &console.MailExportJob{
				ID:                       "job-1",
				UserID:                   "user-1",
				ProjectID:                "proj-1",
				AccessKeyID:              "AKIA",
				Bucket:                   "gmail",
				Format:                   "pst",
				Mode:                     "selected",
				Prefix:                   "inbox/",
				Keys:                     []string{"a.gmail", "b.gmail"},
				KeysJSON:                 json.RawMessage(keysJSON),
				AccessGrant:              "1accessgrant",
				Status:                   console.MailExportStatusQueued,
				RetryCount:               1,
				Progress:                 10,
				ProcessedFiles:           2,
				TotalFiles:               2,
				ProcessedBytes:           100,
				TotalBytes:               200,
				LastDownloadChargeID:     "charge-1",
				LastDownloadChargedBytes: &chargedBytes,
				CreatedAt:                now,
				StartedAt:                &started,
			},
		},
		{
			name: "mode all without keys",
			row: &dbx.MailExportJob{
				Id:        "job-2",
				UserId:    "user-2",
				ProjectId: "proj-2",
				Bucket:    "gmail",
				Format:    "json",
				Mode:      "all",
				Prefix:    &prefix,
				Status:    console.MailExportStatusProcessing,
				CreatedAt: now,
			},
			want: &console.MailExportJob{
				ID:        "job-2",
				UserID:    "user-2",
				ProjectID: "proj-2",
				Bucket:    "gmail",
				Format:    "json",
				Mode:      "all",
				Prefix:    "inbox/",
				Status:    console.MailExportStatusProcessing,
				CreatedAt: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mailExportJobFromDBX(tt.row)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeMailExportKeys(t *testing.T) {
	tests := []struct {
		name string
		job  *console.MailExportJob
		want []string
	}{
		{
			name: "nil job",
			job:  nil,
			want: nil,
		},
		{
			name: "keeps existing keys",
			job: &console.MailExportJob{
				Keys:     []string{"already"},
				KeysJSON: json.RawMessage(`["a","b"]`),
			},
			want: []string{"already"},
		},
		{
			name: "parses keys_json",
			job: &console.MailExportJob{
				KeysJSON: json.RawMessage(`["a","b"]`),
			},
			want: []string{"a", "b"},
		},
		{
			name: "invalid keys_json left empty",
			job: &console.MailExportJob{
				KeysJSON: json.RawMessage(`{`),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizeMailExportKeys(tt.job)
			if tt.job == nil {
				return
			}
			require.Equal(t, tt.want, tt.job.Keys)
		})
	}
}
