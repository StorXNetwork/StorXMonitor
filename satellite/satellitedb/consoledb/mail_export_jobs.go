// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoledb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/StorXMonitor/shared/dbutil"
	"github.com/StorXNetwork/StorXMonitor/shared/tagsql"
)

var _ console.MailExportJobs = (*mailExportJobs)(nil)

var errMailExportJobs = errs.Class("mail export jobs")

const mailExportJobReturningCols = `id, user_id, project_id, access_key_id, bucket, format, mode, prefix, keys_json,
				access_grant, status, retry_count, progress, processed_files, total_files,
				processed_bytes, total_bytes, current_object, archive_bucket, archive_key,
				archive_name, error_message, last_download_charge_id, last_download_charged_bytes,
				created_at, started_at, completed_at, expires_at`

type mailExportJobs struct {
	db   *dbx.DB
	impl dbutil.Implementation
}

// MailExportJobs is a getter for mail export jobs repository.
func (db *ConsoleDB) MailExportJobs() console.MailExportJobs {
	return &mailExportJobs{db: db.DB, impl: db.Impl}
}

func (m *mailExportJobs) Create(ctx context.Context, job console.CreateMailExportJob) (_ *console.MailExportJob, err error) {
	defer mon.Task()(&ctx)(&err)

	optional := dbx.MailExportJob_Create_Fields{}
	if job.Prefix != "" {
		optional.Prefix = dbx.MailExportJob_Prefix(job.Prefix)
	}
	if len(job.Keys) > 0 {
		keysJSON, marshalErr := json.Marshal(job.Keys)
		if marshalErr != nil {
			return nil, errMailExportJobs.Wrap(marshalErr)
		}
		optional.KeysJson = dbx.MailExportJob_KeysJson(keysJSON)
	}
	if job.AccessGrant != "" {
		optional.AccessGrant = dbx.MailExportJob_AccessGrant(job.AccessGrant)
	}

	row, err := m.db.Create_MailExportJob(ctx,
		dbx.MailExportJob_Id(job.ID),
		dbx.MailExportJob_UserId(job.UserID),
		dbx.MailExportJob_ProjectId(job.ProjectID),
		dbx.MailExportJob_AccessKeyId(job.AccessKeyID),
		dbx.MailExportJob_Bucket(job.Bucket),
		dbx.MailExportJob_Format(job.Format),
		dbx.MailExportJob_Mode(job.Mode),
		dbx.MailExportJob_Status(console.MailExportStatusQueued),
		dbx.MailExportJob_RetryCount(0),
		dbx.MailExportJob_Progress(0),
		dbx.MailExportJob_ProcessedFiles(0),
		dbx.MailExportJob_TotalFiles(job.TotalFiles),
		dbx.MailExportJob_ProcessedBytes(0),
		dbx.MailExportJob_TotalBytes(job.TotalBytes),
		optional,
	)
	if err != nil {
		return nil, errMailExportJobs.Wrap(err)
	}
	return mailExportJobFromDBX(row), nil
}

func (m *mailExportJobs) Get(ctx context.Context, id string) (_ *console.MailExportJob, err error) {
	defer mon.Task()(&ctx)(&err)

	row, err := m.db.Get_MailExportJob_By_Id(ctx, dbx.MailExportJob_Id(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrMailExportJobNotFound.Wrap(err)
		}
		return nil, errMailExportJobs.Wrap(err)
	}
	return mailExportJobFromDBX(row), nil
}

func (m *mailExportJobs) Claim(ctx context.Context) (_ *console.MailExportJob, err error) {
	defer mon.Task()(&ctx)(&err)

	var rows tagsql.Rows
	switch m.impl {
	case dbutil.Postgres:
		rows, err = m.db.QueryContext(ctx, `
			UPDATE mail_export_jobs SET status = $1, started_at = now()
			WHERE id IN (
				SELECT id FROM mail_export_jobs
				WHERE status = $2
				ORDER BY created_at ASC
				FOR UPDATE SKIP LOCKED
				LIMIT 1
			)
			RETURNING `+mailExportJobReturningCols+`
		`, console.MailExportStatusProcessing, console.MailExportStatusQueued)
	case dbutil.Cockroach:
		rows, err = m.db.QueryContext(ctx, `
			UPDATE mail_export_jobs SET status = $1, started_at = now()
			WHERE status = $2
			ORDER BY created_at ASC
			LIMIT 1
			RETURNING `+mailExportJobReturningCols+`
		`, console.MailExportStatusProcessing, console.MailExportStatusQueued)
	case dbutil.Spanner:
		rows, err = m.db.QueryContext(ctx, `
			UPDATE mail_export_jobs
			SET status = ?, started_at = CURRENT_TIMESTAMP()
			WHERE id IN (
				SELECT id FROM (
					SELECT id FROM mail_export_jobs
					WHERE status = ?
					ORDER BY created_at ASC
					LIMIT 1
				)
			)
			THEN RETURN `+mailExportJobReturningCols+`
		`, console.MailExportStatusProcessing, console.MailExportStatusQueued)
	default:
		return nil, errMailExportJobs.New("unhandled database: %v", m.impl)
	}
	if err != nil {
		return nil, errMailExportJobs.Wrap(err)
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, errMailExportJobs.Wrap(err)
		}
		return nil, console.ErrMailExportJobNotFound.New("no queued jobs")
	}
	job, err := scanMailExportJob(rows)
	if err != nil {
		return nil, err
	}
	return job, errMailExportJobs.Wrap(rows.Err())
}

func (m *mailExportJobs) Patch(ctx context.Context, id string, patch console.PatchMailExportJob) (_ *console.MailExportJob, err error) {
	defer mon.Task()(&ctx)(&err)

	update := dbx.MailExportJob_Update_Fields{}
	if patch.Status != nil {
		update.Status = dbx.MailExportJob_Status(*patch.Status)
	}
	if patch.RetryCount != nil {
		update.RetryCount = dbx.MailExportJob_RetryCount(*patch.RetryCount)
	}
	if patch.Progress != nil {
		update.Progress = dbx.MailExportJob_Progress(*patch.Progress)
	}
	if patch.ProcessedFiles != nil {
		update.ProcessedFiles = dbx.MailExportJob_ProcessedFiles(*patch.ProcessedFiles)
	}
	if patch.TotalFiles != nil {
		update.TotalFiles = dbx.MailExportJob_TotalFiles(*patch.TotalFiles)
	}
	if patch.ProcessedBytes != nil {
		update.ProcessedBytes = dbx.MailExportJob_ProcessedBytes(*patch.ProcessedBytes)
	}
	if patch.TotalBytes != nil {
		update.TotalBytes = dbx.MailExportJob_TotalBytes(*patch.TotalBytes)
	}
	if patch.CurrentObject != nil {
		update.CurrentObject = dbx.MailExportJob_CurrentObject(*patch.CurrentObject)
	}
	if patch.ArchiveBucket != nil {
		update.ArchiveBucket = dbx.MailExportJob_ArchiveBucket(*patch.ArchiveBucket)
	}
	if patch.ArchiveKey != nil {
		update.ArchiveKey = dbx.MailExportJob_ArchiveKey(*patch.ArchiveKey)
	}
	if patch.ArchiveName != nil {
		update.ArchiveName = dbx.MailExportJob_ArchiveName(*patch.ArchiveName)
	}
	if patch.ErrorMessage != nil {
		update.ErrorMessage = dbx.MailExportJob_ErrorMessage(*patch.ErrorMessage)
	}
	if patch.LastDownloadChargeID != nil {
		update.LastDownloadChargeId = dbx.MailExportJob_LastDownloadChargeId(*patch.LastDownloadChargeID)
	}
	if patch.LastDownloadChargedBytes != nil {
		update.LastDownloadChargedBytes = dbx.MailExportJob_LastDownloadChargedBytes(*patch.LastDownloadChargedBytes)
	}
	if patch.StartedAt != nil {
		update.StartedAt = dbx.MailExportJob_StartedAt(*patch.StartedAt)
	}
	if patch.CompletedAt != nil {
		update.CompletedAt = dbx.MailExportJob_CompletedAt(*patch.CompletedAt)
	}
	if patch.ExpiresAt != nil {
		update.ExpiresAt = dbx.MailExportJob_ExpiresAt(*patch.ExpiresAt)
	}

	row, err := m.db.Update_MailExportJob_By_Id(ctx, dbx.MailExportJob_Id(id), update)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, console.ErrMailExportJobNotFound.Wrap(err)
		}
		return nil, errMailExportJobs.Wrap(err)
	}
	if row == nil {
		return nil, console.ErrMailExportJobNotFound.New("%s", id)
	}
	return mailExportJobFromDBX(row), nil
}

func (m *mailExportJobs) Cancel(ctx context.Context, id string) (_ *console.MailExportJob, err error) {
	defer mon.Task()(&ctx)(&err)

	job, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if job.Status != console.MailExportStatusQueued && job.Status != console.MailExportStatusProcessing {
		return job, nil
	}
	now := time.Now().UTC()
	status := console.MailExportStatusCancelled
	return m.Patch(ctx, id, console.PatchMailExportJob{
		Status:      &status,
		CompletedAt: &now,
	})
}

func (m *mailExportJobs) Expire(ctx context.Context) (_ []console.MailExportJob, err error) {
	defer mon.Task()(&ctx)(&err)

	var rows tagsql.Rows
	switch m.impl {
	case dbutil.Postgres, dbutil.Cockroach:
		rows, err = m.db.QueryContext(ctx, `
			UPDATE mail_export_jobs SET status = $1
			WHERE status = $2 AND expires_at IS NOT NULL AND expires_at < now()
			RETURNING `+mailExportJobReturningCols+`
		`, console.MailExportStatusExpired, console.MailExportStatusSucceeded)
	case dbutil.Spanner:
		rows, err = m.db.QueryContext(ctx, `
			UPDATE mail_export_jobs SET status = ?
			WHERE status = ? AND expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP()
			THEN RETURN `+mailExportJobReturningCols+`
		`, console.MailExportStatusExpired, console.MailExportStatusSucceeded)
	default:
		return nil, errMailExportJobs.New("unhandled database: %v", m.impl)
	}
	if err != nil {
		return nil, errMailExportJobs.Wrap(err)
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	var jobs []console.MailExportJob
	for rows.Next() {
		job, scanErr := scanMailExportJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		jobs = append(jobs, *job)
	}
	return jobs, errMailExportJobs.Wrap(rows.Err())
}

func (m *mailExportJobs) RequeueStale(ctx context.Context, olderThan time.Duration) (count int, err error) {
	defer mon.Task()(&ctx)(&err)

	cutoff := time.Now().UTC().Add(-olderThan)
	var result sql.Result
	switch m.impl {
	case dbutil.Postgres, dbutil.Cockroach:
		result, err = m.db.ExecContext(ctx, `
			UPDATE mail_export_jobs
			SET status = $1, started_at = NULL
			WHERE status = $2 AND started_at IS NOT NULL AND started_at < $3
		`, console.MailExportStatusQueued, console.MailExportStatusProcessing, cutoff)
	case dbutil.Spanner:
		result, err = m.db.ExecContext(ctx, `
			UPDATE mail_export_jobs
			SET status = ?, started_at = NULL
			WHERE status = ? AND started_at IS NOT NULL AND started_at < ?
		`, console.MailExportStatusQueued, console.MailExportStatusProcessing, cutoff)
	default:
		return 0, errMailExportJobs.New("unhandled database: %v", m.impl)
	}
	if err != nil {
		return 0, errMailExportJobs.Wrap(err)
	}
	n, err := result.RowsAffected()
	return int(n), errMailExportJobs.Wrap(err)
}

func mailExportJobFromDBX(row *dbx.MailExportJob) *console.MailExportJob {
	if row == nil {
		return nil
	}
	job := &console.MailExportJob{
		ID:                       row.Id,
		UserID:                   row.UserId,
		ProjectID:                row.ProjectId,
		AccessKeyID:              row.AccessKeyId,
		Bucket:                   row.Bucket,
		Format:                   row.Format,
		Mode:                     row.Mode,
		Prefix:                   derefString(row.Prefix),
		KeysJSON:                 append(json.RawMessage(nil), row.KeysJson...),
		AccessGrant:              derefString(row.AccessGrant),
		Status:                   row.Status,
		RetryCount:               row.RetryCount,
		Progress:                 row.Progress,
		ProcessedFiles:           row.ProcessedFiles,
		TotalFiles:               row.TotalFiles,
		ProcessedBytes:           row.ProcessedBytes,
		TotalBytes:               row.TotalBytes,
		CurrentObject:            derefString(row.CurrentObject),
		ArchiveBucket:            derefString(row.ArchiveBucket),
		ArchiveKey:               derefString(row.ArchiveKey),
		ArchiveName:              derefString(row.ArchiveName),
		ErrorMessage:             derefString(row.ErrorMessage),
		LastDownloadChargeID:     derefString(row.LastDownloadChargeId),
		LastDownloadChargedBytes: row.LastDownloadChargedBytes,
		CreatedAt:                row.CreatedAt,
		StartedAt:                row.StartedAt,
		CompletedAt:              row.CompletedAt,
		ExpiresAt:                row.ExpiresAt,
	}
	normalizeMailExportKeys(job)
	return job
}

func scanMailExportJob(rows tagsql.Rows) (*console.MailExportJob, error) {
	var (
		row                dbx.MailExportJob
		prefix             sql.NullString
		accessGrant        sql.NullString
		currentObject      sql.NullString
		archiveBucket      sql.NullString
		archiveKey         sql.NullString
		archiveName        sql.NullString
		errorMessage       sql.NullString
		lastChargeID       sql.NullString
		lastChargedBytes   sql.NullInt64
		startedAt          sql.NullTime
		completedAt        sql.NullTime
		expiresAt          sql.NullTime
	)
	err := rows.Scan(
		&row.Id, &row.UserId, &row.ProjectId, &row.AccessKeyId, &row.Bucket, &row.Format, &row.Mode,
		&prefix, &row.KeysJson, &accessGrant, &row.Status, &row.RetryCount, &row.Progress,
		&row.ProcessedFiles, &row.TotalFiles, &row.ProcessedBytes, &row.TotalBytes,
		&currentObject, &archiveBucket, &archiveKey, &archiveName, &errorMessage,
		&lastChargeID, &lastChargedBytes,
		&row.CreatedAt, &startedAt, &completedAt, &expiresAt,
	)
	if err != nil {
		return nil, errMailExportJobs.Wrap(err)
	}
	if prefix.Valid {
		row.Prefix = &prefix.String
	}
	if accessGrant.Valid {
		row.AccessGrant = &accessGrant.String
	}
	if currentObject.Valid {
		row.CurrentObject = &currentObject.String
	}
	if archiveBucket.Valid {
		row.ArchiveBucket = &archiveBucket.String
	}
	if archiveKey.Valid {
		row.ArchiveKey = &archiveKey.String
	}
	if archiveName.Valid {
		row.ArchiveName = &archiveName.String
	}
	if errorMessage.Valid {
		row.ErrorMessage = &errorMessage.String
	}
	if lastChargeID.Valid {
		row.LastDownloadChargeId = &lastChargeID.String
	}
	if lastChargedBytes.Valid {
		v := lastChargedBytes.Int64
		row.LastDownloadChargedBytes = &v
	}
	if startedAt.Valid {
		t := startedAt.Time
		row.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		row.CompletedAt = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		row.ExpiresAt = &t
	}
	return mailExportJobFromDBX(&row), nil
}

func normalizeMailExportKeys(job *console.MailExportJob) {
	if job == nil || len(job.Keys) > 0 || len(job.KeysJSON) == 0 {
		return
	}
	var keys []string
	if err := json.Unmarshal(job.KeysJSON, &keys); err == nil {
		job.Keys = keys
	}
}
