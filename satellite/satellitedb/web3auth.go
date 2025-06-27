package satellitedb

import (
	"context"
	"strings"
	"time"

	"storj.io/storj/satellite/backup"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/satellitedb/dbx"
)

var _ console.Web3Auth = (*web3Auth)(nil)

type web3Auth struct {
	db *satelliteDB
}

func (b *web3Auth) GetBackupShare(ctx context.Context, backupID string) (share []byte, err error) {
	rows, err := b.db.Get_Web3BackupShare_Share_By_BackupId(ctx, dbx.Web3BackupShare_BackupId([]byte(backupID)))
	if err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, nil
	}
	return rows.Share, nil
}

func (b *web3Auth) UploadBackupShare(ctx context.Context, backupID string, share []byte) (err error) {
	err = b.db.CreateNoReturn_Web3BackupShare(ctx,
		dbx.Web3BackupShare_BackupId([]byte(backupID)),
		dbx.Web3BackupShare_Share(share),
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			_, err = b.db.Update_Web3BackupShare_By_BackupId(ctx,
				dbx.Web3BackupShare_BackupId([]byte(backupID)),
				dbx.Web3BackupShare_Update_Fields{
					Share: dbx.Web3BackupShare_Share(share),
				},
			)
		}
		return err
	}
	return nil
}

func (b *web3Auth) CreateKeyVersion(ctx context.Context, keyID []byte, version string) error {
	return b.db.CreateNoReturn_KeyVersion(ctx,
		dbx.KeyVersion_KeyId(keyID),
		dbx.KeyVersion_Version(version),
	)
}

func (b *web3Auth) GetKeyVersion(ctx context.Context, keyID []byte) (string, error) {
	row, err := b.db.Get_KeyVersion_Version_By_KeyId(ctx, dbx.KeyVersion_KeyId(keyID))
	if err != nil {
		return "", err
	}
	return row.Version, nil
}

func (b *web3Auth) UpdateKeyVersion(ctx context.Context, keyID []byte, newVersion string) error {
	_, err := b.db.Update_KeyVersion_By_KeyId(ctx,
		dbx.KeyVersion_KeyId(keyID),
		dbx.KeyVersion_Update_Fields{
			Version: dbx.KeyVersion_Version(newVersion),
		},
	)
	return err
}

// Backup status methods
func (b *web3Auth) CreateBackupFinalStatus(ctx context.Context, backupDate string, status string) error {
	return b.db.CreateNoReturn_BackupFinalStatus(ctx,
		dbx.BackupFinalStatus_BackupDate(backupDate),
		dbx.BackupFinalStatus_Status(status),
		dbx.BackupFinalStatus_CompletedAt(time.Time{}),
		dbx.BackupFinalStatus_TotalPages(0),
		dbx.BackupFinalStatus_TotalKeys(0),
		dbx.BackupFinalStatus_BackupFilePath(""),
		dbx.BackupFinalStatus_ErrorMessage(""),
		dbx.BackupFinalStatus_Checksum(""),
		dbx.BackupFinalStatus_FileSize(0),
	)
}

func (b *web3Auth) UpdateBackupFinalStatus(ctx context.Context, backupDate string, status string, completedAt time.Time, totalPages, totalKeys int, backupFilePath, errorMessage, checksum string, fileSize int64) error {
	_, err := b.db.Update_BackupFinalStatus_By_BackupDate(ctx,
		dbx.BackupFinalStatus_BackupDate(backupDate),
		dbx.BackupFinalStatus_Update_Fields{
			Status:         dbx.BackupFinalStatus_Status(status),
			CompletedAt:    dbx.BackupFinalStatus_CompletedAt(completedAt),
			TotalPages:     dbx.BackupFinalStatus_TotalPages(totalPages),
			TotalKeys:      dbx.BackupFinalStatus_TotalKeys(totalKeys),
			BackupFilePath: dbx.BackupFinalStatus_BackupFilePath(backupFilePath),
			ErrorMessage:   dbx.BackupFinalStatus_ErrorMessage(errorMessage),
			Checksum:       dbx.BackupFinalStatus_Checksum(checksum),
			FileSize:       dbx.BackupFinalStatus_FileSize(fileSize),
		},
	)
	return err
}

func (b *web3Auth) GetBackupFinalStatus(ctx context.Context, backupDate string) (*backup.BackupFinalStatus, error) {
	row, err := b.db.Get_BackupFinalStatus_By_BackupDate(ctx, dbx.BackupFinalStatus_BackupDate(backupDate))
	if err != nil {
		return nil, err
	}
	return &backup.BackupFinalStatus{
		BackupDate:     row.BackupDate,
		Status:         row.Status,
		CompletedAt:    row.CompletedAt,
		TotalPages:     row.TotalPages,
		TotalKeys:      row.TotalKeys,
		BackupFilePath: row.BackupFilePath,
		ErrorMessage:   row.ErrorMessage,
		Checksum:       row.Checksum,
		FileSize:       row.FileSize,
	}, nil
}

func (b *web3Auth) GetLatestBackupStatus(ctx context.Context) (*backup.BackupFinalStatus, error) {
	rows, err := b.db.All_BackupFinalStatus_OrderBy_Desc_BackupDate(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	row := rows[0] // First row is the latest due to DESC ordering
	return &backup.BackupFinalStatus{
		BackupDate:     row.BackupDate,
		Status:         row.Status,
		CompletedAt:    row.CompletedAt,
		TotalPages:     row.TotalPages,
		TotalKeys:      row.TotalKeys,
		BackupFilePath: row.BackupFilePath,
		ErrorMessage:   row.ErrorMessage,
		Checksum:       row.Checksum,
		FileSize:       row.FileSize,
	}, nil
}

func (b *web3Auth) ListBackupStatuses(ctx context.Context, limit int) ([]*backup.BackupFinalStatus, error) {
	rows, err := b.db.All_BackupFinalStatus_OrderBy_Desc_BackupDate(ctx)
	if err != nil {
		return nil, err
	}

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	statuses := make([]*backup.BackupFinalStatus, len(rows))
	for i, row := range rows {
		statuses[i] = &backup.BackupFinalStatus{
			BackupDate:     row.BackupDate,
			Status:         row.Status,
			CompletedAt:    row.CompletedAt,
			TotalPages:     row.TotalPages,
			TotalKeys:      row.TotalKeys,
			BackupFilePath: row.BackupFilePath,
			ErrorMessage:   row.ErrorMessage,
			Checksum:       row.Checksum,
			FileSize:       row.FileSize,
		}
	}
	return statuses, nil
}

func (b *web3Auth) CreateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string) error {
	return b.db.CreateNoReturn_BackupPageStatus(ctx,
		dbx.BackupPageStatus_BackupDate(backupDate),
		dbx.BackupPageStatus_PageNumber(pageNumber),
		dbx.BackupPageStatus_Status(status),
		dbx.BackupPageStatus_CompletedAt(time.Time{}),
		dbx.BackupPageStatus_KeysCount(0),
		dbx.BackupPageStatus_FilePath(""),
		dbx.BackupPageStatus_ErrorMessage(""),
		dbx.BackupPageStatus_Checksum(""),
		dbx.BackupPageStatus_FileSize(0),
	)
}

func (b *web3Auth) UpdateBackupPageStatus(ctx context.Context, backupDate string, pageNumber int, status string, completedAt time.Time, keysCount int, filePath, errorMessage, checksum string, fileSize int64) error {
	_, err := b.db.Update_BackupPageStatus_By_BackupDate_And_PageNumber(ctx,
		dbx.BackupPageStatus_BackupDate(backupDate),
		dbx.BackupPageStatus_PageNumber(pageNumber),
		dbx.BackupPageStatus_Update_Fields{
			Status:       dbx.BackupPageStatus_Status(status),
			CompletedAt:  dbx.BackupPageStatus_CompletedAt(completedAt),
			KeysCount:    dbx.BackupPageStatus_KeysCount(keysCount),
			FilePath:     dbx.BackupPageStatus_FilePath(filePath),
			ErrorMessage: dbx.BackupPageStatus_ErrorMessage(errorMessage),
			Checksum:     dbx.BackupPageStatus_Checksum(checksum),
			FileSize:     dbx.BackupPageStatus_FileSize(fileSize),
		},
	)
	return err
}

func (b *web3Auth) GetBackupPageStatus(ctx context.Context, backupDate string, pageNumber int) (*backup.BackupPageStatus, error) {
	row, err := b.db.Get_BackupPageStatus_By_BackupDate_And_PageNumber(ctx,
		dbx.BackupPageStatus_BackupDate(backupDate),
		dbx.BackupPageStatus_PageNumber(pageNumber),
	)
	if err != nil {
		return nil, err
	}
	return &backup.BackupPageStatus{
		BackupDate:   row.BackupDate,
		PageNumber:   row.PageNumber,
		Status:       row.Status,
		CompletedAt:  row.CompletedAt,
		KeysCount:    row.KeysCount,
		FilePath:     row.FilePath,
		ErrorMessage: row.ErrorMessage,
		Checksum:     row.Checksum,
		FileSize:     row.FileSize,
	}, nil
}

func (b *web3Auth) GetBackupPageStatuses(ctx context.Context, backupDate string) ([]*backup.BackupPageStatus, error) {
	rows, err := b.db.All_BackupPageStatus_By_BackupDate_OrderBy_Asc_PageNumber(ctx, dbx.BackupPageStatus_BackupDate(backupDate))
	if err != nil {
		return nil, err
	}

	statuses := make([]*backup.BackupPageStatus, len(rows))
	for i, row := range rows {
		statuses[i] = &backup.BackupPageStatus{
			BackupDate:   row.BackupDate,
			PageNumber:   row.PageNumber,
			Status:       row.Status,
			CompletedAt:  row.CompletedAt,
			KeysCount:    row.KeysCount,
			FilePath:     row.FilePath,
			ErrorMessage: row.ErrorMessage,
			Checksum:     row.Checksum,
			FileSize:     row.FileSize,
		}
	}
	return statuses, nil
}

func (b *web3Auth) DeleteOldBackupStatuses(ctx context.Context, olderThan time.Time) error {
	// TODO: Implement proper deletion with raw SQL query
	// For now, return nil to avoid compilation errors
	return nil
}

func (b *web3Auth) DeleteBackupPageStatuses(ctx context.Context, backupDate string) error {
	// TODO: Implement proper deletion with raw SQL query
	// For now, return nil to avoid compilation errors
	return nil
}
