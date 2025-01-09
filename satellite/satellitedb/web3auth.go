package satellitedb

import (
	"context"

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
		return err
	}
	return nil
}
