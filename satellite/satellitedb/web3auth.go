package satellitedb

import (
	"context"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
)

var _ console.Web3Auth = (*web3Auth)(nil)

type web3Auth struct {
	db *satelliteDB
}

func (b *web3Auth) GetBackupShare(ctx context.Context, backupID uuid.UUID) (share []byte, err error) {
	return nil, nil
}

func (b *web3Auth) UploadBackupShare(ctx context.Context, backupID uuid.UUID, share []byte) (err error) {
	return nil
}
