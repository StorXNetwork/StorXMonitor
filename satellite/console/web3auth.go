package console

import (
	"context"

	"storj.io/common/uuid"
)

type Web3Auth interface {
	GetBackupShare(ctx context.Context, backupID uuid.UUID) (share []byte, err error)
	UploadBackupShare(ctx context.Context, backupID uuid.UUID, share []byte) (err error)
}
