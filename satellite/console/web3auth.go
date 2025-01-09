package console

import (
	"context"
)

type Web3Auth interface {
	GetBackupShare(ctx context.Context, backupID string) (share []byte, err error)
	UploadBackupShare(ctx context.Context, backupID string, share []byte) (err error)
}
