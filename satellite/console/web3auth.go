package console

import (
	"context"
)

type Web3Auth interface {
	GetBackupShare(ctx context.Context, backupID string) (share []byte, err error)
	UploadBackupShare(ctx context.Context, backupID string, share []byte) (err error)

	CreateKeyVersion(ctx context.Context, keyID []byte, version string) error
	GetKeyVersion(ctx context.Context, keyID []byte) (version string, err error)
	UpdateKeyVersion(ctx context.Context, keyID []byte, newVersion string) error
}
