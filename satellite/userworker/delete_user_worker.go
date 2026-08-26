// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package userworker

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/common/macaroon"
	"github.com/StorXNetwork/common/sync2"
	"github.com/StorXNetwork/common/uuid"
)

var mon = monkit.Package()

type DeleteUserQueue interface {
	GetNextUser(ctx context.Context) (user *uuid.UUID, err error)
	MarkProcessed(ctx context.Context, userID uuid.UUID, err error) error
}

// BackupToolsAccountPurger purges Backup-Tools data for a satellite user before Satellite hard delete.
type BackupToolsAccountPurger interface {
	PurgeBackupToolsAccount(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID) error
}

type projectStore interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]console.Project, error)
	Delete(ctx context.Context, projectID uuid.UUID) error
}

type apiKeyStore interface {
	GetPagedByProjectID(ctx context.Context, projectID uuid.UUID, cursor console.APIKeyCursor) (*console.APIKeyPage, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type bucketStore interface {
	ListBuckets(ctx context.Context, projectID uuid.UUID, listOpts buckets.ListOptions, allowedBuckets macaroon.AllowedBuckets) (buckets.List, error)
	DeleteBucket(ctx context.Context, bucketName []byte, projectID uuid.UUID) error
}

type userStore interface {
	Delete(ctx context.Context, userID uuid.UUID) error
}

type backupCredentialStore interface {
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error
}

// DeleteUserWorker deletes a user.
type DeleteUserWorker struct {
	log               *zap.Logger
	queue             DeleteUserQueue
	Loop              *sync2.Cycle
	projects          projectStore
	apiKeys           apiKeyStore
	buckets           bucketStore
	users             userStore
	backupCredentials backupCredentialStore
	btPurger          BackupToolsAccountPurger
}

// NewDeleteUserWorker creates a new DeleteUserWorker.
func NewDeleteUserWorker(
	log *zap.Logger,
	queue DeleteUserQueue,
	projects console.Projects,
	apiKeys console.APIKeys,
	bucketsDB buckets.DB,
	users console.Users,
	backupCredentials console.BackupCredentials,
	btPurger BackupToolsAccountPurger,
	interval time.Duration,
) *DeleteUserWorker {
	return &DeleteUserWorker{
		log:               log,
		queue:             queue,
		projects:          projects,
		apiKeys:           apiKeys,
		buckets:           bucketsDB,
		users:             users,
		backupCredentials: backupCredentials,
		btPurger:          btPurger,
		Loop:              sync2.NewCycle(interval),
	}
}

func (worker *DeleteUserWorker) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return worker.Loop.Run(ctx, func(ctx context.Context) (err error) {
		err = worker.process(ctx)
		if err == nil {
			return nil
		}

		worker.log.Error("failure processing delete user queue", zap.Error(err))

		return nil
	})
}

func (worker *DeleteUserWorker) process(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	for {
		userID, err := worker.queue.GetNextUser(ctx)
		if err != nil {
			if audit.ErrEmptyQueue.Has(err) {
				return nil
			}
			return err
		}

		// delete all data
		err = worker.deleteAllData(ctx, *userID)

		worker.log.Info("deleting user", zap.String("user_id", userID.String()), zap.Error(err))
		err = worker.queue.MarkProcessed(ctx, *userID, err)
		if err != nil {
			return err
		}
	}
}

func (worker *DeleteUserWorker) deleteAllData(ctx context.Context, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	// get project ids from user
	projects, err := worker.projects.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	projectIDs := make([]uuid.UUID, 0, len(projects))
	for _, project := range projects {
		projectIDs = append(projectIDs, project.ID)
	}

	// BT purge first — failure must not wipe Satellite data.
	if worker.btPurger != nil {
		if err = worker.btPurger.PurgeBackupToolsAccount(ctx, userID, projectIDs); err != nil {
			return err
		}
	}

	for _, project := range projects {
		for {
			listed, err := worker.buckets.ListBuckets(ctx, project.ID, buckets.ListOptions{
				Direction: buckets.DirectionForward,
			}, macaroon.AllowedBuckets{
				All: true,
			})
			if err != nil {
				return err
			}

			for _, bucket := range listed.Items {
				err = worker.buckets.DeleteBucket(ctx, []byte(bucket.Name), project.ID)
				if err != nil {
					return err
				}
			}

			if !listed.More {
				break
			}
		}

		for {
			apiKeys, err := worker.apiKeys.GetPagedByProjectID(ctx, project.ID, console.APIKeyCursor{
				Limit: 100,
				Page:  1,
			})
			if err != nil {
				return err
			}
			if len(apiKeys.APIKeys) == 0 {
				break
			}

			for _, apiKey := range apiKeys.APIKeys {
				err = worker.apiKeys.Delete(ctx, apiKey.ID)
				if err != nil {
					return err
				}
			}
		}

		err = worker.projects.Delete(ctx, project.ID)
		if err != nil {
			return err
		}
	}

	if worker.backupCredentials != nil {
		if err = worker.backupCredentials.DeleteAllByUserID(ctx, userID); err != nil {
			return err
		}
	}

	err = worker.users.Delete(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}
