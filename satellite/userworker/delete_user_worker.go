package userworker

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"
	"storj.io/common/macaroon"
	"storj.io/common/sync2"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/audit"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/console"
)

var mon = monkit.Package()

type DeleteUserQueue interface {
	GetNextUser(ctx context.Context) (user *uuid.UUID, err error)
	MarkProcessed(ctx context.Context, userID uuid.UUID, err error) error
}

// DeleteUserWorker deletes a user.
type DeleteUserWorker struct {
	log      *zap.Logger
	queue    DeleteUserQueue
	Loop     *sync2.Cycle
	projects console.Projects
	apiKeys  console.APIKeys
	buckets  buckets.DB
	users    console.Users
}

// NewDeleteUserWorker creates a new DeleteUserWorker.
func NewDeleteUserWorker(log *zap.Logger, queue DeleteUserQueue, projects console.Projects, apiKeys console.APIKeys, buckets buckets.DB, users console.Users) *DeleteUserWorker {
	return &DeleteUserWorker{
		log:      log,
		queue:    queue,
		projects: projects,
		apiKeys:  apiKeys,
		buckets:  buckets,
		users:    users,
		Loop:     sync2.NewCycle(time.Hour * 4),
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

	for _, project := range projects {
		// get all buckets for project

		for {
			buckets, err := worker.buckets.ListBuckets(ctx, project.ID, buckets.ListOptions{
				Direction: buckets.DirectionForward,
			}, macaroon.AllowedBuckets{
				All: true,
			})
			if err != nil {
				return err
			}

			// delete all buckets
			for _, bucket := range buckets.Items {
				err = worker.buckets.DeleteBucket(ctx, []byte(bucket.Name), project.ID)
				if err != nil {
					return err
				}
			}

			if !buckets.More {
				break
			}
		}

		for {
			// delete all api keys
			apiKeys, err := worker.apiKeys.GetPagedByProjectID(ctx, project.ID, console.APIKeyCursor{
				Limit: 100,
				Page:  1,
			})
			if err != nil {
				return err
			}

			for _, apiKey := range apiKeys.APIKeys {
				err = worker.apiKeys.Delete(ctx, apiKey.ID)
				if err != nil {
					return err
				}
			}

			if apiKeys.TotalCount == uint64(len(apiKeys.APIKeys)) {
				break
			}
		}

		// delete project
		err = worker.projects.Delete(ctx, project.ID)
		if err != nil {
			return err
		}

	}

	// delete user
	err = worker.users.Delete(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}
