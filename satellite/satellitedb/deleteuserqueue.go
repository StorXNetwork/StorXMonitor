package satellitedb

import (
	"context"
	"database/sql"
	"errors"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/audit"
	"storj.io/storj/satellite/userworker"
)

type deleteUserQueue struct {
	db *satelliteDB
}

var _ userworker.DeleteUserQueue = (*deleteUserQueue)(nil)

// GetNextUser retrieves a user from the queue. The user will be the
// user which has been in the queue the longest, except those which
// have already been claimed by another worker within the last
// retryInterval. If there are no such users, an error wrapped by
// audit.ErrEmptyQueue will be returned.
func (duq *deleteUserQueue) GetNextUser(ctx context.Context) (user *uuid.UUID, err error) {
	defer mon.Task()(&ctx)(&err)

	user = &uuid.UUID{}
	err = duq.db.QueryRowContext(ctx, `
		WITH next_entry AS (
			SELECT *
			FROM user_delete_requests
			WHERE status = 'pending'
			LIMIT 1
		)
		UPDATE user_delete_requests
		SET status = 'processing'
		FROM next_entry
		WHERE user_delete_requests.id = next_entry.id
		RETURNING user_delete_requests.user_id
	`).Scan(&user)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, audit.ErrEmptyQueue.Wrap(err)
	}
	return user, err
}

// MarkProcessed marks a user as processed.
func (duq *deleteUserQueue) MarkProcessed(ctx context.Context, userID uuid.UUID, err error) error {
	defer mon.Task()(&ctx)(&err)

	status := "success"
	if err != nil {
		status = "error"
	}

	_, err = duq.db.ExecContext(ctx, `
		UPDATE user_delete_requests
		SET status = $1, error = $2
		WHERE user_id = $3
	`, status, err, userID)
	return err
}
