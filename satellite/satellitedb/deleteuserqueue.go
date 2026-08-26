package satellitedb

import (
	"context"
	"database/sql"
	"errors"

	"github.com/StorXNetwork/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/userworker"
)

type deleteUserQueue struct {
	db *satelliteDB
}

var _ userworker.DeleteUserQueue = (*deleteUserQueue)(nil)

// GetNextUser claims the oldest due INIT row (delete_at <= now). Claims are exclusive via status=processing.
func (duq *deleteUserQueue) GetNextUser(ctx context.Context) (user *uuid.UUID, err error) {
	defer mon.Task()(&ctx)(&err)

	user = &uuid.UUID{}
	err = duq.db.QueryRowContext(ctx, `
		WITH next_entry AS (
			SELECT *
			FROM user_delete_requests
			WHERE status = 'INIT' AND delete_at <= now()
			ORDER BY delete_at ASC, created_at ASC
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

// MarkProcessed marks success, or requeues INIT on failure so BT purge / wipe can retry.
func (duq *deleteUserQueue) MarkProcessed(ctx context.Context, userID uuid.UUID, processErr error) (err error) {
	defer mon.Task()(&ctx)(&err)

	if processErr != nil {
		_, err = duq.db.ExecContext(ctx, `
			UPDATE user_delete_requests
			SET status = 'INIT', error = $1
			WHERE user_id = $2 AND status = 'processing'
		`, processErr.Error(), userID)
		return err
	}

	_, err = duq.db.ExecContext(ctx, `
		UPDATE user_delete_requests
		SET status = 'success', error = NULL
		WHERE user_id = $1 AND status = 'processing'
	`, userID)
	return err
}
