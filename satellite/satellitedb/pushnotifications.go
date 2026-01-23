// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/pushnotifications"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

// ensures that pushNotifications implements pushnotifications.PushNotificationDB.
var _ pushnotifications.PushNotificationDB = (*pushNotifications)(nil)

// ErrPushNotifications represents errors from the push_notifications database.
var ErrPushNotifications = errs.Class("pushnotifications")

type pushNotifications struct {
	db *satelliteDB
}

// InsertNotification inserts a new push notification record.
func (p *pushNotifications) InsertNotification(ctx context.Context, notification pushnotifications.PushNotificationRecord) (_ pushnotifications.PushNotificationRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	var dataJSON []byte
	if notification.Data != nil {
		var err error
		dataJSON, err = json.Marshal(notification.Data)
		if err != nil {
			return notification, ErrPushNotifications.Wrap(err)
		}
	}

	var optional dbx.PushNotifications_Create_Fields
	if notification.TokenID != nil {
		optional.TokenId = dbx.PushNotifications_TokenId(notification.TokenID[:])
	}
	if len(dataJSON) > 0 {
		optional.Data = dbx.PushNotifications_Data(dataJSON)
	}
	if notification.ErrorMessage != nil {
		optional.ErrorMessage = dbx.PushNotifications_ErrorMessage(*notification.ErrorMessage)
	}
	if notification.SentAt != nil {
		optional.SentAt = dbx.PushNotifications_SentAt(*notification.SentAt)
	}
	if notification.RetryCount > 0 {
		optional.RetryCount = dbx.PushNotifications_RetryCount(notification.RetryCount)
	}

	dbxNotification, err := p.db.Create_PushNotifications(ctx,
		dbx.PushNotifications_Id(notification.ID[:]),
		dbx.PushNotifications_UserId(notification.UserID[:]),
		dbx.PushNotifications_Title(notification.Title),
		dbx.PushNotifications_Body(notification.Body),
		dbx.PushNotifications_Status(notification.Status),
		optional)
	if err != nil {
		return notification, ErrPushNotifications.Wrap(err)
	}

	return pushNotificationFromDBX(dbxNotification)
}

// UpdateNotificationStatus updates the status of a notification.
func (p *pushNotifications) UpdateNotificationStatus(ctx context.Context, id uuid.UUID, status string, errorMsg *string, sentAt *time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Build update query since status is not in Update_Fields
	query := "UPDATE push_notifications SET status = $2"
	args := []interface{}{id[:], status}
	argIndex := 3

	if errorMsg != nil {
		query += fmt.Sprintf(", error_message = $%d", argIndex)
		args = append(args, *errorMsg)
		argIndex++
	} else {
		query += ", error_message = NULL"
	}

	if sentAt != nil {
		query += fmt.Sprintf(", sent_at = $%d", argIndex)
		args = append(args, *sentAt)
		argIndex++
	} else {
		query += ", sent_at = NULL"
	}

	query += " WHERE id = $1"

	_, err = p.db.ExecContext(ctx, p.db.Rebind(query), args...)
	return ErrPushNotifications.Wrap(err)
}

// IncrementRetryCount increments the retry count for a notification.
func (p *pushNotifications) IncrementRetryCount(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Get current notification to read retry_count
	dbxNotification, err := p.db.Get_PushNotifications_By_Id(ctx, dbx.PushNotifications_Id(id[:]))
	if err != nil {
		return ErrPushNotifications.Wrap(err)
	}

	newRetryCount := dbxNotification.RetryCount + 1
	_, err = p.db.Update_PushNotifications_By_Id(ctx, dbx.PushNotifications_Id(id[:]), dbx.PushNotifications_Update_Fields{
		RetryCount: dbx.PushNotifications_RetryCount(newRetryCount),
	})
	return ErrPushNotifications.Wrap(err)
}

// GetNotificationsByUserID retrieves all notifications for a user.
func (p *pushNotifications) GetNotificationsByUserID(ctx context.Context, userID uuid.UUID) (_ []pushnotifications.PushNotificationRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxNotifications, err := p.db.All_PushNotifications_By_UserId(ctx, dbx.PushNotifications_UserId(userID[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return []pushnotifications.PushNotificationRecord{}, nil
		}
		return nil, ErrPushNotifications.Wrap(err)
	}

	notifications := make([]pushnotifications.PushNotificationRecord, 0, len(dbxNotifications))
	for _, dbxNotification := range dbxNotifications {
		notification, err := pushNotificationFromDBX(dbxNotification)
		if err != nil {
			return nil, ErrPushNotifications.Wrap(err)
		}
		notifications = append(notifications, notification)
	}

	return notifications, nil
}

// GetNotificationByID retrieves a notification by ID.
func (p *pushNotifications) GetNotificationByID(ctx context.Context, id uuid.UUID) (_ pushnotifications.PushNotificationRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	dbxNotification, err := p.db.Get_PushNotifications_By_Id(ctx, dbx.PushNotifications_Id(id[:]))
	if err != nil {
		return pushnotifications.PushNotificationRecord{}, ErrPushNotifications.Wrap(err)
	}

	return pushNotificationFromDBX(dbxNotification)
}

// pushNotificationFromDBX converts a dbx.PushNotifications to pushnotifications.PushNotificationRecord.
func pushNotificationFromDBX(dbxNotification *dbx.PushNotifications) (pushnotifications.PushNotificationRecord, error) {
	id, err := uuid.FromBytes(dbxNotification.Id)
	if err != nil {
		return pushnotifications.PushNotificationRecord{}, ErrPushNotifications.Wrap(err)
	}

	userID, err := uuid.FromBytes(dbxNotification.UserId)
	if err != nil {
		return pushnotifications.PushNotificationRecord{}, ErrPushNotifications.Wrap(err)
	}

	notification := pushnotifications.PushNotificationRecord{
		ID:         id,
		UserID:     userID,
		Title:      dbxNotification.Title,
		Body:       dbxNotification.Body,
		Status:     dbxNotification.Status,
		RetryCount: dbxNotification.RetryCount,
		CreatedAt:  dbxNotification.CreatedAt,
		Hide:       dbxNotification.Hide,
	}

	if dbxNotification.TokenId != nil {
		tokenID, err := uuid.FromBytes(dbxNotification.TokenId)
		if err != nil {
			return pushnotifications.PushNotificationRecord{}, ErrPushNotifications.Wrap(err)
		}
		notification.TokenID = &tokenID
	}

	if dbxNotification.Data != nil {
		var data map[string]interface{}
		if err := json.Unmarshal(dbxNotification.Data, &data); err != nil {
			return pushnotifications.PushNotificationRecord{}, ErrPushNotifications.Wrap(err)
		}
		notification.Data = data
	}

	if dbxNotification.ErrorMessage != nil {
		errorMsg := *dbxNotification.ErrorMessage
		notification.ErrorMessage = &errorMsg
	}

	if dbxNotification.SentAt != nil {
		notification.SentAt = dbxNotification.SentAt
	}

	return notification, nil
}

// ListNotifications retrieves paginated notifications for a user with optional filter and time filter.
func (p *pushNotifications) ListNotifications(ctx context.Context, userID uuid.UUID, limit, page int, filter pushnotifications.NotificationFilter, timeFilter *time.Time) (_ *pushnotifications.NotificationPage, err error) {
	defer mon.Task()(&ctx)(&err)

	if limit <= 0 {
		limit = 50
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	where := "user_id = $1"
	args := []interface{}{userID[:]}
	argIndex := 2

	if filter == pushnotifications.FilterUnread {
		where += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, pushnotifications.StatusSent)
		argIndex++
	}

	// Add time filter if provided
	if timeFilter != nil {
		where += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, *timeFilter)
		argIndex++
	}

	// Query A: Fetch paginated notifications
	limitIndex := argIndex
	offsetIndex := argIndex + 1
	query := fmt.Sprintf(`SELECT id, user_id, token_id, title, body, data, status, error_message, retry_count, sent_at, created_at, hide
		FROM push_notifications
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, limitIndex, offsetIndex)

	rows, err := p.db.QueryContext(ctx, p.db.Rebind(query), append(args, limit, offset)...)
	if err != nil {
		return nil, ErrPushNotifications.Wrap(err)
	}
	defer rows.Close()

	var dbxNotifications []*dbx.PushNotifications
	for rows.Next() {
		var n dbx.PushNotifications
		var tokenID, data []byte
		var errorMsg sql.NullString
		if err := rows.Scan(
			&n.Id,
			&n.UserId,
			&tokenID,
			&n.Title,
			&n.Body,
			&data,
			&n.Status,
			&errorMsg,
			&n.RetryCount,
			&n.SentAt,
			&n.CreatedAt,
			&n.Hide,
		); err != nil {
			return nil, ErrPushNotifications.Wrap(err)
		}
		if len(tokenID) > 0 {
			n.TokenId = tokenID
		}
		if len(data) > 0 {
			n.Data = data
		}
		if errorMsg.Valid {
			n.ErrorMessage = &errorMsg.String
		}
		dbxNotifications = append(dbxNotifications, &n)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrPushNotifications.Wrap(err)
	}

	// Query B: Count total notifications
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM push_notifications WHERE %s", where)
	var totalCount int
	if err := p.db.QueryRowContext(ctx, p.db.Rebind(countQuery), args...).Scan(&totalCount); err != nil {
		return nil, ErrPushNotifications.Wrap(err)
	}

	// Convert DBX to API model
	notifications := make([]pushnotifications.PushNotificationRecord, 0, len(dbxNotifications))
	for _, dbxNotif := range dbxNotifications {
		notif, err := pushNotificationFromDBX(dbxNotif)
		if err != nil {
			return nil, ErrPushNotifications.Wrap(err)
		}
		notifications = append(notifications, notif)
	}

	pageCount := (totalCount + limit - 1) / limit
	if pageCount == 0 {
		pageCount = 1
	}

	return &pushnotifications.NotificationPage{
		Notifications: notifications,
		TotalCount:    totalCount,
		Limit:         limit,
		Page:          page,
		PageCount:     pageCount,
	}, nil
}

// MarkNotificationAsRead marks a single notification as read (updates status to "read").
func (p *pushNotifications) MarkNotificationAsRead(ctx context.Context, notificationID, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	query := `UPDATE push_notifications
		SET status = $1
		WHERE id = $2
		  AND user_id = $3
		  AND status = $4`
	res, err := p.db.ExecContext(
		ctx,
		p.db.Rebind(query),
		pushnotifications.MarkAsRead(),
		notificationID[:],
		userID[:],
		pushnotifications.StatusSent,
	)
	if err != nil {
		return ErrPushNotifications.Wrap(err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return ErrPushNotifications.Wrap(err)
	}
	if rowsAffected == 0 {
		return nil
	}
	return nil
}

// MarkAllNotificationsAsRead marks all unread notifications for a user as read (updates status to "read").
func (p *pushNotifications) MarkAllNotificationsAsRead(ctx context.Context, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	newStatus := pushnotifications.MarkAsRead()
	query := "UPDATE push_notifications SET status = $1 WHERE user_id = $2 AND status = $3"
	_, err = p.db.ExecContext(ctx, p.db.Rebind(query), newStatus, userID[:], pushnotifications.StatusSent)
	return ErrPushNotifications.Wrap(err)
}

// GetUnreadCount returns the count of unread notifications for a user.
func (p *pushNotifications) GetUnreadCount(ctx context.Context, userID uuid.UUID) (_ int, err error) {
	defer mon.Task()(&ctx)(&err)

	query := "SELECT COUNT(*) FROM push_notifications WHERE user_id = $1 AND status = $2"
	var count int
	err = p.db.QueryRowContext(ctx, p.db.Rebind(query), userID[:], pushnotifications.StatusSent).Scan(&count)
	if err != nil {
		return 0, ErrPushNotifications.Wrap(err)
	}
	return count, nil
}

// DismissNotification hides a notification from the notification bar (sets hide = true).
func (p *pushNotifications) DismissNotification(ctx context.Context, notificationID, userID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	query := `UPDATE push_notifications
		SET hide = true
		WHERE id = $1
		  AND user_id = $2`
	res, err := p.db.ExecContext(
		ctx,
		p.db.Rebind(query),
		notificationID[:],
		userID[:],
	)
	if err != nil {
		return ErrPushNotifications.Wrap(err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return ErrPushNotifications.Wrap(err)
	}
	if rowsAffected == 0 {
		return ErrPushNotifications.New("notification not found or does not belong to user")
	}
	return nil
}
