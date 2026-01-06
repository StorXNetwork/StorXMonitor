// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/pushnotifications"
)

var (
	ErrNotificationsAPI = errs.Class("consoleapi notifications")
)

type Notifications struct {
	log     *zap.Logger
	service *console.Service
}

func NewNotifications(log *zap.Logger, service *console.Service) *Notifications {
	return &Notifications{
		log:     log,
		service: service,
	}
}

type NotificationResponse struct {
	ID           uuid.UUID              `json:"id"`
	UserID       uuid.UUID              `json:"userId"`
	TokenID      *uuid.UUID             `json:"tokenId,omitempty"`
	Title        string                 `json:"title"`
	Body         string                 `json:"body"`
	Data         map[string]interface{} `json:"data,omitempty"`
	Status       string                 `json:"status"`
	ErrorMessage *string                `json:"errorMessage,omitempty"`
	RetryCount   int                    `json:"retryCount"`
	SentAt       *string                `json:"sentAt,omitempty"`
	CreatedAt    string                 `json:"createdAt"`
	IsRead       bool                   `json:"isRead"`
	Hide         bool                   `json:"hide"`
}

type NotificationListResponse struct {
	Items      []NotificationResponse `json:"items"`
	TotalCount int                    `json:"totalCount"`
	Limit      int                    `json:"limit"`
	Page       int                    `json:"page"`
	PageCount  int                    `json:"pageCount"`
}

type UnreadCountResponse struct {
	Count int `json:"count"`
}

func (n *Notifications) ListNotifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	limit := n.parseLimit(r.URL.Query().Get("limit"))
	page := n.parsePage(r.URL.Query().Get("page"))
	filter := n.parseFilter(r.URL.Query().Get("filter"))
	timeFilter := n.parseTimeFilter(r.URL.Query().Get("timeFilter"))

	pageResult, err := n.service.GetPushNotifications().ListNotifications(ctx, user.ID, limit, page, filter, timeFilter)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNotificationsAPI.Wrap(err))
		return
	}

	response := NotificationListResponse{
		Items:      n.convertNotifications(pageResult.Notifications),
		TotalCount: pageResult.TotalCount,
		Limit:      pageResult.Limit,
		Page:       pageResult.Page,
		PageCount:  pageResult.PageCount,
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(response); err != nil {
		n.log.Error("failed to encode response", zap.Error(err))
	}
}

func (n *Notifications) parseLimit(limitStr string) int {
	if limitStr == "" {
		return 50
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		return 50
	}
	return limit
}

func (n *Notifications) parsePage(pageStr string) int {
	if pageStr == "" {
		return 1
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		return 1
	}
	return page
}

func (n *Notifications) parseFilter(filterStr string) pushnotifications.NotificationFilter {
	if filterStr == "unread" {
		return pushnotifications.FilterUnread
	}
	return pushnotifications.FilterAll
}

func (n *Notifications) parseTimeFilter(timeFilterStr string) *time.Time {
	if timeFilterStr == "" {
		return nil
	}

	now := time.Now()
	var cutoffTime time.Time

	switch timeFilterStr {
	case "1d", "1day":
		cutoffTime = now.AddDate(0, 0, -1)
	case "7d", "7days":
		cutoffTime = now.AddDate(0, 0, -7)
	case "15d", "15days":
		cutoffTime = now.AddDate(0, 0, -15)
	case "1m", "1month":
		cutoffTime = now.AddDate(0, -1, 0)
	case "6m", "6months":
		cutoffTime = now.AddDate(0, -6, 0)
	case "1y", "1year":
		cutoffTime = now.AddDate(-1, 0, 0)
	default:
		return nil
	}

	return &cutoffTime
}

func (n *Notifications) GetNotificationDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	notificationIDStr, ok := mux.Vars(r)["id"]
	if !ok {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationsAPI.New("notification id is required"))
		return
	}

	notificationID, err := uuid.FromString(notificationIDStr)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationsAPI.New("invalid notification id format: %v", err))
		return
	}

	notificationDB := n.service.GetPushNotifications()
	notif, err := notificationDB.GetNotificationByID(ctx, notificationID)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusNotFound, ErrNotificationsAPI.Wrap(err))
		return
	}

	if notif.UserID != user.ID {
		web.ServeJSONError(ctx, n.log, w, http.StatusForbidden, ErrNotificationsAPI.New("notification does not belong to user"))
		return
	}

	if !pushnotifications.IsRead(notif.Status) {
		if markErr := notificationDB.MarkNotificationAsRead(ctx, notificationID, user.ID); markErr != nil {
			n.log.Warn("failed to mark notification as read", zap.Error(markErr), zap.Stringer("notification_id", notificationID))
		} else {
			notif.Status = pushnotifications.MarkAsRead()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(n.convertNotification(notif)); err != nil {
		n.log.Error("failed to encode response", zap.Error(err))
	}
}

func (n *Notifications) MarkAllAsRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	err = n.service.GetPushNotifications().MarkAllNotificationsAsRead(ctx, user.ID)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(map[string]string{"message": "All notifications marked as read"}); err != nil {
		n.log.Error("failed to encode response", zap.Error(err))
	}
}

func (n *Notifications) GetUnreadCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	count, err := n.service.GetPushNotifications().GetUnreadCount(ctx, user.ID)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(UnreadCountResponse{Count: count}); err != nil {
		n.log.Error("failed to encode response", zap.Error(err))
	}
}

func (n *Notifications) DismissNotification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := console.GetUser(ctx)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
		return
	}

	notificationIDStr, ok := mux.Vars(r)["id"]
	if !ok {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationsAPI.New("notification id is required"))
		return
	}

	notificationID, err := uuid.FromString(notificationIDStr)
	if err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNotificationsAPI.New("invalid notification id format: %v", err))
		return
	}

	err = n.service.GetPushNotifications().DismissNotification(ctx, notificationID, user.ID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			web.ServeJSONError(ctx, n.log, w, http.StatusNotFound, ErrNotificationsAPI.Wrap(err))
			return
		}
		web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNotificationsAPI.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(map[string]string{"message": "Notification dismissed successfully"}); err != nil {
		n.log.Error("failed to encode response", zap.Error(err))
	}
}

func (n *Notifications) convertNotification(notif pushnotifications.PushNotificationRecord) NotificationResponse {
	response := NotificationResponse{
		ID:           notif.ID,
		UserID:       notif.UserID,
		TokenID:      notif.TokenID,
		Title:        notif.Title,
		Body:         notif.Body,
		Data:         notif.Data,
		Status:       notif.Status,
		ErrorMessage: notif.ErrorMessage,
		RetryCount:   notif.RetryCount,
		CreatedAt:    notif.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		IsRead:       pushnotifications.IsRead(notif.Status),
		Hide:         notif.Hide,
	}
	if notif.SentAt != nil {
		sentAtStr := notif.SentAt.Format("2006-01-02T15:04:05Z07:00")
		response.SentAt = &sentAtStr
	}
	return response
}

func (n *Notifications) convertNotifications(notifications []pushnotifications.PushNotificationRecord) []NotificationResponse {
	items := make([]NotificationResponse, 0, len(notifications))
	for _, notif := range notifications {
		items = append(items, n.convertNotification(notif))
	}
	return items
}
