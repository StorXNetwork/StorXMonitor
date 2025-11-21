// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consoleapi/utils"
)

var ErrNewsletterAPI = errs.Class("consoleapi newsletter error")

type Newsletter struct {
	log     *zap.Logger
	service *console.Service
}

func NewNewsletter(log *zap.Logger, service *console.Service) *Newsletter {
	return &Newsletter{log: log, service: service}
}

type NewsletterRequest struct {
	Email string `json:"email"`
}
type NewsletterResponse struct {
	Email   string `json:"email"`
	Status  int    `json:"status,omitempty"`
	Message string `json:"message"`
}

// HandleSubscription handles POST /api/v0/newsletter/{action}
// Path param {action} can be "subscribe" or "unsubscribe"
func (n *Newsletter) HandleSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	action := mux.Vars(r)["action"]
	if action != "subscribe" && action != "unsubscribe" {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest,
			ErrNewsletterAPI.New("invalid action. must be 'subscribe' or 'unsubscribe'"))
		return
	}

	var req NewsletterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNewsletterAPI.Wrap(err))
		return
	}

	if req.Email == "" {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNewsletterAPI.New("email is required"))
		return
	}

	if !utils.ValidateEmail(req.Email) {
		web.ServeJSONError(ctx, n.log, w, http.StatusBadRequest, ErrNewsletterAPI.New("invalid email format"))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch action {
	case "subscribe":
		subscription, err := n.service.SubscribeNewsletter(ctx, req.Email)
		if err != nil {
			web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNewsletterAPI.Wrap(err))
			return
		}
		json.NewEncoder(w).Encode(NewsletterResponse{
			Email:   subscription.Email,
			Status:  subscription.Status,
			Message: "Successfully subscribed to newsletter",
		})

	case "unsubscribe":
		if err := n.service.UnsubscribeNewsletter(ctx, req.Email); err != nil {
			web.ServeJSONError(ctx, n.log, w, http.StatusInternalServerError, ErrNewsletterAPI.Wrap(err))
			return
		}
		json.NewEncoder(w).Encode(NewsletterResponse{
			Email:   req.Email,
			Message: "Successfully unsubscribed from newsletter",
		})
	}
}
