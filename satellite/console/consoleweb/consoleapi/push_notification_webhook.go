// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zeebo/errs"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/pushnotifications"
)

type PushNotificationWebhook struct {
	service      *console.Service
	config       console.Config
	pushService  *pushnotifications.Service
	address      string
	supportEmail string
}

func NewPushNotificationWebhook(service *console.Service, pushService *pushnotifications.Service, config console.Config, address, supportEmail string) *PushNotificationWebhook {
	return &PushNotificationWebhook{
		service:      service,
		pushService:  pushService,
		config:       config,
		address:      address,
		supportEmail: supportEmail,
	}
}

func (p *PushNotificationWebhook) SendNotification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var requestData struct{ Token string }
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		p.serveJSONError(w, errs.New("error decoding request body"))
		return
	}

	if requestData.Token == "" {
		p.serveJSONError(w, errs.New("JWT token is required"))
		return
	}

	token, err := jwt.Parse(requestData.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.config.EmailApiKey), nil
	})
	if err != nil || !token.Valid {
		p.serveJSONError(w, errs.Wrap(err))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		p.serveJSONError(w, errs.New("invalid JWT claims"))
		return
	}

	// Validate required claims
	required := map[string]string{
		"user_id": claims["user_id"].(string),
		"title":   claims["title"].(string),
		"body":    claims["body"].(string),
	}
	for field, value := range required {
		if value == "" {
			p.serveJSONError(w, errs.New(field+" claim is required"))
			return
		}
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		p.serveJSONError(w, errs.New("JWT token expired"))
		return
	}

	userID, err := uuid.FromString(required["user_id"])
	if err != nil {
		p.serveJSONError(w, errs.Wrap(err))
		return
	}

	// Build notification
	notification := pushnotifications.Notification{
		Title:    required["title"],
		Body:     required["body"],
		Data:     make(map[string]string),
		Priority: "normal",
	}

	// Set optional fields
	if priority, ok := claims["priority"].(string); ok && (priority == "high" || priority == "normal") {
		notification.Priority = priority
	}
	if imageURL, ok := claims["image_url"].(string); ok && imageURL != "" {
		notification.ImageURL = imageURL
	}
	if dataClaim, ok := claims["data"].(map[string]interface{}); ok {
		for k, v := range dataClaim {
			if strVal, ok := v.(string); ok {
				notification.Data[k] = strVal
			}
		}
	}

	// Send push notification
	if err := p.service.SendPushNotification(ctx, userID, notification); err != nil {
		p.serveJSONError(w, errs.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "push notification sent successfully"})
}

// serveJSONError writes JSON error to response output stream.
func (p *PushNotificationWebhook) serveJSONError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
