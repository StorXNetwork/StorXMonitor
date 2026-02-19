package consoleapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zeebo/errs"
	"github.com/StorXNetwork/StorXMonitor/private/post"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
)

type EmailWebhook struct {
	service      *console.Service
	config       console.Config
	mailService  *mailservice.Service
	address      string
	supportEmail string
}

func NewEmailWebhook(service *console.Service, mailService *mailservice.Service, config console.Config, address, supportEmail string) *EmailWebhook {
	return &EmailWebhook{
		service:      service,
		mailService:  mailService,
		config:       config,
		address:      address,
		supportEmail: supportEmail,
	}
}

func (a *EmailWebhook) SendEmailByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var requestData struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		a.serveJSONError(w, errs.New("error decoding request body"))
		return
	}

	if requestData.Token == "" {
		a.serveJSONError(w, errs.New("JWT token is required"))
		return
	}

	token, err := jwt.Parse(requestData.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.config.EmailApiKey), nil
	})
	if err != nil {
		a.serveJSONError(w, errs.Wrap(err))
		return
	}

	if !token.Valid {
		a.serveJSONError(w, errs.New("invalid JWT token"))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		a.serveJSONError(w, errs.New("invalid JWT claims"))
		return
	}

	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			a.serveJSONError(w, errs.New("JWT token expired"))
			return
		}
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		a.serveJSONError(w, errs.New("email claim is required"))
		return
	}

	errorMessage, ok := claims["error"].(string)
	if !ok || errorMessage == "" {
		a.serveJSONError(w, errs.New("error claim is required"))
		return
	}

	method, ok := claims["method"].(string)
	if !ok || method == "" {
		a.serveJSONError(w, errs.New("method claim is required"))
		return
	}

	a.mailService.SendRenderedAsync(ctx,
		[]post.Address{{Address: email}},
		&console.AutoBackupFailureEmail{
			Email:  email,
			Error:  errorMessage,
			Method: method,
		},
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "email sent successfully"})
}

// serveJSONError writes JSON error to response output stream.
func (a *EmailWebhook) serveJSONError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
