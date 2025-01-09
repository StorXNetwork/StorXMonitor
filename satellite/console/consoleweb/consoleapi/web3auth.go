package consoleapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/smartcontract"
)

type Web3Auth struct {
	log     *zap.Logger
	service *console.Service

	web3AuthSocialShareHelper smartcontract.SocialShareHelper

	secreteKey string
}

func NewWeb3Auth(log *zap.Logger, service *console.Service, web3AuthSocialShareHelper smartcontract.SocialShareHelper, secreteKey string) *Web3Auth {
	return &Web3Auth{
		log:                       log,
		service:                   service,
		web3AuthSocialShareHelper: web3AuthSocialShareHelper,
		secreteKey:                secreteKey,
	}
}

func (a *Web3Auth) UploadBackupShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	backupIDStr := r.URL.Query().Get("backup_id")
	share, err := io.ReadAll(r.Body)
	if err != nil {
		a.sendError(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if len(share) == 0 || backupIDStr == "" {
		a.sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = a.service.UploadBackupShare(r.Context(), backupIDStr, share)
	if err != nil {
		a.sendError(w, "Error uploading backup share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *Web3Auth) GetBackupShare(w http.ResponseWriter, r *http.Request) {
	backupIDStr := r.URL.Query().Get("backup_id")

	share, err := a.service.GetBackupShare(r.Context(), backupIDStr)
	if err != nil {
		a.sendError(w, "Error getting backup share", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"share":     string(share),
		"backup_id": backupIDStr,
	})
	if err != nil {
		a.sendError(w, "Error encoding backup share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *Web3Auth) UploadSocialShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	id := r.URL.Query().Get("id")
	share, err := io.ReadAll(r.Body)
	if err != nil {
		a.sendError(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if id == "" || len(share) == 0 {
		a.sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = a.web3AuthSocialShareHelper.UploadSocialShare(ctx, id, share)
	if err != nil {
		a.sendError(w, "Error uploading social share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *Web3Auth) GetSocialShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	id := r.URL.Query().Get("id")
	share, err := a.web3AuthSocialShareHelper.GetSocialShare(ctx, id)
	if err != nil {
		a.sendError(w, "Error getting social share", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"share": string(share),
		"id":    id,
	})
	if err != nil {
		a.sendError(w, "Error encoding social share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *Web3Auth) GetSignMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	email := r.URL.Query().Get("email")
	if email == "" {
		a.sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, _, err := a.service.GetUserByEmailWithUnverified(ctx, email)
	if err != nil {
		a.sendError(w, "Error getting user", http.StatusInternalServerError)
		return
	}

	if user == nil {
		a.sendError(w, "User not found", http.StatusNotFound)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"nonce": strconv.FormatInt(time.Now().Unix(), 10),
		"exp":   strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10),
	})
	tokenString, err := token.SignedString([]byte(a.secreteKey))
	if err != nil {
		a.sendError(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
	if err != nil {
		a.sendError(w, "Error encoding sign message", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *Web3Auth) verifyToken(token string) (bool, error) {
	return true, nil
}

func (a *Web3Auth) sendError(w http.ResponseWriter, err string, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": err,
	})
}
