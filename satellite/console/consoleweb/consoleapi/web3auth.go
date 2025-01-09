package consoleapi

import (
	"encoding/json"
	"io"
	"net/http"

	"go.uber.org/zap"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/smartcontract"
)

type Web3Auth struct {
	log     *zap.Logger
	service *console.Service

	web3AuthSocialShareHelper smartcontract.SocialShareHelper
}

func NewWeb3Auth(log *zap.Logger, service *console.Service, web3AuthSocialShareHelper smartcontract.SocialShareHelper) *Web3Auth {
	return &Web3Auth{
		log:                       log,
		service:                   service,
		web3AuthSocialShareHelper: web3AuthSocialShareHelper,
	}
}

func (a *Web3Auth) UploadBackupShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	backupIDStr := r.URL.Query().Get("backup_id")
	share, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if len(share) == 0 || backupIDStr == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = a.service.UploadBackupShare(r.Context(), backupIDStr, share)
	if err != nil {
		http.Error(w, "Error uploading backup share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *Web3Auth) GetBackupShare(w http.ResponseWriter, r *http.Request) {
	backupIDStr := r.URL.Query().Get("backup_id")

	share, err := a.service.GetBackupShare(r.Context(), backupIDStr)
	if err != nil {
		http.Error(w, "Error getting backup share: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"share":     string(share),
		"backup_id": backupIDStr,
	})
	if err != nil {
		http.Error(w, "Error encoding backup share", http.StatusInternalServerError)
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
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if id == "" || len(share) == 0 {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = a.web3AuthSocialShareHelper.UploadSocialShare(ctx, id, share)
	if err != nil {
		http.Error(w, "Error uploading social share", http.StatusInternalServerError)
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
		http.Error(w, "Error getting social share", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"share": string(share),
		"id":    id,
	})
	if err != nil {
		http.Error(w, "Error encoding social share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
