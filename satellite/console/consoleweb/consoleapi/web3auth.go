package consoleapi

import (
	"encoding/json"
	"io"
	"net/http"

	"go.uber.org/zap"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
)

type Web3Auth struct {
	log     *zap.Logger
	service *console.Service
}

func NewWeb3Auth(log *zap.Logger, service *console.Service) *Web3Auth {
	return &Web3Auth{
		log:     log,
		service: service,
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

	backupID, err := uuid.FromString(backupIDStr)
	if err != nil {
		http.Error(w, "Error parsing backup ID", http.StatusInternalServerError)
		return
	}

	err = a.service.UploadBackupShare(r.Context(), backupID, share)
	if err != nil {
		http.Error(w, "Error uploading backup share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *Web3Auth) GetBackupShare(w http.ResponseWriter, r *http.Request) {
	backupIDStr := r.URL.Query().Get("backup_id")
	backupID, err := uuid.FromString(backupIDStr)
	if err != nil {
		http.Error(w, "Error parsing backup ID", http.StatusInternalServerError)
		return
	}

	share, err := a.service.GetBackupShare(r.Context(), backupID)
	if err != nil {
		http.Error(w, "Error getting backup share", http.StatusInternalServerError)
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
