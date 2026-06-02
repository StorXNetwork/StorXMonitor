// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// GoogleBackupRestore proxies Backup-Tools restore-all APIs (/google-auth, /restore/*).
type GoogleBackupRestore struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewGoogleBackupRestore constructs a restore HTTP controller.
func NewGoogleBackupRestore(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *GoogleBackupRestore {
	return &GoogleBackupRestore{
		log:        log,
		service:    service,
		cookieAuth: cookieAuth,
	}
}

func (g *GoogleBackupRestore) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := g.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (g *GoogleBackupRestore) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: g.log, service: g.service, cookieAuth: g.cookieAuth}).serveJSONError(ctx, w, err)
}

func (g *GoogleBackupRestore) googleAuthFromRequest(r *http.Request, bodyAuth string) string {
	if v := strings.TrimSpace(bodyAuth); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Google-Auth")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("Google-Auth")); v != "" {
		return v
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return auth
}

func (g *GoogleBackupRestore) storxGrantFromRequest(r *http.Request, bodyGrant string) string {
	if v := strings.TrimSpace(bodyGrant); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Storx-Access-Grant")); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("Storx-Access-Grant"))
}

func decodeStrictJSON(r *http.Request, dest interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return console.ErrValidation.New("invalid request body")
	}
	if dec.More() {
		return console.ErrValidation.New("invalid request body")
	}
	return nil
}

type restoreCronCall func(ctx context.Context, tokenKey, googleAuth string) ([]byte, int, error)

func (g *GoogleBackupRestore) restoreCron(w http.ResponseWriter, r *http.Request, call restoreCronCall) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	googleAuth := g.googleAuthFromRequest(r, "")
	if googleAuth == "" {
		g.serveJSONError(ctx, w, console.ErrValidation.New("google_auth is required (X-Google-Auth header)"))
		return
	}

	respBody, status, err := call(ctx, tokenKey, googleAuth)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

func (g *GoogleBackupRestore) manualRestoreBatch(w http.ResponseWriter, r *http.Request, backupToolsPath string) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var body GoogleBackupManualRestoreSwaggerRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	req := console.GoogleBackupManualRestoreRequest{
		StorxAccessGrant: g.storxGrantFromRequest(r, body.StorxAccessGrant),
		GoogleAuth:       g.googleAuthFromRequest(r, body.GoogleAuth),
		Keys:             body.Keys,
	}
	respBody, status, err := g.service.GoogleBackupManualRestore(ctx, tokenKey, backupToolsPath, req)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// GoogleAuth exchanges google_key for Backup-Tools google-auth JWT.
//
// @Summary      Exchange Google token for Backup-Tools auth JWT
// @Description  Proxies Backup-Tools POST /google-auth. Call before restore-all or manual restore. Pass Google OAuth id_token or access_token as google_key.
// @Tags         google-backup-auth
// @Accept       json
// @Produce      json
// @Param        body  body      GoogleBackupAuthSwaggerRequest  true  "Google OAuth token"
// @Success      200   {object}  GoogleBackupAuthSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google-auth [post]
func (g *GoogleBackupRestore) GoogleAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var body GoogleBackupAuthSwaggerRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.BackupToolsGoogleAuth(ctx, body.GoogleKey)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestoreAll starts an async restore-all job on Backup-Tools.
//
// @Summary      Start restore-all job
// @Description  Proxies Backup-Tools POST /restore/all. Requires google_auth JWT (from POST /google-backup/google-auth), storx_access_grant, and login_id matching the Google account. Worker picks up job within ~30s.
// @Tags         google-backup-restore-cron
// @Accept       json
// @Produce      json
// @Param        body  body      GoogleBackupRestoreAllSwaggerRequest  true  "Restore-all request"
// @Success      202   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      409   {object}  BackupToolsJSONResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/all [post]
func (g *GoogleBackupRestore) RestoreAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	var body GoogleBackupRestoreAllSwaggerRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.StartGoogleBackupRestoreAll(ctx, tokenKey, console.GoogleBackupRestoreAllRequest{
		Service:          body.Service,
		LoginID:          body.LoginID,
		StorxAccessGrant: g.storxGrantFromRequest(r, body.StorxAccessGrant),
		GoogleAuth:       g.googleAuthFromRequest(r, body.GoogleAuth),
	})
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestoreLive lists running restore jobs (Backup-Tools GET /restore/live).
//
// @Summary      List active restore jobs
// @Description  Proxies Backup-Tools GET /restore/live (running jobs only). Pass google_auth in X-Google-Auth header.
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        X-Google-Auth  header  string  true  "Backup-Tools google-auth JWT"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/live [get]
func (g *GoogleBackupRestore) RestoreLive(w http.ResponseWriter, r *http.Request) {
	g.restoreCron(w, r, func(ctx context.Context, tokenKey, googleAuth string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, "/restore/live", tokenKey, googleAuth, nil)
	})
}

// RestoreJobs lists recent restore jobs.
//
// @Summary      List restore job history
// @Description  Proxies Backup-Tools GET /restore/jobs
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        limit          query   string  false  "Max jobs (default 20)"
// @Param        X-Google-Auth  header  string  true   "Backup-Tools google-auth JWT"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/jobs [get]
func (g *GoogleBackupRestore) RestoreJobs(w http.ResponseWriter, r *http.Request) {
	limit := strings.TrimSpace(r.URL.Query().Get("limit"))
	g.restoreCron(w, r, func(ctx context.Context, tokenKey, googleAuth string) ([]byte, int, error) {
		path := "/restore/jobs"
		if limit != "" {
			path += "?limit=" + limit
		}
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, path, tokenKey, googleAuth, nil)
	})
}

// GetRestoreJob returns one restore job by id.
//
// @Summary      Get restore job status
// @Description  Proxies Backup-Tools GET /restore/job/{job_id} (use after POST /restore/all while status is queued)
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        job_id         path    string  true  "Restore job ID"
// @Param        X-Google-Auth  header  string  true  "Backup-Tools google-auth JWT"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Failure      404            {object}  BackupToolsJSONResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/job/{job_id} [get]
func (g *GoogleBackupRestore) GetRestoreJob(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]
	g.restoreCron(w, r, func(ctx context.Context, tokenKey, googleAuth string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, "/restore/job/"+jobID, tokenKey, googleAuth, nil)
	})
}

// CancelRestoreJob cancels a restore job.
//
// @Summary      Cancel restore job
// @Description  Proxies Backup-Tools POST /restore/job/{job_id}/cancel
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        job_id         path    string  true  "Restore job ID"
// @Param        X-Google-Auth  header  string  true  "Backup-Tools google-auth JWT"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/job/{job_id}/cancel [post]
func (g *GoogleBackupRestore) CancelRestoreJob(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]
	g.restoreCron(w, r, func(ctx context.Context, tokenKey, googleAuth string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodPost, "/restore/job/"+jobID+"/cancel", tokenKey, googleAuth, nil)
	})
}

// ListRestoreDeadItems lists failed object keys for a job.
//
// @Summary      List restore dead-letter items
// @Description  Proxies Backup-Tools GET /restore/job/{job_id}/dead-items
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        job_id         path    string  true  "Restore job ID"
// @Param        X-Google-Auth  header  string  true  "Backup-Tools google-auth JWT"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/job/{job_id}/dead-items [get]
func (g *GoogleBackupRestore) ListRestoreDeadItems(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]
	g.restoreCron(w, r, func(ctx context.Context, tokenKey, googleAuth string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, "/restore/job/"+jobID+"/dead-items", tokenKey, googleAuth, nil)
	})
}

// ManualRestoreGmail proxies Backup-Tools POST /google/gmail/insert-mail.
//
// @Summary      Manual restore Gmail messages
// @Description  Proxies Backup-Tools POST /google/gmail/insert-mail (max 10 base64 vault keys). Requires POST /google-backup/google-auth first. Headers: Authorization, ACCESS_TOKEN (or body fields).
// @Tags         google-backup-restore-manual
// @Accept       json
// @Produce      json
// @Param        body  body  GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys (forwarded as JSON array to Backup-Tools)"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/gmail/insert-mail [post]
func (g *GoogleBackupRestore) ManualRestoreGmail(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/gmail/insert-mail")
}

// ManualRestoreDrive proxies Backup-Tools POST /google/satellite-to-drive.
//
// @Summary      Manual restore Google Drive
// @Description  Proxies Backup-Tools POST /google/satellite-to-drive (max 10 base64 vault keys).
// @Tags         google-backup-restore-manual
// @Accept       json
// @Produce      json
// @Param        body  body  GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-drive [post]
func (g *GoogleBackupRestore) ManualRestoreDrive(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-drive")
}

// ManualRestorePhotos proxies Backup-Tools POST /google/satellite-to-photos.
//
// @Summary      Manual restore Google Photos
// @Description  Proxies Backup-Tools POST /google/satellite-to-photos (max 10 base64 vault keys).
// @Tags         google-backup-restore-manual
// @Accept       json
// @Produce      json
// @Param        body  body  GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-photos [post]
func (g *GoogleBackupRestore) ManualRestorePhotos(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-photos")
}

// ManualRestoreCalendar proxies Backup-Tools POST /google/satellite-to-calendar.
//
// @Summary      Manual restore Google Calendar
// @Description  Proxies Backup-Tools POST /google/satellite-to-calendar (max 10 base64 vault keys).
// @Tags         google-backup-restore-manual
// @Accept       json
// @Produce      json
// @Param        body  body  GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-calendar [post]
func (g *GoogleBackupRestore) ManualRestoreCalendar(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-calendar")
}

// ManualRestoreContacts proxies Backup-Tools POST /google/satellite-to-contacts.
//
// @Summary      Manual restore Google Contacts
// @Description  Proxies Backup-Tools POST /google/satellite-to-contacts (max 10 base64 vault keys).
// @Tags         google-backup-restore-manual
// @Accept       json
// @Produce      json
// @Param        body  body  GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys"
// @Success      200   {object}  BackupToolsJSONResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-contacts [post]
func (g *GoogleBackupRestore) ManualRestoreContacts(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-contacts")
}
