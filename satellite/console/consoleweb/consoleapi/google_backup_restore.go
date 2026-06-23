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

func (g *GoogleBackupRestore) googleAuthFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Google-Auth")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("Google-Auth")); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("Authorization"))
}

func (g *GoogleBackupRestore) parseManualRestoreRequest(r *http.Request) (console.GoogleBackupManualRestoreRequest, error) {
	googleAuth := g.googleAuthFromRequest(r)

	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			return console.GoogleBackupManualRestoreRequest{}, console.ErrValidation.New("invalid request body")
		}
		keys := r.MultipartForm.Value["keys"]
		if len(keys) == 0 {
			keys = r.MultipartForm.Value["ids"]
		}
		return console.GoogleBackupManualRestoreRequest{
			GoogleAuth: googleAuth,
			Keys:       keys,
		}, nil
	}

	var body GoogleBackupManualRestoreSwaggerRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		return console.GoogleBackupManualRestoreRequest{}, err
	}
	keys := body.Keys
	if len(keys) == 0 {
		keys = body.IDs
	}
	return console.GoogleBackupManualRestoreRequest{
		GoogleAuth: googleAuth,
		Keys:       keys,
	}, nil
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

type restoreCronCall func(ctx context.Context, tokenKey string) ([]byte, int, error)

func (g *GoogleBackupRestore) restoreCron(w http.ResponseWriter, r *http.Request, call restoreCronCall) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := call(ctx, tokenKey)
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

	req, err := g.parseManualRestoreRequest(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := g.service.GoogleBackupManualRestore(ctx, tokenKey, backupToolsPath, req)
	g.service.RecordUserAuditHTTP(ctx, "GB_MANUAL_RESTORE", "Manual restore", "Manual restore completed", status, respBody, err)
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
	g.service.RecordUserAuditHTTP(ctx, "GB_RESTORE_AUTH", "Google restore auth", "Google restore authentication completed", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestorePrepare runs pre-flight checks before restore-all (Backup-Tools GET /restore/prepare).
//
// @Summary      Pre-flight restore-all check
// @Description  **Full route:** `GET /api/v0/google-backup/restore/prepare`
//
// Proxies Backup-Tools `GET /restore/prepare` with `token_key` only. Flat response (not success/failed envelope). `auth_mode` is computed (`oauth` vs `dwd`). UI `service` param maps to DB `method` on job rows (e.g. drive → google_drive).
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        project_id  query  string  true  "Storj/Satellite project public UUID"
// @Param        login_id    query  string  true  "Mailbox email (same as policy UI)"
// @Param        service     query  string  true  "gmail, drive, photos, calendar, or contacts"
// @Success      200         {object}  RestorePrepareSwaggerResponse
// @Failure      400         {object}  SwaggerErrorResponse
// @Failure      401         {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/prepare [get]
func (g *GoogleBackupRestore) RestorePrepare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.PrepareGoogleBackupRestore(ctx, tokenKey, console.GoogleBackupRestorePrepareParams{
		ProjectID: r.URL.Query().Get("project_id"),
		LoginID:   r.URL.Query().Get("login_id"),
		Service:   r.URL.Query().Get("service"),
	})
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestoreAll starts an async restore-all job on Backup-Tools.
//
// @Summary      Start restore-all job
// @Description  **Full route:** `POST /api/v0/google-backup/restore/all`
//
// Proxies Backup-Tools `POST /restore/all` with `token_key` only. Body: `project_id`, `login_id`, `service`. Call `GET /restore/prepare` first. **409** when an active restore exists for the same user + service + login_id. **422** returns the same flat body as prepare when `ready: false`.
// @Tags         google-backup-restore-cron
// @Accept       json
// @Produce      json
// @Param        body  body      GoogleBackupRestoreAllSwaggerRequest  true  "Restore-all request"
// @Success      202   {object}  RestoreAllQueuedSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      409   {object}  SwaggerErrorResponse
// @Failure      422   {object}  RestorePrepareSwaggerResponse
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
		Service:   body.Service,
		ProjectID: body.ProjectID,
		LoginID:   body.LoginID,
	})
	g.service.RecordUserAuditHTTP(ctx, "GB_RESTORE_INITIATED", "Restore", "Restore initiated", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestoreLive lists running restore jobs (Backup-Tools GET /restore/live).
//
// @Summary      List active restore jobs
// @Description  **Full route:** `GET /api/v0/google-backup/restore/live`
//
// Proxies Backup-Tools `GET /restore/live` with `token_key` only. Response envelope: `{ message, success, failed }` (autosync style). Poll every 5–30s while jobs run. Use `success[].total`, `processed`, `progress_percent` for progress bars.
// @Tags         google-backup-restore-cron
// @Produce      json
// @Success      200  {object}  RestoreLiveSwaggerResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/live [get]
func (g *GoogleBackupRestore) RestoreLive(w http.ResponseWriter, r *http.Request) {
	g.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, "/restore/live", tokenKey, nil)
	})
}

// RestoreJobs lists recent restore jobs.
//
// @Summary      List restore job history
// @Description  **Full route:** `GET /api/v0/google-backup/restore/jobs`
//
// Proxies Backup-Tools `GET /restore/jobs` with `token_key` only. Response envelope: `{ message, success, failed }`. List items are metadata only (no progress counters — use `/restore/live` or `/restore/job/{job_id}`). Use top-level `login_id` (not `input_data.email`). DB field is `method` (not `service`).
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        service    query  string  false  "UI service filter: gmail, drive, photos, calendar, contacts"
// @Param        method     query  string  false  "Internal method alias (google_drive, etc.)"
// @Param        status     query  string  false  "queued, running, completed, partial_completed, failed, cancelled"
// @Param        search     query  string  false  "Partial match on login_id"
// @Param        email      query  string  false  "Alias for search (partial login_id)"
// @Param        from_time  query  string  false  "Created-at range start (YYYY-MM-DD or RFC3339)"
// @Param        to_time    query  string  false  "Created-at range end (YYYY-MM-DD end-of-day or RFC3339)"
// @Param        limit      query  string  false  "Max jobs (default 20, max 100)"
// @Param        offset     query  string  false  "Pagination offset"
// @Success      200        {object}  RestoreJobListSwaggerResponse
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/jobs [get]
func (g *GoogleBackupRestore) RestoreJobs(w http.ResponseWriter, r *http.Request) {
	g.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		path := "/restore/jobs"
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, path, tokenKey, nil)
	})
}

// GetRestoreJob returns one restore job by id.
//
// @Summary      Get restore job status
// @Description  **Full route:** `GET /api/v0/google-backup/restore/job/{job_id}`
//
// Proxies Backup-Tools `GET /restore/job/{job_id}` with `token_key` only. Response envelope: `{ message, success: [detail], failed }`. Detail includes progress (`total`, `processed`, `failed`, `progress_percent`) and `message_status`.
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        job_id  path  string  true  "Restore job ID"
// @Success      200     {object}  RestoreJobDetailSwaggerResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Failure      404     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/job/{job_id} [get]
func (g *GoogleBackupRestore) GetRestoreJob(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]
	g.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, "/restore/job/"+jobID, tokenKey, nil)
	})
}

// CancelRestoreJob cancels a restore job.
//
// @Summary      Cancel restore job
// @Description  **Full route:** `POST /api/v0/google-backup/restore/job/{job_id}/cancel`
//
// Proxies Backup-Tools `POST /restore/job/{job_id}/cancel` with `token_key` only. Sets job `status=cancelled` and `message_status=error`.
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        job_id  path  string  true  "Restore job ID"
// @Success      200     {object}  RestoreCancelSwaggerResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/job/{job_id}/cancel [post]
func (g *GoogleBackupRestore) CancelRestoreJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	jobID := mux.Vars(r)["job_id"]
	tokenKey, err := g.sessionTokenKey(r)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := g.service.CancelGoogleBackupRestoreJob(ctx, tokenKey, jobID)
	g.service.RecordUserAuditHTTP(ctx, "GB_RESTORE_CANCEL", "Restore job", "Restore job cancelled", status, respBody, err)
	if err != nil {
		g.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListRestoreDeadItems lists failed object keys for a job.
//
// @Summary      List restore dead-letter items
// @Description  **Full route:** `GET /api/v0/google-backup/restore/job/{job_id}/dead-items`
//
// Proxies Backup-Tools `GET /restore/job/{job_id}/dead-items` with `token_key` only. Returns `{ items: [...] }` DLQ rows.
// @Tags         google-backup-restore-cron
// @Produce      json
// @Param        job_id  path  string  true  "Restore job ID"
// @Success      200     {object}  RestoreDeadItemsSwaggerResponse
// @Failure      401     {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/restore/job/{job_id}/dead-items [get]
func (g *GoogleBackupRestore) ListRestoreDeadItems(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]
	g.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		return g.service.ProxyGoogleBackupRestoreCron(ctx, http.MethodGet, "/restore/job/"+jobID+"/dead-items", tokenKey, nil)
	})
}

// ManualRestoreGmail proxies Backup-Tools POST /google/gmail/insert-mail.
//
// @Summary      Manual restore Gmail messages
// @Description  Proxies Backup-Tools POST /google/gmail/insert-mail. Single or multiple items (max 10 per request): send base64 vault keys in body `keys` or `ids` (from GET /google-backup/backup-restore/logs). Call POST /google-backup/google-auth first. `Authorization` header = Backup-Tools JWT. Session cookie → `token_key`. No `ACCESS_TOKEN` (StorX from DB).
// @Tags         google-backup-restore-manual
// @Accept       json
// @Accept       multipart/form-data
// @Produce      json
// @Param        Authorization  header  string  true  "Backup-Tools JWT from POST /google-backup/google-auth"
// @Param        body           body     GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys: one item in array for single restore, up to 10 for batch"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      400            {object}  SwaggerErrorResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/gmail/insert-mail [post]
func (g *GoogleBackupRestore) ManualRestoreGmail(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/gmail/insert-mail")
}

// ManualRestoreDrive proxies Backup-Tools POST /google/satellite-to-drive.
//
// @Summary      Manual restore Google Drive
// @Description  Proxies Backup-Tools POST /google/satellite-to-drive. Single or multiple items (max 10): body `keys` or `ids`. Authorization = Backup-Tools JWT. No ACCESS_TOKEN.
// @Tags         google-backup-restore-manual
// @Accept       json
// @Accept       multipart/form-data
// @Produce      json
// @Param        Authorization  header  string  true  "Backup-Tools JWT from POST /google-backup/google-auth"
// @Param        body           body     GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys (1–10)"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      400            {object}  SwaggerErrorResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-drive [post]
func (g *GoogleBackupRestore) ManualRestoreDrive(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-drive")
}

// ManualRestorePhotos proxies Backup-Tools POST /google/satellite-to-photos.
//
// @Summary      Manual restore Google Photos
// @Description  Proxies Backup-Tools POST /google/satellite-to-photos. Single or multiple items (max 10): body `keys` or `ids`. Authorization = Backup-Tools JWT. No ACCESS_TOKEN.
// @Tags         google-backup-restore-manual
// @Accept       json
// @Accept       multipart/form-data
// @Produce      json
// @Param        Authorization  header  string  true  "Backup-Tools JWT from POST /google-backup/google-auth"
// @Param        body           body     GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys (1–10)"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      400            {object}  SwaggerErrorResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-photos [post]
func (g *GoogleBackupRestore) ManualRestorePhotos(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-photos")
}

// ManualRestoreCalendar proxies Backup-Tools POST /google/satellite-to-calendar.
//
// @Summary      Manual restore Google Calendar
// @Description  Proxies Backup-Tools POST /google/satellite-to-calendar. Single or multiple items (max 10): body `keys` or `ids`. Authorization = Backup-Tools JWT. No ACCESS_TOKEN.
// @Tags         google-backup-restore-manual
// @Accept       json
// @Accept       multipart/form-data
// @Produce      json
// @Param        Authorization  header  string  true  "Backup-Tools JWT from POST /google-backup/google-auth"
// @Param        body           body     GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys (1–10)"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      400            {object}  SwaggerErrorResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-calendar [post]
func (g *GoogleBackupRestore) ManualRestoreCalendar(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-calendar")
}

// ManualRestoreContacts proxies Backup-Tools POST /google/satellite-to-contacts.
//
// @Summary      Manual restore Google Contacts
// @Description  Proxies Backup-Tools POST /google/satellite-to-contacts. Single or multiple items (max 10): body `keys` or `ids`. Authorization = Backup-Tools JWT. No ACCESS_TOKEN.
// @Tags         google-backup-restore-manual
// @Accept       json
// @Accept       multipart/form-data
// @Produce      json
// @Param        Authorization  header  string  true  "Backup-Tools JWT from POST /google-backup/google-auth"
// @Param        body           body     GoogleBackupManualRestoreSwaggerRequest  true  "Vault keys (1–10)"
// @Success      200            {object}  BackupToolsJSONResponse
// @Failure      400            {object}  SwaggerErrorResponse
// @Failure      401            {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /google-backup/google/satellite-to-contacts [post]
func (g *GoogleBackupRestore) ManualRestoreContacts(w http.ResponseWriter, r *http.Request) {
	g.manualRestoreBatch(w, r, "/google/satellite-to-contacts")
}
