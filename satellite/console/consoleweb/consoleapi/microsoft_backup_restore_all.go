// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// MicrosoftBackupRestoreAll proxies Backup-Tools Microsoft restore-all APIs (/restore/*).
type MicrosoftBackupRestoreAll struct {
	log        *zap.Logger
	service    *console.Service
	cookieAuth *consolewebauth.CookieAuth
}

// NewMicrosoftBackupRestoreAll constructs the Microsoft restore-all HTTP controller.
func NewMicrosoftBackupRestoreAll(log *zap.Logger, service *console.Service, cookieAuth *consolewebauth.CookieAuth) *MicrosoftBackupRestoreAll {
	return &MicrosoftBackupRestoreAll{log: log, service: service, cookieAuth: cookieAuth}
}

func (m *MicrosoftBackupRestoreAll) sessionTokenKey(r *http.Request) (string, error) {
	tokenInfo, err := m.cookieAuth.GetToken(r)
	if err != nil {
		return "", console.ErrUnauthorized.Wrap(err)
	}
	return tokenInfo.Token.String(), nil
}

func (m *MicrosoftBackupRestoreAll) serveJSONError(ctx context.Context, w http.ResponseWriter, err error) {
	(&Auth{log: m.log, service: m.service, cookieAuth: m.cookieAuth}).serveJSONError(ctx, w, err)
}

type microsoftRestoreCronCall func(ctx context.Context, tokenKey string) ([]byte, int, error)

func (m *MicrosoftBackupRestoreAll) restoreCron(w http.ResponseWriter, r *http.Request, call microsoftRestoreCronCall) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	respBody, status, err := call(ctx, tokenKey)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// MicrosoftBackupRestoreAllSwaggerRequest is the body for POST /microsoft-backup/restore/all.
type MicrosoftBackupRestoreAllSwaggerRequest struct {
	Service     string `json:"service"`
	ProjectID   string `json:"project_id"`
	LoginID     string `json:"login_id"`
	TargetEmail string `json:"target_email,omitempty"`
}

// RestorePrepare proxies GET /restore/prepare for Microsoft services.
func (m *MicrosoftBackupRestoreAll) RestorePrepare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := m.service.PrepareMicrosoftBackupRestore(ctx, tokenKey, console.MicrosoftBackupRestorePrepareParams{
		ProjectID:   r.URL.Query().Get("project_id"),
		LoginID:     r.URL.Query().Get("login_id"),
		Service:     r.URL.Query().Get("service"),
		TargetEmail: r.URL.Query().Get("target_email"),
	})
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestoreAll proxies POST /restore/all for Microsoft services.
func (m *MicrosoftBackupRestoreAll) RestoreAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	var body MicrosoftBackupRestoreAllSwaggerRequest
	if err := decodeStrictJSON(r, &body); err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}

	respBody, status, err := m.service.StartMicrosoftBackupRestoreAll(ctx, tokenKey, console.MicrosoftBackupRestoreAllRequest{
		Service:     body.Service,
		ProjectID:   body.ProjectID,
		LoginID:     body.LoginID,
		TargetEmail: body.TargetEmail,
	})
	m.service.RecordUserAuditHTTP(ctx, "MB_RESTORE_INITIATED", "Restore", "Microsoft restore initiated", status, respBody, err)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// RestoreCredentials proxies GET /restore/credentials?provider=microsoft.
func (m *MicrosoftBackupRestoreAll) RestoreCredentials(w http.ResponseWriter, r *http.Request) {
	m.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		return m.service.ListMicrosoftBackupRestoreCredentials(ctx, tokenKey, r.URL.RawQuery)
	})
}

// RestoreWorkspaces proxies GET /restore/workspaces?provider=microsoft.
func (m *MicrosoftBackupRestoreAll) RestoreWorkspaces(w http.ResponseWriter, r *http.Request) {
	m.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		return m.service.ListMicrosoftBackupRestoreWorkspaces(ctx, tokenKey, r.URL.RawQuery)
	})
}

// RestoreLive proxies GET /restore/live.
func (m *MicrosoftBackupRestoreAll) RestoreLive(w http.ResponseWriter, r *http.Request) {
	m.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		return m.service.ProxyMicrosoftBackupRestoreCron(ctx, http.MethodGet, "/restore/live", tokenKey, nil)
	})
}

// RestoreJobs proxies GET /restore/jobs.
func (m *MicrosoftBackupRestoreAll) RestoreJobs(w http.ResponseWriter, r *http.Request) {
	m.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		path := "/restore/jobs"
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		return m.service.ProxyMicrosoftBackupRestoreCron(ctx, http.MethodGet, path, tokenKey, nil)
	})
}

// GetRestoreJob proxies GET /restore/job/{job_id}.
func (m *MicrosoftBackupRestoreAll) GetRestoreJob(w http.ResponseWriter, r *http.Request) {
	m.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		jobID := mux.Vars(r)["job_id"]
		return m.service.ProxyMicrosoftBackupRestoreCron(ctx, http.MethodGet, "/restore/job/"+jobID, tokenKey, nil)
	})
}

// CancelRestoreJob proxies POST /restore/job/{job_id}/cancel.
func (m *MicrosoftBackupRestoreAll) CancelRestoreJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	tokenKey, err := m.sessionTokenKey(r)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	jobID := mux.Vars(r)["job_id"]
	respBody, status, err := m.service.CancelMicrosoftBackupRestoreJob(ctx, tokenKey, jobID)
	if err != nil {
		m.serveJSONError(ctx, w, err)
		return
	}
	writeBackupToolsJSON(w, status, respBody)
}

// ListRestoreDeadItems proxies GET /restore/job/{job_id}/dead-items.
func (m *MicrosoftBackupRestoreAll) ListRestoreDeadItems(w http.ResponseWriter, r *http.Request) {
	m.restoreCron(w, r, func(ctx context.Context, tokenKey string) ([]byte, int, error) {
		jobID := mux.Vars(r)["job_id"]
		return m.service.ProxyMicrosoftBackupRestoreCron(ctx, http.MethodGet, "/restore/job/"+jobID+"/dead-items", tokenKey, nil)
	})
}
