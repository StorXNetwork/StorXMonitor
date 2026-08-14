// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

// MailExportJobs serves gateway-mt internal mail-export job and quota routes.
type MailExportJobs struct {
	log          *zap.Logger
	service      *console.Service
	serviceToken string
}

// NewMailExportJobs constructs the internal mail export HTTP controller.
func NewMailExportJobs(log *zap.Logger, service *console.Service, serviceToken string) *MailExportJobs {
	return &MailExportJobs{
		log:          log,
		service:      service,
		serviceToken: serviceToken,
	}
}

type createMailExportJobRequest struct {
	ID          string   `json:"id"`
	UserID      string   `json:"userId"`
	ProjectID   string   `json:"projectId"`
	AccessKeyID string   `json:"accessKeyId"`
	Bucket      string   `json:"bucket"`
	Format      string   `json:"format"`
	Mode        string   `json:"mode"`
	Prefix      string   `json:"prefix,omitempty"`
	Keys        []string `json:"keys,omitempty"`
	TotalFiles  int64    `json:"totalFiles,omitempty"`
	TotalBytes  int64    `json:"totalBytes,omitempty"`
	AccessGrant string   `json:"accessGrant,omitempty"`
}

type patchMailExportJobRequest struct {
	Status         *string    `json:"status,omitempty"`
	RetryCount     *int       `json:"retryCount,omitempty"`
	Progress       *int       `json:"progress,omitempty"`
	ProcessedFiles *int64     `json:"processedFiles,omitempty"`
	TotalFiles     *int64     `json:"totalFiles,omitempty"`
	ProcessedBytes *int64     `json:"processedBytes,omitempty"`
	TotalBytes     *int64     `json:"totalBytes,omitempty"`
	CurrentObject  *string    `json:"currentObject,omitempty"`
	ArchiveBucket  *string    `json:"archiveBucket,omitempty"`
	ArchiveKey     *string    `json:"archiveKey,omitempty"`
	ArchiveName    *string    `json:"archiveName,omitempty"`
	ErrorMessage   *string    `json:"errorMessage,omitempty"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
}

type requeueStaleRequest struct {
	OlderThan string `json:"olderThan"`
}

type expireJobsResponse struct {
	Jobs []console.MailExportJob `json:"jobs"`
}

type requeueStaleResponse struct {
	Count int `json:"count"`
}

type bandwidthQuotaRequest struct {
	AccessKeyID string `json:"accessKeyId,omitempty"`
	AccessGrant string `json:"accessGrant,omitempty"`
	UserID      string `json:"userId,omitempty"`
	ProjectID   string `json:"projectId,omitempty"`
}

type bandwidthQuotaResponse struct {
	AvailableBytes int64 `json:"availableBytes"`
}

type bandwidthUsageRequest struct {
	AccessGrant string `json:"accessGrant"`
	Bytes       int64  `json:"bytes"`
	JobID       string `json:"jobId"`
	ChargeID    string `json:"chargeId"`
}

type bandwidthUsageResponse struct {
	ChargedBytes   int64 `json:"chargedBytes"`
	AlreadyCharged bool  `json:"alreadyCharged"`
}

type mailExportErrorResponse struct {
	Error string `json:"error,omitempty"`
}

func (h *MailExportJobs) validateBearerToken(r *http.Request) bool {
	expected := strings.TrimSpace(h.serviceToken)
	if expected == "" {
		return false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (h *MailExportJobs) writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.log.Error("failed to encode mail export response", zap.Error(err))
	}
}

func (h *MailExportJobs) writeUnauthorized(w http.ResponseWriter) {
	h.writeJSON(w, http.StatusUnauthorized, mailExportErrorResponse{Error: "unauthorized"})
}

func (h *MailExportJobs) writeServiceError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if console.ErrMailExportJobNotFound.Has(err) {
		status = http.StatusNotFound
	} else if console.ErrValidation.Has(err) {
		status = http.StatusBadRequest
	}
	if status >= 500 {
		h.log.Debug("mail export request failed", zap.Error(err))
	}
	h.writeJSON(w, status, mailExportErrorResponse{Error: err.Error()})
}

// Create handles POST /api/v0/internal/mail-export-jobs.
func (h *MailExportJobs) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	var body createMailExportJobRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&body); err != nil {
		h.writeJSON(w, http.StatusBadRequest, mailExportErrorResponse{Error: "invalid request body"})
		return
	}

	job, err := h.service.CreateMailExportJob(ctx, console.CreateMailExportJob{
		ID:          body.ID,
		UserID:      body.UserID,
		ProjectID:   body.ProjectID,
		AccessKeyID: body.AccessKeyID,
		Bucket:      body.Bucket,
		Format:      body.Format,
		Mode:        body.Mode,
		Prefix:      body.Prefix,
		Keys:        body.Keys,
		TotalFiles:  body.TotalFiles,
		TotalBytes:  body.TotalBytes,
		AccessGrant: body.AccessGrant,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, job)
}

// Get handles GET /api/v0/internal/mail-export-jobs/{id}.
func (h *MailExportJobs) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	id := mux.Vars(r)["id"]
	job, err := h.service.GetMailExportJob(ctx, id)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, job)
}

// Claim handles POST /api/v0/internal/mail-export-jobs/claim.
func (h *MailExportJobs) Claim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	job, err := h.service.ClaimMailExportJob(ctx)
	if err != nil {
		if console.ErrMailExportJobNotFound.Has(err) {
			// Empty queue is normal worker polling — GMT treats 404 as "no job".
			h.writeJSON(w, http.StatusNotFound, mailExportErrorResponse{Error: "no queued jobs"})
			return
		}
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, job)
}

// Patch handles PATCH /api/v0/internal/mail-export-jobs/{id}.
func (h *MailExportJobs) Patch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	var body patchMailExportJobRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&body); err != nil {
		h.writeJSON(w, http.StatusBadRequest, mailExportErrorResponse{Error: "invalid request body"})
		return
	}

	id := mux.Vars(r)["id"]
	job, err := h.service.PatchMailExportJob(ctx, id, console.PatchMailExportJob{
		Status:         body.Status,
		RetryCount:     body.RetryCount,
		Progress:       body.Progress,
		ProcessedFiles: body.ProcessedFiles,
		TotalFiles:     body.TotalFiles,
		ProcessedBytes: body.ProcessedBytes,
		TotalBytes:     body.TotalBytes,
		CurrentObject:  body.CurrentObject,
		ArchiveBucket:  body.ArchiveBucket,
		ArchiveKey:     body.ArchiveKey,
		ArchiveName:    body.ArchiveName,
		ErrorMessage:   body.ErrorMessage,
		StartedAt:      body.StartedAt,
		CompletedAt:    body.CompletedAt,
		ExpiresAt:      body.ExpiresAt,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, job)
}

// Cancel handles POST /api/v0/internal/mail-export-jobs/{id}/cancel.
func (h *MailExportJobs) Cancel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	id := mux.Vars(r)["id"]
	job, err := h.service.CancelMailExportJob(ctx, id)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, job)
}

// Expire handles POST /api/v0/internal/mail-export-jobs/expire.
func (h *MailExportJobs) Expire(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	jobs, err := h.service.ExpireMailExportJobs(ctx)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if jobs == nil {
		jobs = []console.MailExportJob{}
	}
	h.writeJSON(w, http.StatusOK, expireJobsResponse{Jobs: jobs})
}

// RequeueStale handles POST /api/v0/internal/mail-export-jobs/requeue-stale.
func (h *MailExportJobs) RequeueStale(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	var body requeueStaleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&body); err != nil {
		h.writeJSON(w, http.StatusBadRequest, mailExportErrorResponse{Error: "invalid request body"})
		return
	}
	olderThan, err := time.ParseDuration(strings.TrimSpace(body.OlderThan))
	if err != nil || olderThan <= 0 {
		h.writeJSON(w, http.StatusBadRequest, mailExportErrorResponse{Error: "invalid olderThan"})
		return
	}

	count, err := h.service.RequeueStaleMailExportJobs(ctx, olderThan)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, requeueStaleResponse{Count: count})
}

// BandwidthQuota handles POST /api/v0/internal/bandwidth-quota (preferred: accessGrant)
// and GET with query params for older clients.
// This is an advisory start gate only — concurrent consumers can still reduce
// headroom mid-stream (same class of race as S3 allocated vs settled).
func (h *MailExportJobs) BandwidthQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}

	var userID, projectID, accessKeyID, accessGrant string
	switch r.Method {
	case http.MethodPost:
		var body bandwidthQuotaRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err = dec.Decode(&body); err != nil {
			h.writeJSON(w, http.StatusBadRequest, mailExportErrorResponse{Error: "invalid request body"})
			return
		}
		userID = body.UserID
		projectID = body.ProjectID
		accessKeyID = body.AccessKeyID
		accessGrant = body.AccessGrant
	default:
		q := r.URL.Query()
		userID = q.Get("userId")
		projectID = q.Get("projectId")
		accessKeyID = q.Get("accessKeyId")
		accessGrant = q.Get("accessGrant")
	}

	available, err := h.service.GetAvailableBandwidthForMailExport(ctx, userID, projectID, accessKeyID, accessGrant)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, bandwidthQuotaResponse{AvailableBytes: available})
}

// BandwidthUsage handles POST /api/v0/internal/bandwidth-usage.
// Charges actual download bytes for a local mail-export archive download (idempotent on chargeId).
func (h *MailExportJobs) BandwidthUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	if !h.validateBearerToken(r) {
		h.writeUnauthorized(w)
		return
	}
	if r.Method != http.MethodPost {
		h.writeJSON(w, http.StatusMethodNotAllowed, mailExportErrorResponse{Error: "method not allowed"})
		return
	}

	var body bandwidthUsageRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&body); err != nil {
		h.writeJSON(w, http.StatusBadRequest, mailExportErrorResponse{Error: "invalid request body"})
		return
	}

	result, err := h.service.ChargeMailExportDownloadBandwidth(ctx, console.ChargeMailExportDownloadBandwidthRequest{
		AccessGrant: body.AccessGrant,
		Bytes:       body.Bytes,
		JobID:       body.JobID,
		ChargeID:    body.ChargeID,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, bandwidthUsageResponse{
		ChargedBytes:   result.ChargedBytes,
		AlreadyCharged: result.AlreadyCharged,
	})
}
