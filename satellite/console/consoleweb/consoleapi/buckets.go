// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting"
	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/configs"
	"github.com/StorXNetwork/common/uuid"
)

const (
	missingParamErrMsg = "missing '%s' query parameter"
	invalidParamErrMsg = "invalid value '%s' for query parameter '%s': %w"
)

var (
	// ErrBucketsAPI - console buckets api error type.
	ErrBucketsAPI = errs.Class("console api buckets")
)

// Buckets is an api controller that exposes all buckets related functionality.
type Buckets struct {
	log                       *zap.Logger
	service                   *console.Service
	billingURL                string
	storageWarningThreshold   float64
	secreteKey                string
	bandwidthWarningThreshold float64
}

// NewBuckets is a constructor for api buckets controller.
func NewBuckets(log *zap.Logger, service *console.Service, billingURL string, storageWarningThreshold float64, bandwidthWarningThreshold float64, secreteKey string) *Buckets {
	return &Buckets{
		log:                       log,
		service:                   service,
		billingURL:                billingURL,
		storageWarningThreshold:   storageWarningThreshold,
		bandwidthWarningThreshold: bandwidthWarningThreshold,
		secreteKey:                secreteKey,
	}
}

// AllBucketNames returns all bucket names for a specific project.
func (b *Buckets) AllBucketNames(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	publicIDString := r.URL.Query().Get("publicID")

	var projectID uuid.UUID
	if projectIDString != "" {
		projectID, err = uuid.FromString(projectIDString)
		if err != nil {
			b.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	} else if publicIDString != "" {
		projectID, err = uuid.FromString(publicIDString)
		if err != nil {
			b.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	} else {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("Project ID was not provided."))
		return
	}

	bucketNames, err := b.service.GetAllBucketNames(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(bucketNames)
	if err != nil {
		b.log.Error("failed to write json all bucket names response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// GetBucketMetadata returns all bucket names and metadata (placement and versioning) for a specific project.
func (b *Buckets) GetBucketMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	publicIDString := r.URL.Query().Get("publicID")

	var projectID uuid.UUID
	if projectIDString != "" {
		projectID, err = uuid.FromString(projectIDString)
		if err != nil {
			b.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	} else if publicIDString != "" {
		projectID, err = uuid.FromString(publicIDString)
		if err != nil {
			b.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	} else {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("Project ID was not provided."))
		return
	}

	bucketMetadata, err := b.service.GetBucketMetadata(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(bucketMetadata)
	if err != nil {
		b.log.Error("failed to write json all bucket names response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// GetPlacementDetails returns a list of available placements and their details.
func (b *Buckets) GetPlacementDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("Project ID was not provided."))
		return
	}

	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	placementDetails, err := b.service.GetPlacementDetails(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	details := make([]console.PlacementDetail, 0, len(placementDetails))
	for _, detail := range placementDetails {
		detail.Pending = detail.WaitlistURL != ""
		detail.WaitlistURL = ""
		details = append(details, detail)
	}
	err = json.NewEncoder(w).Encode(details)
	if err != nil {
		b.log.Error("failed to write placement details json", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// bucketImmutabilityRulesItem is the per-bucket payload for GetImmutabilityRules.
type bucketImmutabilityRulesItem struct {
	BucketName        string                    `json:"bucketName"`
	ImmutabilityRules buckets.ImmutabilityRules `json:"immutabilityRules"`
}

// GetImmutabilityRules returns immutability rules for all buckets in the project.
// Response: { "buckets": [ { "bucketName", "immutabilityRules" }, ... ] }.
// Project-scoped authorization is enforced via GetProject before fetching bucket metadata.
func (b *Buckets) GetImmutabilityRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "projectID"))
		return
	}
	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, projectIDString, "projectID", err))
		return
	}

	if _, err = b.service.GetProject(ctx, projectID); err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	bucketMetadata, err := b.service.GetBucketMetadata(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	resp := struct {
		Buckets []bucketImmutabilityRulesItem `json:"buckets"`
	}{
		Buckets: make([]bucketImmutabilityRulesItem, 0, len(bucketMetadata)),
	}
	for _, bm := range bucketMetadata {
		resp.Buckets = append(resp.Buckets, bucketImmutabilityRulesItem{
			BucketName:        bm.Name,
			ImmutabilityRules: bm.ImmutabilityRules,
		})
	}
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		b.log.Error("failed to write json get immutability rules response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// UpdateImmutabilityRules updates the immutability rules of a bucket with re-authentication.
func (b *Buckets) UpdateImmutabilityRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "projectID"))
		return
	}
	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, projectIDString, "projectID", err))
		return
	}

	bucketName := r.URL.Query().Get("bucketName")
	if bucketName == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "bucketName"))
		return
	}

	var request struct {
		Immutability    bool `json:"immutability"`
		RetentionPeriod int  `json:"retentionPeriod"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	user, err := console.GetUser(ctx)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	// Re-authentication logic
	ip, err := web.GetRequestIP(r)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	mfaPasscode := r.Header.Get("X-MFA-Passcode")
	mfaRecoveryCode := r.Header.Get("X-MFA-Recovery-Code")

	// Call login function (TokenWithoutPassword) to check if user is able to relogin
	_, err = b.service.TokenWithoutPassword(ctx, console.AuthWithoutPassword{
		Email:           user.Email,
		IP:              ip,
		UserAgent:       r.UserAgent(),
		MFAPasscode:     mfaPasscode,
		MFARecoveryCode: mfaRecoveryCode,
	})
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusUnauthorized, errs.New("re-authentication failed: %v", err))
		return
	}

	// Update immutability rules
	rules := buckets.ImmutabilityRules{
		Immutability:    request.Immutability,
		RetentionPeriod: request.RetentionPeriod,
	}

	if !rules.Immutability {
		rules.RetentionPeriod = 0
	}

	err = b.service.UpdateBucketImmutabilityRules(ctx, []byte(bucketName), projectID, rules)
	b.service.RecordUserAudit(ctx, "BUCKET_IMMUTABILITY_UPDATE", "Bucket", "Bucket immutability updated", err)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(rules)
	if err != nil {
		b.log.Error("failed to write json update immutability rules response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

func (b *Buckets) UpdateBucketMigrationStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "projectID"))
		return
	}
	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, projectIDString, "projectID", err))
		return
	}

	bucketName := r.URL.Query().Get("bucketName")
	if bucketName == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "bucketName"))
		return
	}

	status := r.URL.Query().Get("status")
	if status == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "status"))
		return
	}

	var statusInt int
	switch status {
	case "started":
		statusInt = 1
	case "partially_completed":
		statusInt = 2
	case "completed":
		statusInt = 3
	case "failed":
		statusInt = 4
	default:
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, status, "status", errs.New("invalid status")))
		return
	}

	err = b.service.UpdateBucketMigrationStatus(ctx, []byte(bucketName), projectID, statusInt)
	b.service.RecordUserAudit(ctx, "BUCKET_MIGRATION_UPDATE", "Bucket", "Bucket migration updated", err)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Migration status updated successfully",
	})
	if err != nil {
		b.log.Error("failed to write json update migration status response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// GetBucketTotals returns a page of bucket usage totals since project creation.
// GetBucketTotals returns paginated per-bucket usage totals for a project in a time range.
//
// @Summary      Paginated bucket usage totals
// @Description  **Full route:** `GET /api/v0/buckets/usage-totals`
//
// Example: `?projectID=37159d9b-6f3c-4c38-bfe2-0efbbc4b568d&before=2026-06-03T09:01:55.204Z&limit=10&search=&page=1`
//
// `before` and `limit` and `page` are required. `since` is optional (RFC3339 with millis, e.g. `2006-01-02T15:04:05.999Z`).
// @Tags         buckets
// @Produce      json
// @Param        projectID  query  string  true   "Project public UUID"
// @Param        before     query  string  true   "Range end (2006-01-02T15:04:05.999Z)"
// @Param        limit      query  int     true   "Page size"  example(10)
// @Param        page       query  int     true   "Page number (1-based)"  example(1)
// @Param        search     query  string  false  "Bucket name filter"
// @Param        since      query  string  false  "Range start (2006-01-02T15:04:05.999Z)"
// @Success      200        {object}  BucketUsageTotalsPageSwagger
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      500        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /buckets/usage-totals [get]
func (b *Buckets) GetBucketTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "projectID"))
		return
	}
	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, projectIDString, "projectID", err))
		return
	}

	var since time.Time
	if sinceString := r.URL.Query().Get("since"); sinceString != "" {
		var parseErr error
		since, parseErr = time.Parse(dateLayout, sinceString)
		if parseErr != nil {
			b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, sinceString, "since", parseErr))
			return
		}
	}

	beforeString := r.URL.Query().Get("before")
	if beforeString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "before"))
		return
	}
	before, err := time.Parse(dateLayout, beforeString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, beforeString, "before", err))
		return
	}

	limitString := r.URL.Query().Get("limit")
	if limitString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "limit"))
		return
	}
	limitU64, err := strconv.ParseUint(limitString, 10, 32)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, limitString, "limit", err))
		return
	}
	limit := uint(limitU64)

	pageString := r.URL.Query().Get("page")
	if pageString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "page"))
		return
	}
	pageU64, err := strconv.ParseUint(pageString, 10, 32)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, pageString, "page", err))
		return
	}
	page := uint(pageU64)

	totals, err := b.service.GetBucketTotals(ctx, projectID, accounting.BucketUsageCursor{
		Limit:  limit,
		Search: r.URL.Query().Get("search"),
		Page:   page,
	}, since, before)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(totals)
	if err != nil {
		b.log.Error("failed to write json bucket totals response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// GetSingleBucketTotals returns a single bucket usage totals since project creation.
func (b *Buckets) GetSingleBucketTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "projectID"))
		return
	}
	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, projectIDString, "projectID", err))
		return
	}

	beforeString := r.URL.Query().Get("before")
	if beforeString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "before"))
		return
	}
	before, err := time.Parse(dateLayout, beforeString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, beforeString, "before", err))
		return
	}

	bucketString := r.URL.Query().Get("bucket")
	if len(bucketString) < 3 || len(bucketString) > 63 {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, bucketString, "bucket", errs.New("bucket name must be at least 3 and no more than 63 characters long")))
		return
	}

	totals, err := b.service.GetSingleBucketTotals(ctx, projectID, bucketString, before)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(totals)
	if err != nil {
		b.log.Error("failed to write json single bucket totals response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// GetBucketTotalsForReservedBucket returns usage for reserved integration vaults (Google Backup, Dropbox, etc.).
//
// @Summary      Reserved vault usage totals
// @Description  **Full route:** `GET /api/v0/buckets/usage-totals-for-reserved`
//
// Returns per-bucket **storage** (GB), **objectCount**, and metadata for vaults created for integrations.
// Only buckets that exist for the project are included (no zero placeholders).
//
// **Reserved bucket names** (SQL filter): `gmail`, `google-drive`, `google-cloud`, `google-photos`, `google-calendar`, `google-contacts`, `dropbox`, `aws-s3`, `github`, `shopify`, `quickbooks`.
//
// **Protected Services overview (UI):** call this endpoint with `projectID`, then filter the array where `bucketName` is one of:
// `gmail`, `google-drive`, `google-photos`, `google-contacts`, `google-calendar`.
// Use `bucketName` as vault name, `storage` as used storage, `objectCount` as item count.
// @Tags         buckets-reserved-usage
// @Produce      json
// @Param        projectID  query     string  true  "Project UUID"
// @Success      200        {array}   ReservedBucketUsageItem
// @Failure      400        {object}  SwaggerErrorResponse
// @Failure      401        {object}  SwaggerErrorResponse
// @Failure      500        {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /buckets/usage-totals-for-reserved [get]
func (b *Buckets) GetBucketTotalsForReservedBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "projectID"))
		return
	}
	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(invalidParamErrMsg, projectIDString, "projectID", err))
		return
	}

	totals, err := b.service.GetBucketTotalsForReserveBucket(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if totals == nil {
		totals = []accounting.BucketUsage{}
	}

	err = json.NewEncoder(w).Encode(totals)
	if err != nil {
		b.log.Error("failed to write json bucket totals response", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// CheckUpload evaluates storage/bandwidth quota and returns popup flags for the UI.
//
// @Summary      Check storage and bandwidth quota (popup)
// @Description  **Full route:** `POST /api/v0/buckets/check-upload`
//
// Returns quota usage and whether to show a warning popup. `operation`: `login` (after sign-in), `upload` (before upload), `download` (before download). Optional `file_size` validates the operation fits remaining quota (not used for `login`). Popup text comes from DB config `popup_messages`. Related: `GET /api/v0/dashboard/stats` (dashboard cards), `GET /api/v0/projects/{id}/usage-limits` (raw limits).
// @Tags         buckets-quota-check
// @Accept       json
// @Produce      json
// @Param        body  body  CheckUploadSwaggerRequest  true  "project_id, operation, optional file_size"
// @Success      200   {object}  CheckUploadSwaggerResponse
// @Failure      400   {object}  SwaggerErrorResponse
// @Failure      401   {object}  SwaggerErrorResponse
// @Failure      500   {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /buckets/check-upload [post]
func (b *Buckets) CheckUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ProjectID string `json:"project_id"`
		FileSize  *int64 `json:"file_size,omitempty"`
		Operation string `json:"operation"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest,
			errs.New("invalid request body: %w", err))
		return
	}

	if req.ProjectID == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest,
			errs.New("project_id is required"))
		return
	}

	if req.Operation == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest,
			errs.New("operation is required"))
		return
	}

	if req.Operation != "login" && req.Operation != "download" && req.Operation != "upload" {
		b.serveJSONError(ctx, w, http.StatusBadRequest,
			errs.New("operation must be one of: login, download, upload"))
		return
	}

	projectIDParam, err := uuid.FromString(req.ProjectID)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest,
			errs.New("invalid project_id: %w", err))
		return
	}

	snap, err := b.loadProjectQuotaSnapshot(ctx, projectIDParam)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if snap.StorageLimit == 0 && snap.StorageUsed == 0 && snap.BandwidthLimit == 0 && snap.BandwidthUsed == 0 {
		b.sendResponse(w, 0, 0, 0.0, 0, 0, 0.0, false, true, true, "")
		return
	}

	storageAtLimit := snap.StorageLimit > 0 && snap.StorageUsed >= snap.StorageLimit
	bandwidthAtLimit := snap.BandwidthLimit > 0 && snap.BandwidthUsed >= snap.BandwidthLimit
	storageAtThreshold := snap.StoragePercent >= b.storageWarningThreshold
	bandwidthAtThreshold := snap.BandwidthPercent >= b.bandwidthWarningThreshold

	allowUpload := !storageAtLimit
	allowDownload := !bandwidthAtLimit

	popupMessages := b.loadPopupMessagesConfig(ctx)

	// Validate file size based on operation
	if req.FileSize != nil && req.Operation != "login" {
		fileSize := *req.FileSize
		if fileSize <= 0 {
			b.serveJSONError(ctx, w, http.StatusBadRequest,
				errs.New("file_size must be > 0"))
			return
		}

		// For upload: check storage limit
		if req.Operation == "upload" && snap.StorageRemaining < fileSize {
			b.sendResponse(w, snap.StorageLimit, snap.StorageRemaining, snap.StoragePercent, snap.BandwidthLimit, snap.BandwidthRemaining, snap.BandwidthPercent, true, false, allowDownload, popupMessages.FileSize.StorageExceeded)
			return
		}

		// For download: check bandwidth limit
		if req.Operation == "download" && snap.BandwidthRemaining < fileSize {
			b.sendResponse(w, snap.StorageLimit, snap.StorageRemaining, snap.StoragePercent, snap.BandwidthLimit, snap.BandwidthRemaining, snap.BandwidthPercent, true, allowUpload, false, popupMessages.FileSize.BandwidthExceeded)
			return
		}
	}

	popup, message := b.determinePopupMessage(req.Operation, storageAtLimit, bandwidthAtLimit, storageAtThreshold, bandwidthAtThreshold, snap.StoragePercent, snap.BandwidthPercent, popupMessages)

	b.sendResponse(w, snap.StorageLimit, snap.StorageRemaining, snap.StoragePercent, snap.BandwidthLimit, snap.BandwidthRemaining, snap.BandwidthPercent, popup, allowUpload, allowDownload, message)
}

// formatMessage formats message with actual storage usage percentage and threshold if message is not empty.
func (b *Buckets) formatMessage(msg string, storageUsagePercent float64) string {
	if msg == "" {
		return ""
	}
	return fmt.Sprintf(msg, storageUsagePercent, b.storageWarningThreshold)
}

// formatMessageWithBandwidth formats message with actual bandwidth usage percentage and threshold if message is not empty.
func (b *Buckets) formatMessageWithBandwidth(msg string, bandwidthUsagePercent float64) string {
	if msg == "" {
		return ""
	}
	return fmt.Sprintf(msg, bandwidthUsagePercent, b.bandwidthWarningThreshold)
}

// formatMessageWithBoth formats message with both actual usage percentages and thresholds if message is not empty.
func (b *Buckets) formatMessageWithBoth(msg string, storageUsagePercent, bandwidthUsagePercent float64) string {
	if msg == "" {
		return ""
	}
	return fmt.Sprintf(msg, storageUsagePercent, bandwidthUsagePercent, b.storageWarningThreshold, b.bandwidthWarningThreshold)
}

// formatMessageWithStorageLimitAndBandwidthThreshold formats message with storage limit (100%), bandwidth usage percentage, and bandwidth threshold.
func (b *Buckets) formatMessageWithStorageLimitAndBandwidthThreshold(msg string, bandwidthUsagePercent float64) string {
	if msg == "" {
		return ""
	}
	return fmt.Sprintf(msg, bandwidthUsagePercent, b.bandwidthWarningThreshold, b.storageWarningThreshold)
}

// formatMessageWithBandwidthLimitAndStorageThreshold formats message with bandwidth limit (100%), storage usage percentage, and storage threshold.
func (b *Buckets) formatMessageWithBandwidthLimitAndStorageThreshold(msg string, storageUsagePercent float64) string {
	if msg == "" {
		return ""
	}
	return fmt.Sprintf(msg, storageUsagePercent, b.storageWarningThreshold)
}

// determinePopupMessage determines popup and message based on operation and limits.
func (b *Buckets) determinePopupMessage(operation string, storageAtLimit, bandwidthAtLimit, storageAtThreshold, bandwidthAtThreshold bool, storageUsagePercent, bandwidthUsagePercent float64, popupMessages PopupMessagesResponse) (bool, string) {
	switch operation {
	case "login":
		if storageAtLimit && bandwidthAtThreshold {
			return true, b.formatMessageWithStorageLimitAndBandwidthThreshold(popupMessages.Login.StorageLimitAndBandwidthThreshold, bandwidthUsagePercent)
		}
		if bandwidthAtLimit && storageAtThreshold {
			return true, b.formatMessageWithBandwidthLimitAndStorageThreshold(popupMessages.Login.BandwidthLimitAndStorageThreshold, storageUsagePercent)
		}
		if storageAtThreshold && bandwidthAtThreshold {
			return true, b.formatMessageWithBoth(popupMessages.Login.StorageAndBandwidthThreshold, storageUsagePercent, bandwidthUsagePercent)
		}
		if storageAtThreshold {
			return true, b.formatMessage(popupMessages.Login.StorageThreshold, storageUsagePercent)
		}
		if bandwidthAtThreshold {
			return true, b.formatMessageWithBandwidth(popupMessages.Login.BandwidthThreshold, bandwidthUsagePercent)
		}
	case "download":
		if bandwidthAtLimit {
			return true, popupMessages.Download.BandwidthLimit
		}
		if bandwidthAtThreshold {
			return true, b.formatMessageWithBandwidth(popupMessages.Download.BandwidthWarning, bandwidthUsagePercent)
		}
	case "upload":
		if storageAtLimit {
			return true, popupMessages.Upload.StorageLimit
		}
		if storageAtThreshold {
			return true, b.formatMessage(popupMessages.Upload.StorageWarning, storageUsagePercent)
		}
	}
	return false, ""
}

// sendResponse sends the check upload response
func (b *Buckets) sendResponse(w http.ResponseWriter, totalSpace, remainingSpace int64, storageUsagePercent float64, totalBandwidth, remainingBandwidth int64, bandwidthUsagePercent float64, popupShow, allowUpload, allowDownload bool, message string) {
	resp := struct {
		PopupShow                 bool    `json:"popup_show"`
		AllowUpload               bool    `json:"allow_upload"`
		AllowDownload             bool    `json:"allow_download"`
		TotalSpace                int64   `json:"total_space"`
		RemainingSpace            int64   `json:"remaining_space"`
		StorageUsagePercent       float64 `json:"storage_usage_percent"`
		TotalBandwidth            int64   `json:"total_bandwidth"`
		RemainingBandwidth        int64   `json:"remaining_bandwidth"`
		BandwidthUsagePercent     float64 `json:"bandwidth_usage_percent"`
		StorageWarningThreshold   float64 `json:"storage_warning_threshold"`
		BandwidthWarningThreshold float64 `json:"bandwidth_warning_threshold"`
		Message                   string  `json:"message"`
		UpgradeURL                string  `json:"upgrade_url"`
	}{
		PopupShow:                 popupShow,
		AllowUpload:               allowUpload,
		AllowDownload:             allowDownload,
		TotalSpace:                totalSpace,
		RemainingSpace:            remainingSpace,
		StorageUsagePercent:       storageUsagePercent,
		TotalBandwidth:            totalBandwidth,
		RemainingBandwidth:        remainingBandwidth,
		BandwidthUsagePercent:     bandwidthUsagePercent,
		StorageWarningThreshold:   b.storageWarningThreshold,
		BandwidthWarningThreshold: b.bandwidthWarningThreshold,
		Message:                   message,
		UpgradeURL:                b.billingURL,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Error encoding response - response already started, can't send error
	}
}

// PopupMessagesResponse represents popup messages configuration from database.
type PopupMessagesResponse struct {
	Login struct {
		StorageAndBandwidthThreshold      string `json:"storage_and_bandwidth_threshold"`
		StorageThreshold                  string `json:"storage_threshold"`
		BandwidthThreshold                string `json:"bandwidth_threshold"`
		StorageLimitAndBandwidthThreshold string `json:"storage_limit_and_bandwidth_threshold"`
		BandwidthLimitAndStorageThreshold string `json:"bandwidth_limit_and_storage_threshold"`
	} `json:"login"`
	Download struct {
		BandwidthLimit   string `json:"bandwidth_limit"`
		BandwidthWarning string `json:"bandwidth_warning"`
	} `json:"download"`
	Upload struct {
		StorageLimit   string `json:"storage_limit"`
		StorageWarning string `json:"storage_warning"`
	} `json:"upload"`
	FileSize struct {
		StorageExceeded   string `json:"storage_exceeded"`
		BandwidthExceeded string `json:"bandwidth_exceeded"`
	} `json:"file_size"`
}

// loadPopupMessagesConfig loads popup messages configuration from database.
func (b *Buckets) loadPopupMessagesConfig(ctx context.Context) PopupMessagesResponse {
	response := PopupMessagesResponse{}

	configService := configs.NewService(b.service.GetConfigs())
	dbConfig, err := configService.GetConfigByName(ctx, configs.ConfigTypePopupMessages, "popup")
	if err != nil || !dbConfig.IsActive {
		return response
	}

	configJSON, err := json.Marshal(dbConfig.ConfigData)
	if err != nil {
		return response
	}

	if err := json.Unmarshal(configJSON, &response); err != nil {
		return response
	}

	return response
}

// QuotaMetricLevel is ok | warn | error for one quota dimension.
type QuotaMetricLevel string

const (
	QuotaLevelOK    QuotaMetricLevel = "ok"
	QuotaLevelWarn  QuotaMetricLevel = "warn"
	QuotaLevelError QuotaMetricLevel = "error"
)

// QuotaMetricStatus is storage or bandwidth usage for GET /buckets/quota-status.
type QuotaMetricStatus struct {
	Used      int64            `json:"used"`
	Limit     int64            `json:"limit"`
	Remaining int64            `json:"remaining"`
	Percent   float64          `json:"percent"`
	Level     QuotaMetricLevel `json:"level"`
	Threshold float64          `json:"threshold"`
	Message   string           `json:"message"`
}

// QuotaStatusResponse is returned by GET /api/v0/buckets/quota-status.
type QuotaStatusResponse struct {
	PopupShow                 bool              `json:"popup_show"`
	Storage                   QuotaMetricStatus `json:"storage"`
	Bandwidth                 QuotaMetricStatus `json:"bandwidth"`
	Message                   string            `json:"message"`
	UpgradeURL                string            `json:"upgrade_url"`
	StorageWarningThreshold   float64           `json:"storage_warning_threshold"`
	BandwidthWarningThreshold float64           `json:"bandwidth_warning_threshold"`
}

// QuotaStatus returns project storage + bandwidth usage for after-login / sidebar UI.
//
// @Summary      Project quota status (storage + bandwidth)
// @Description  **Full route:** `GET /api/v0/buckets/quota-status?project_id=`
//
// Simple status only (no file_size / upload / download). Same usage as check-upload.
// Levels: ok | warn (≥ threshold) | error (full). Hardcoded messages; combined when both fire.
// @Tags         buckets-quota-check
// @Produce      json
// @Param        project_id  query  string  true  "Project UUID"
// @Success      200  {object}  QuotaStatusSwaggerResponse
// @Failure      400  {object}  SwaggerErrorResponse
// @Failure      401  {object}  SwaggerErrorResponse
// @Failure      500  {object}  SwaggerErrorResponse
// @Security     CookieAuth
// @Router       /buckets/quota-status [get]
func (b *Buckets) QuotaStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	projectIDStr := r.URL.Query().Get("project_id")
	if projectIDStr == "" {
		projectIDStr = r.URL.Query().Get("projectID")
	}
	if projectIDStr == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("project_id is required"))
		return
	}

	projectID, err := uuid.FromString(projectIDStr)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid project_id: %w", err))
		return
	}

	snap, err := b.loadProjectQuotaSnapshot(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	storage := buildQuotaMetric(snap.StorageUsed, snap.StorageLimit, b.storageWarningThreshold, "storage")
	bandwidth := buildQuotaMetric(snap.BandwidthUsed, snap.BandwidthLimit, b.bandwidthWarningThreshold, "bandwidth")

	resp := QuotaStatusResponse{
		PopupShow:                 storage.Level != QuotaLevelOK || bandwidth.Level != QuotaLevelOK,
		Storage:                   storage,
		Bandwidth:                 bandwidth,
		Message:                   combineQuotaMessages(storage, bandwidth),
		UpgradeURL:                b.billingURL,
		StorageWarningThreshold:   b.storageWarningThreshold,
		BandwidthWarningThreshold: b.bandwidthWarningThreshold,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		b.log.Error("error encoding quota status", zap.Error(ErrBucketsAPI.Wrap(err)))
	}
}

// projectQuotaSnapshot is shared by check-upload and quota-status (same usage source).
type projectQuotaSnapshot struct {
	StorageLimit       int64
	StorageUsed        int64
	StorageRemaining   int64
	StoragePercent     float64
	BandwidthLimit     int64
	BandwidthUsed      int64
	BandwidthRemaining int64
	BandwidthPercent   float64
}

// loadProjectQuotaSnapshot loads effective storage/bandwidth used+limit once (honors user-set limits).
func (b *Buckets) loadProjectQuotaSnapshot(ctx context.Context, projectID uuid.UUID) (*projectQuotaSnapshot, error) {
	usageLimits, err := b.service.GetProjectUsageLimits(ctx, projectID)
	if err != nil {
		return nil, err
	}

	storageLimit := quotaEffectiveLimit(usageLimits.StorageLimit, usageLimits.UserSetStorageLimit)
	bandwidthLimit := quotaEffectiveLimit(usageLimits.BandwidthLimit, usageLimits.UserSetBandwidthLimit)
	storageUsed := usageLimits.StorageUsed
	bandwidthUsed := usageLimits.BandwidthUsed

	storageRemaining := storageLimit - storageUsed
	if storageRemaining < 0 {
		storageRemaining = 0
	}
	bandwidthRemaining := bandwidthLimit - bandwidthUsed
	if bandwidthRemaining < 0 {
		bandwidthRemaining = 0
	}

	return &projectQuotaSnapshot{
		StorageLimit:       storageLimit,
		StorageUsed:        storageUsed,
		StorageRemaining:   storageRemaining,
		StoragePercent:     quotaUsagePercent(storageUsed, storageLimit),
		BandwidthLimit:     bandwidthLimit,
		BandwidthUsed:      bandwidthUsed,
		BandwidthRemaining: bandwidthRemaining,
		BandwidthPercent:   quotaUsagePercent(bandwidthUsed, bandwidthLimit),
	}, nil
}

func quotaEffectiveLimit(base int64, userSet *int64) int64 {
	if userSet != nil && *userSet > 0 {
		return *userSet
	}
	return base
}

func quotaUsagePercent(used, limit int64) float64 {
	if limit <= 0 {
		return 0
	}
	return float64(used) / float64(limit) * 100
}

func buildQuotaMetric(used, limit int64, threshold float64, kind string) QuotaMetricStatus {
	percent := quotaUsagePercent(used, limit)
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}

	atLimit := limit > 0 && used >= limit
	atWarn := percent >= threshold

	level := QuotaLevelOK
	message := ""
	switch {
	case atLimit:
		level = QuotaLevelError
		if kind == "storage" {
			message = fmt.Sprintf("Storage is full — %.0f%% of your plan space is consumed. Upgrade or free space to continue backups.", percent)
		} else {
			message = fmt.Sprintf("Bandwidth is full — %.0f%% of your download quota is used. Upgrade or wait for the next billing cycle.", percent)
		}
	case atWarn:
		level = QuotaLevelWarn
		if kind == "storage" {
			message = fmt.Sprintf("Storage warning — you have used %.0f%% of your space (threshold %.0f%%). Consider upgrading soon.", percent, threshold)
		} else {
			message = fmt.Sprintf("Bandwidth warning — you have used %.0f%% of your download quota (threshold %.0f%%). Consider upgrading soon.", percent, threshold)
		}
	}

	return QuotaMetricStatus{
		Used:      used,
		Limit:     limit,
		Remaining: remaining,
		Percent:   percent,
		Level:     level,
		Threshold: threshold,
		Message:   message,
	}
}

// combineQuotaMessages covers storage-only, bandwidth-only, and combined both cases.
func combineQuotaMessages(storage, bandwidth QuotaMetricStatus) string {
	sErr := storage.Level == QuotaLevelError
	bErr := bandwidth.Level == QuotaLevelError
	sWarn := storage.Level == QuotaLevelWarn
	bWarn := bandwidth.Level == QuotaLevelWarn

	switch {
	case sErr && bErr:
		return fmt.Sprintf(
			"Storage and bandwidth are both full — storage %.0f%% and bandwidth %.0f%% used. Upgrade your plan to continue backups and downloads.",
			storage.Percent, bandwidth.Percent,
		)
	case sErr && bWarn:
		return fmt.Sprintf(
			"Storage is full (%.0f%%) and bandwidth is at warning level (%.0f%%, threshold %.0f%%). Upgrade or free space to continue.",
			storage.Percent, bandwidth.Percent, bandwidth.Threshold,
		)
	case bErr && sWarn:
		return fmt.Sprintf(
			"Bandwidth is full (%.0f%%) and storage is at warning level (%.0f%%, threshold %.0f%%). Upgrade or wait for the next billing cycle.",
			bandwidth.Percent, storage.Percent, storage.Threshold,
		)
	case sWarn && bWarn:
		return fmt.Sprintf(
			"Storage and bandwidth are both above threshold — storage %.0f%% and bandwidth %.0f%% used (thresholds %.0f%% / %.0f%%). Consider upgrading soon.",
			storage.Percent, bandwidth.Percent, storage.Threshold, bandwidth.Threshold,
		)
	case sErr || sWarn:
		return storage.Message
	case bErr || bWarn:
		return bandwidth.Message
	default:
		return ""
	}
}

// serveJSONError writes JSON error to response output stream.
func (b *Buckets) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, b.log, w, status, err)
}
