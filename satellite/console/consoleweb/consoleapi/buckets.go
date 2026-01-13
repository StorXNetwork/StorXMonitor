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

	"storj.io/common/memory"
	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/accounting"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/console"
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
	log                     *zap.Logger
	service                 *console.Service
	billingURL              string
	storageWarningThreshold float64
	secreteKey              string
}

// NewBuckets is a constructor for api buckets controller.
func NewBuckets(log *zap.Logger, service *console.Service, billingURL string, storageWarningThreshold float64, secreteKey string) *Buckets {
	return &Buckets{
		log:                     log,
		service:                 service,
		billingURL:              billingURL,
		storageWarningThreshold: storageWarningThreshold,
		secreteKey:              secreteKey,
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
		UpdatedAt:       time.Now(),
	}

	if !rules.Immutability {
		rules.RetentionPeriod = 0
	}

	err = b.service.UpdateBucketImmutabilityRules(ctx, []byte(bucketName), projectID, rules)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusOK)
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
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// GetBucketTotals returns a page of bucket usage totals since project creation.
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
	}, before)
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

// GetBucketTotalsForReservedBucket
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

func (b *Buckets) CheckUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ProjectID string `json:"project_id"`
		FileSize  *int64 `json:"file_size,omitempty"`
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

	projectIDParam, err := uuid.FromString(req.ProjectID)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusBadRequest,
			errs.New("invalid project_id: %w", err))
		return
	}

	// Get project first - this handles both id and public_id
	// Then use the actual project.ID (not public_id) for storage queries
	project, err := b.service.GetProject(ctx, projectIDParam)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	// Get usage limits (includes both storage and bandwidth)
	usageLimits, err := b.service.GetProjectUsageLimits(ctx, project.ID)
	if err != nil {
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	storageLimit := usageLimits.StorageLimit
	storageUsed := usageLimits.StorageUsed
	bandwidthLimit := usageLimits.BandwidthLimit
	bandwidthUsed := usageLimits.BandwidthUsed

	if storageLimit == 0 && storageUsed == 0 && bandwidthLimit == 0 && bandwidthUsed == 0 {
		b.sendResponse(w, 0, 0, 0.0, 0, 0, 0.0, false, true, "")
		return
	}

	// Calculate remaining space and bandwidth
	remaining := storageLimit - storageUsed
	remainingBandwidth := bandwidthLimit - bandwidthUsed

	// Calculate usage percentages (avoid division by zero)
	var usagePercent, bandwidthUsagePercent float64
	if storageLimit > 0 {
		usagePercent = float64(storageUsed) / float64(storageLimit) * 100
	}
	if bandwidthLimit > 0 {
		bandwidthUsagePercent = float64(bandwidthUsed) / float64(bandwidthLimit) * 100
	}

	// Validate file size if provided
	var fileSize int64
	if req.FileSize != nil {
		fileSize = *req.FileSize
		if fileSize <= 0 {
			b.serveJSONError(ctx, w, http.StatusBadRequest,
				errs.New("file_size must be > 0"))
			return
		}

		// Check if file exceeds remaining space
		if remaining < fileSize {
			b.sendResponse(w, storageLimit, remaining, usagePercent, bandwidthLimit, remainingBandwidth, bandwidthUsagePercent, true, false,
				fmt.Sprintf("Uploading %s exceeds your storage limit. Remaining: %s / Total: %s.",
					memory.Size(fileSize).Base10String(), memory.Size(remaining).Base10String(), memory.Size(storageLimit).Base10String()))
			return
		}

		// Check if file exceeds remaining bandwidth
		if remainingBandwidth < fileSize {
			b.sendResponse(w, storageLimit, remaining, usagePercent, bandwidthLimit, remainingBandwidth, bandwidthUsagePercent, true, false,
				fmt.Sprintf("Uploading %s exceeds your bandwidth limit. Remaining: %s / Total: %s.",
					memory.Size(fileSize).Base10String(), memory.Size(remainingBandwidth).Base10String(), memory.Size(bandwidthLimit).Base10String()))
			return
		}
	}

	// Determine response based on usage
	allowUpload := true
	popup := false
	message := ""

	if usagePercent >= 100 {
		allowUpload = false
		popup = true
		message = fmt.Sprintf("Storage limit reached. Used %s of %s. Please upgrade.",
			memory.Size(storageUsed).Base10String(), memory.Size(storageLimit).Base10String())
	} else if usagePercent >= b.storageWarningThreshold {
		popup = true
		message = fmt.Sprintf("You're nearing your storage limit—%s of %s used (%.1f%%). Upgrade now to avoid interruptions.",
			memory.Size(storageUsed).Base10String(), memory.Size(storageLimit).Base10String(), usagePercent)
	}

	// Check bandwidth limits (bandwidth warnings take precedence if both are over threshold)
	if bandwidthUsagePercent >= 100 {
		allowUpload = false
		popup = true
		message = fmt.Sprintf("Bandwidth limit reached. Used %s of %s. Please upgrade.",
			memory.Size(bandwidthUsed).Base10String(), memory.Size(bandwidthLimit).Base10String())
	} else if bandwidthUsagePercent >= b.storageWarningThreshold && !popup {
		popup = true
		message = fmt.Sprintf("You're nearing your bandwidth limit—%s of %s used (%.1f%%). Upgrade now to avoid interruptions.",
			memory.Size(bandwidthUsed).Base10String(), memory.Size(bandwidthLimit).Base10String(), bandwidthUsagePercent)
	}

	b.sendResponse(w, storageLimit, remaining, usagePercent, bandwidthLimit, remainingBandwidth, bandwidthUsagePercent, popup, allowUpload, message)
}

// sendResponse sends the check upload response
func (b *Buckets) sendResponse(w http.ResponseWriter, totalSpace, remainingSpace int64, storageUsagePercent float64, totalBandwidth, remainingBandwidth int64, bandwidthUsagePercent float64, popupShow, allowUpload bool, message string) {
	resp := struct {
		PopupShow             bool    `json:"popup_show"`
		AllowUpload           bool    `json:"allow_upload"`
		TotalSpace            int64   `json:"total_space"`
		RemainingSpace        int64   `json:"remaining_space"`
		StorageUsagePercent   float64 `json:"storage_usage_percent"`
		TotalBandwidth        int64   `json:"total_bandwidth"`
		RemainingBandwidth    int64   `json:"remaining_bandwidth"`
		BandwidthUsagePercent float64 `json:"bandwidth_usage_percent"`
		WarningThreshold      float64 `json:"warning_threshold"`
		Message               string  `json:"message"`
		UpgradeURL            string  `json:"upgrade_url"`
	}{
		PopupShow:             popupShow,
		AllowUpload:           allowUpload,
		TotalSpace:            totalSpace,
		RemainingSpace:        remainingSpace,
		StorageUsagePercent:   storageUsagePercent,
		TotalBandwidth:        totalBandwidth,
		RemainingBandwidth:    remainingBandwidth,
		BandwidthUsagePercent: bandwidthUsagePercent,
		WarningThreshold:      b.storageWarningThreshold,
		Message:               message,
		UpgradeURL:            b.billingURL,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Error encoding response - response already started, can't send error
	}
}

// serveJSONError writes JSON error to response output stream.
func (b *Buckets) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, b.log, w, status, err)
}
