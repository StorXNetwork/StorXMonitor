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

	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/accounting"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/configs"
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

// GetImmutabilityRules returns the immutability rules (status) for a specific bucket.
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

	bucketName := r.URL.Query().Get("bucketName")
	if bucketName == "" {
		b.serveJSONError(ctx, w, http.StatusBadRequest, errs.New(missingParamErrMsg, "bucketName"))
		return
	}

	// Project-scoped authorization: fail fast before fetching bucket metadata.
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

	var rules *buckets.ImmutabilityRules
	for _, bm := range bucketMetadata {
		if bm.Name == bucketName {
			ruleCopy := bm.ImmutabilityRules
			rules = &ruleCopy
			break
		}
	}
	if rules == nil {
		b.serveJSONError(ctx, w, http.StatusNotFound, errs.New("bucket %q not found in project", bucketName))
		return
	}

	if err = json.NewEncoder(w).Encode(rules); err != nil {
		b.log.Error("failed to write json get immutability rules response", zap.Error(ErrBucketsAPI.Wrap(err)))
		return
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

	project, err := b.service.GetProject(ctx, projectIDParam)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			b.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		b.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

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
		b.sendResponse(w, 0, 0, 0.0, 0, 0, 0.0, false, true, true, "")
		return
	}

	remaining := storageLimit - storageUsed
	remainingBandwidth := bandwidthLimit - bandwidthUsed

	var usagePercent, bandwidthUsagePercent float64
	if storageLimit > 0 {
		usagePercent = float64(storageUsed) / float64(storageLimit) * 100
	}
	if bandwidthLimit > 0 {
		bandwidthUsagePercent = float64(bandwidthUsed) / float64(bandwidthLimit) * 100
	}

	storageAtLimit := storageLimit > 0 && storageUsed >= storageLimit
	bandwidthAtLimit := bandwidthLimit > 0 && bandwidthUsed >= bandwidthLimit
	storageAtThreshold := usagePercent >= b.storageWarningThreshold
	bandwidthAtThreshold := bandwidthUsagePercent >= b.bandwidthWarningThreshold

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
		if req.Operation == "upload" && remaining < fileSize {
			b.sendResponse(w, storageLimit, remaining, usagePercent, bandwidthLimit, remainingBandwidth, bandwidthUsagePercent, true, false, allowDownload, popupMessages.FileSize.StorageExceeded)
			return
		}

		// For download: check bandwidth limit
		if req.Operation == "download" && remainingBandwidth < fileSize {
			b.sendResponse(w, storageLimit, remaining, usagePercent, bandwidthLimit, remainingBandwidth, bandwidthUsagePercent, true, allowUpload, false, popupMessages.FileSize.BandwidthExceeded)
			return
		}
	}

	popup, message := b.determinePopupMessage(req.Operation, storageAtLimit, bandwidthAtLimit, storageAtThreshold, bandwidthAtThreshold, usagePercent, bandwidthUsagePercent, popupMessages)

	b.sendResponse(w, storageLimit, remaining, usagePercent, bandwidthLimit, remainingBandwidth, bandwidthUsagePercent, popup, allowUpload, allowDownload, message)
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

// serveJSONError writes JSON error to response output stream.
func (b *Buckets) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, b.log, w, status, err)
}
