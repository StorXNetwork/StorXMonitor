// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/uuid"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consoleapi/utils"
)

var (
	// ErrAPIKeysAPI - console api keys api error type.
	ErrAPIKeysAPI = errs.Class("console api keys")
)

// APIKeys is an api controller that exposes all api keys related functionality.
type APIKeys struct {
	log     *zap.Logger
	service *console.Service
}

// NewAPIKeys is a constructor for api api keys controller.
func NewAPIKeys(log *zap.Logger, service *console.Service) *APIKeys {
	return &APIKeys{
		log:     log,
		service: service,
	}
}

// CreateAPIKey creates new API key for given project.
func (keys *APIKeys) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var ok bool
	var idParam string

	if idParam, ok = mux.Vars(r)["projectID"]; !ok {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing projectID route param"))
		return
	}

	projectID, err := uuid.FromString(idParam)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}
	name := string(bodyBytes)

	info, key, err := keys.service.CreateAPIKey(ctx, projectID, name)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	response := console.CreateAPIKeyResponse{
		Key:     key.Serialize(),
		KeyInfo: info,
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		keys.log.Error("failed to write json create api key response", zap.Error(ErrAPIKeysAPI.Wrap(err)))
		return
	}

	// Send push notification for API key created (unless it's "Web file browser API key")
	if !strings.Contains(name, "Web file browser API key") {
		go func() {
			// Use background context to avoid cancellation when HTTP request completes
			notifyCtx := context.Background()
			consoleUser, err := console.GetUser(ctx)
			if err == nil {
				notifyUserID := consoleUser.ID
				variables := map[string]interface{}{
					"api_key_name": name,
					"project_id":   projectID.String(),
				}
				if err := keys.service.SendPushNotificationByEventName(notifyCtx, notifyUserID, "api_key_created", "account", variables); err != nil {
					keys.log.Warn("Failed to send push notification for API key created",
						zap.Stringer("user_id", notifyUserID),
						zap.String("api_key_name", name),
						zap.Error(err))
				} else {
					keys.log.Debug("Successfully sent push notification for API key created",
						zap.Stringer("user_id", notifyUserID),
						zap.String("api_key_name", name))
				}
			}
		}()
	}
}

// GetProjectAPIKeys returns paged API keys by project ID.
func (keys *APIKeys) GetProjectAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	query := r.URL.Query()

	projectIDParam := query.Get("projectID")
	if projectIDParam == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("parameter 'projectID' can't be empty"))
		return
	}

	projectID, err := uuid.FromString(projectIDParam)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	limitParam := query.Get("limit")
	if limitParam == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("parameter 'limit' can't be empty"))
		return
	}

	limit, err := strconv.ParseUint(limitParam, 10, 32)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	pageParam := query.Get("page")
	if pageParam == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("parameter 'page' can't be empty"))
		return
	}

	page, err := strconv.ParseUint(pageParam, 10, 32)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	orderParam := query.Get("order")
	if orderParam == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("parameter 'order' can't be empty"))
		return
	}

	order, err := strconv.ParseUint(orderParam, 10, 32)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	orderDirectionParam := query.Get("orderDirection")
	if orderDirectionParam == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("parameter 'orderDirection' can't be empty"))
		return
	}

	orderDirection, err := strconv.ParseUint(orderDirectionParam, 10, 32)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	searchString := query.Get("search")

	cursor := console.APIKeyCursor{
		Search:         searchString,
		Limit:          uint(limit),
		Page:           uint(page),
		Order:          console.APIKeyOrder(order),
		OrderDirection: console.OrderDirection(orderDirection),
	}

	apiKeys, err := keys.service.GetAPIKeys(ctx, projectID, cursor)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(apiKeys)
	if err != nil {
		keys.log.Error("failed to write json all api keys response", zap.Error(ErrAPIKeysAPI.Wrap(err)))
	}
}

// GetAccessGrant give access grant for a project using API key and passphrase.
func (keys *APIKeys) GetAccessGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	apiKey := r.URL.Query().Get("api-key")
	if apiKey == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing api-key query param"))
		return
	}

	passphrase := r.URL.Query().Get("passphrase")

	var prefix []grant.SharePrefix
	var permission *grant.Permission
	if bucketStr := r.URL.Query().Get("bucket"); bucketStr != "" {
		if strings.Contains(bucketStr, ",") {
			bucketNames := strings.Split(bucketStr, ",")
			for _, bucketName := range bucketNames {
				prefix = append(prefix, grant.SharePrefix{Prefix: "", Bucket: bucketName})
			}
		} else if bucketStr == "all" {
			prefix = []grant.SharePrefix{{Prefix: "", Bucket: ""}}
		} else {
			prefixStr := r.URL.Query().Get("prefix")
			prefix = []grant.SharePrefix{{Prefix: prefixStr, Bucket: bucketStr}}
		}

		permission = createPermissionFromRequest(r)
		if permission == nil {
			keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing permission query param"))
			return
		}
	}

	projectID, ok := mux.Vars(r)["project_id"]
	if !ok {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("missing id route param"))
		return
	}

	id, err := uuid.FromString(projectID)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	parsedAPIKey, err := macaroon.ParseAPIKey(apiKey)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	accessGrantStr, err := keys.service.CreateAccessGrantForProject(ctx, id, passphrase, prefix, permission, parsedAPIKey)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	err = json.NewEncoder(w).Encode(accessGrantStr)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	// Send push notification for access created (vault category)
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		consoleUser, err := console.GetUser(ctx)
		if err == nil {
			notifyUserID := consoleUser.ID
			creationTime := time.Now().Format(time.RFC3339)
			variables := map[string]interface{}{
				"project_id":    id.String(),
				"creation_time": creationTime,
				"access_grant":  "created",
			}
			if err := keys.service.SendPushNotificationByEventName(notifyCtx, notifyUserID, "access_created", "vault", variables); err != nil {
				keys.log.Warn("Failed to send push notification for access created",
					zap.Stringer("user_id", notifyUserID),
					zap.Stringer("project_id", id),
					zap.Error(err))
			} else {
				keys.log.Debug("Successfully sent push notification for access created",
					zap.Stringer("user_id", notifyUserID),
					zap.Stringer("project_id", id))
			}
		}
	}()
}

func createPermissionFromRequest(r *http.Request) *grant.Permission {
	if !r.URL.Query().Has("allow_download") && !r.URL.Query().Has("allow_upload") &&
		!r.URL.Query().Has("allow_list") && !r.URL.Query().Has("allow_delete") && r.URL.Query().Get("expiry") == "" {
		return nil
	}

	out := &grant.Permission{}
	out.AllowDownload = r.URL.Query().Has("allow_download")
	out.AllowUpload = r.URL.Query().Has("allow_upload")
	out.AllowList = r.URL.Query().Has("allow_list")
	out.AllowDelete = r.URL.Query().Has("allow_delete")
	out.NotBefore = time.Now()

	if expiryStr := r.URL.Query().Get("expiry"); expiryStr != "" {
		expiry, err := time.Parse(time.DateTime, expiryStr)
		if err != nil {
			return nil
		}
		out.NotAfter = expiry
	}

	return out
}

// GetAccessGrantForDeveloper give access grant for a project using API key and passphrase.
func (keys *APIKeys) GetAccessGrantForDeveloper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type accessCreateRequest struct {
		Email      string `json:"email"`
		Passphrase string `json:"passphrase"`
	}

	var registerData accessCreateRequest
	err := json.NewDecoder(r.Body).Decode(&registerData)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	fmt.Println("access grant API")

	// trim leading and trailing spaces of email address.
	registerData.Email = strings.TrimSpace(registerData.Email)

	isValidEmail := utils.ValidateEmail(registerData.Email)
	if !isValidEmail {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("invalid email address"))
		return
	}

	// get user from email id
	user, err := keys.service.GetUsers().GetByEmail(ctx, registerData.Email)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	// creaet context with user same we do at registration
	ctxWithUser := console.WithUser(ctx, user)

	// get project
	projects, err := keys.service.GetUsersProjects(ctxWithUser)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	if len(projects) == 0 {
		keys.serveJSONError(ctx, w, http.StatusUnauthorized, errs.New("No project found for this user."))
		return
	}

	project := projects[0]
	name := "API_KEY_FOR_DEVELOPER_FOR_DATA_SYNC"

	_, apiKey, err := keys.service.CreateAPIKey(ctxWithUser, project.ID, name)
	if err != nil {
		if console.ErrUnauthorized.Has(err) || console.ErrNoMembership.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	accessGrantStr, err := keys.service.CreateAccessGrantForProject(ctxWithUser, project.ID, registerData.Passphrase, nil, nil, apiKey)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(accessGrantStr)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
	}
}

// GetAllAPIKeyNames returns all API key names by project ID.
func (keys *APIKeys) GetAllAPIKeyNames(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	projectIDString := r.URL.Query().Get("projectID")
	if projectIDString == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("Project ID was not provided."))
		return
	}

	projectID, err := uuid.FromString(projectIDString)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	apiKeyNames, err := keys.service.GetAllAPIKeyNamesByProjectID(ctx, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(apiKeyNames)
	if err != nil {
		keys.log.Error("failed to write json all api key names response", zap.Error(ErrAPIKeysAPI.Wrap(err)))
	}
}

// DeleteByIDs deletes API keys by given IDs.
func (keys *APIKeys) DeleteByIDs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var data struct {
		IDs []string `json:"ids"`
	}

	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var keyIDs []uuid.UUID
	for _, id := range data.IDs {
		keyID, err := uuid.FromString(id)
		if err != nil {
			keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}

		keyIDs = append(keyIDs, keyID)
	}

	err = keys.service.DeleteAPIKeys(ctx, keyIDs)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

// DeleteByNameAndProjectID deletes specific API key by it's name and project ID.
// ID here may be project.publicID or project.ID.
func (keys *APIKeys) DeleteByNameAndProjectID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	name := r.URL.Query().Get("name")
	projectIDString := r.URL.Query().Get("projectID")
	publicIDString := r.URL.Query().Get("publicID")

	if name == "" {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	var projectID uuid.UUID
	if projectIDString != "" {
		projectID, err = uuid.FromString(projectIDString)
		if err != nil {
			keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	} else if publicIDString != "" {
		projectID, err = uuid.FromString(publicIDString)
		if err != nil {
			keys.serveJSONError(ctx, w, http.StatusBadRequest, err)
			return
		}
	} else {
		keys.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("Project ID was not provided."))
		return
	}

	err = keys.service.DeleteAPIKeyByNameAndProjectID(ctx, name, projectID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		if console.ErrNoAPIKey.Has(err) {
			keys.serveJSONError(ctx, w, http.StatusNoContent, err)
			return
		}

		keys.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	// Send push notification for API key deleted (skip notification for "Web file browser API key")
	if !strings.Contains(name, "Web file browser API key") {
		go func() {
			// Use background context to avoid cancellation when HTTP request completes
			notifyCtx := context.Background()
			consoleUser, err := console.GetUser(ctx)
			if err == nil {
				notifyUserID := consoleUser.ID
				variables := map[string]interface{}{
					"api_key_name": name,
					"project_id":   projectID.String(),
				}
				if err := keys.service.SendPushNotificationByEventName(notifyCtx, notifyUserID, "api_key_deleted", "account", variables); err != nil {
					keys.log.Warn("Failed to send push notification for API key deleted",
						zap.Stringer("user_id", notifyUserID),
						zap.String("api_key_name", name),
						zap.Error(err))
				} else {
					keys.log.Debug("Successfully sent push notification for API key deleted",
						zap.Stringer("user_id", notifyUserID),
						zap.String("api_key_name", name))
				}
			}
		}()
	}
}

// serveJSONError writes JSON error to response output stream.
func (keys *APIKeys) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, keys.log, w, status, err)
}
