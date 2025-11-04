// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

// Package admin implements administrative endpoints for satellite.
package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/storj/private/emptyfs"
	"storj.io/storj/satellite/accounting"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/attribution"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb"
	"storj.io/storj/satellite/console/restkeys"
	"storj.io/storj/satellite/nodeselection"
	"storj.io/storj/satellite/oidc"
	"storj.io/storj/satellite/overlay"
	"storj.io/storj/satellite/payments"
	"storj.io/storj/satellite/payments/stripe"
)

// Assets contains either the built admin/back-office/ui or it is nil.
var Assets fs.FS = emptyfs.FS{}

const (
	// UnauthorizedNotInGroup - message for when api user is not part of a required access group.
	UnauthorizedNotInGroup = "User must be a member of one of these groups to conduct this operation: %s"
	// AuthorizationNotEnabled - message for when authorization is disabled.
	AuthorizationNotEnabled = "Authorization not enabled."

	// BackOfficePathPrefix is the path prefix used for the back office router.
	BackOfficePathPrefix = "/back-office"
)

// Config defines configuration for debug server.
type Config struct {
	Address          string `help:"admin peer http listening address"                                                                              releaseDefault:"" devDefault:""`
	StaticDir        string `help:"an alternate directory path which contains the static assets to serve. When empty, it uses the embedded assets" releaseDefault:"" devDefault:""`
	AllowedOauthHost string `help:"the oauth host allowed to bypass token authentication."`
	Groups           Groups

	AuthorizationToken string `internal:"true" help:"authorization token for API key authentication (legacy)"`
	JWTSecretKey       string `internal:"true" help:"secret key for signing JWT tokens"`
}

// Groups defines permission groups.
type Groups struct {
	LimitUpdate string `help:"the group which is only allowed to update user and project limits and freeze and unfreeze accounts."`
}

// DB is databases needed for the admin server.
type DB interface {
	// ProjectAccounting returns database for storing information about project data use
	ProjectAccounting() accounting.ProjectAccounting
	// Console returns database for satellite console
	Console() console.DB
	// AdminUsers returns database for admin users
	AdminUsers() Users
	// OIDC returns the database for OIDC and OAuth information.
	OIDC() oidc.DB
	// StripeCoinPayments returns database for satellite stripe coin payments
	StripeCoinPayments() stripe.DB
	// Buckets returns database for buckets metainfo.
	Buckets() buckets.DB
	// Attribution returns database for value attribution.
	Attribution() attribution.DB
	// OverlayCache returns database for overlay information
	OverlayCache() overlay.DB
	// LiveAccounting returns database for caching project usage data
	LiveAccounting() accounting.Cache
}

// Server provides endpoints for administrative tasks.
type Server struct {
	log *zap.Logger

	listener net.Listener
	server   http.Server

	db             DB
	liveAccounting accounting.Cache
	payments       payments.Accounts
	buckets        *buckets.Service
	restKeys       *restkeys.Service
	analytics      *analytics.Service
	freezeAccounts *console.AccountFreezeService

	nowFn func() time.Time

	console    consoleweb.Config
	config     Config
	placement  nodeselection.PlacementDefinitions
	auth       *AuthService
	cookieAuth *CookieAuth
}

// NewServer returns a new administration Server.
func NewServer(
	log *zap.Logger,
	listener net.Listener,
	db DB,
	liveAccounting accounting.Cache,
	buckets *buckets.Service,
	restKeys *restkeys.Service,
	freezeAccounts *console.AccountFreezeService,
	analyticsService *analytics.Service,
	accounts payments.Accounts,
	console consoleweb.Config,
	config Config,
	placement nodeselection.PlacementDefinitions,
) (*Server, error) {
	server := &Server{
		log: log,

		listener: listener,

		db:             db,
		liveAccounting: liveAccounting,
		payments:       accounts,
		buckets:        buckets,
		restKeys:       restKeys,
		analytics:      analyticsService,
		freezeAccounts: freezeAccounts,
		nowFn:          time.Now,

		console:   console,
		config:    config,
		placement: placement,
	}

	jwtSecretKey := config.JWTSecretKey
	if jwtSecretKey == "" {
		return nil, Error.New("JWTSecretKey is required for admin authentication")
	}

	server.auth = NewAuthService(AuthConfig{
		SecretKey:  jwtSecretKey,
		Expiration: 24 * time.Hour, // 24 hour expiration
		Issuer:     "storj-admin",
	})

	// Initialize cookie auth (following console pattern)
	server.cookieAuth = NewCookieAuth(CookieSettings{
		Name: "_admin_tokenKey",
		Path: "/",
	}, "")

	// Seed super admin on startup if it doesn't exist
	seedSuperAdmin(log, db, "")

	root := mux.NewRouter()

	// N.B. This middleware has to be the first one because it has to be called
	// the earliest in the HTTP chain.
	root.Use(newTraceRequestMiddleware(log, root))

	api := root.PathPrefix("/api/").Subrouter()

	// When adding new options, also update README.md

	// prod owners only
	fullAccessAPI := api.NewRoute().Subrouter()
	fullAccessAPI.Use(server.withAuth([]string{config.Groups.LimitUpdate}, true))
	fullAccessAPI.HandleFunc("/users", server.addUser).Methods("POST")
	fullAccessAPI.HandleFunc("/users/{useremail}", server.updateUser).Methods("PUT")
	fullAccessAPI.HandleFunc("/users/{useremail}", server.deleteUser).Methods("DELETE")
	fullAccessAPI.HandleFunc("/users/{useremail}/mfa", server.disableUserMFA).Methods("DELETE")
	fullAccessAPI.HandleFunc("/users/{useremail}/deactivate-account", server.deactivateUserAccount).Methods("PUT")
	fullAccessAPI.HandleFunc("/users/{useremail}/activate-account/disable-bot-restriction", server.disableBotRestriction).
		Methods("PATCH")
	fullAccessAPI.HandleFunc("/users/{useremail}/useragent", server.updateUsersUserAgent).Methods("PATCH")
	fullAccessAPI.HandleFunc("/users/{useremail}/geofence", server.createGeofenceForAccount).Methods("PATCH")
	fullAccessAPI.HandleFunc("/users/{useremail}/geofence", server.deleteGeofenceForAccount).Methods("DELETE")
	fullAccessAPI.HandleFunc("/users/{useremail}/trial-expiration", server.updateFreeTrialExpiration).Methods("PATCH")
	fullAccessAPI.HandleFunc("/oauth/clients", server.createOAuthClient).Methods("POST")
	fullAccessAPI.HandleFunc("/oauth/clients/{id}", server.updateOAuthClient).Methods("PUT")
	fullAccessAPI.HandleFunc("/oauth/clients/{id}", server.deleteOAuthClient).Methods("DELETE")
	fullAccessAPI.HandleFunc("/projects", server.addProject).Methods("POST")
	fullAccessAPI.HandleFunc("/projects/{project}", server.renameProject).Methods("PUT")
	fullAccessAPI.HandleFunc("/projects/{project}", server.deleteProject).Methods("DELETE")
	fullAccessAPI.HandleFunc("/projects/{project}", server.getProject).Methods("GET")
	fullAccessAPI.HandleFunc("/projects/{project}/apikeys", server.addAPIKey).Methods("POST")
	fullAccessAPI.HandleFunc("/projects/{project}/apikeys", server.listAPIKeys).Methods("GET")
	fullAccessAPI.HandleFunc("/projects/{project}/apikeys", server.deleteAPIKeyByName).Methods("DELETE").Queries("name", "")
	fullAccessAPI.HandleFunc("/projects/{project}/buckets/{bucket}", server.getBucketInfo).Methods("GET")
	fullAccessAPI.HandleFunc("/projects/{project}/buckets/{bucket}/geofence", server.createGeofenceForBucket).Methods("POST")
	fullAccessAPI.HandleFunc("/projects/{project}/buckets/{bucket}/geofence", server.deleteGeofenceForBucket).Methods("DELETE")
	fullAccessAPI.HandleFunc("/projects/{project}/usage", server.checkProjectUsage).Methods("GET")
	fullAccessAPI.HandleFunc("/projects/{project}/useragent", server.updateProjectsUserAgent).Methods("PATCH")
	fullAccessAPI.HandleFunc("/projects/{project}/geofence", server.createGeofenceForProject).Methods("POST")
	fullAccessAPI.HandleFunc("/projects/{project}/geofence", server.deleteGeofenceForProject).Methods("DELETE")
	fullAccessAPI.HandleFunc("/apikeys/{apikey}", server.getAPIKey).Methods("GET")
	fullAccessAPI.HandleFunc("/apikeys/{apikey}", server.deleteAPIKey).Methods("DELETE")
	fullAccessAPI.HandleFunc("/users/{useremail}/login-history", server.getUserLoginHistory).Methods("GET")
	fullAccessAPI.HandleFunc("/restkeys/{useremail}", server.addRESTKey).Methods("POST")
	fullAccessAPI.HandleFunc("/restkeys/{apikey}/revoke", server.revokeRESTKey).Methods("PUT")

	// limit update access required
	limitUpdateAPI := api.NewRoute().Subrouter()
	limitUpdateAPI.Use(server.withAuth([]string{config.Groups.LimitUpdate}, false))
	limitUpdateAPI.HandleFunc("/users", server.getAllUsers).Methods("GET")
	limitUpdateAPI.HandleFunc("/users/{useremail}", server.userInfo).Methods("GET")
	limitUpdateAPI.HandleFunc("/nodes", server.getAllNodes).Methods("GET")
	limitUpdateAPI.HandleFunc("/nodes/stats", server.getNodeStats).Methods("GET")
	limitUpdateAPI.HandleFunc("/nodes/{nodeId}", server.getNodeDetails).Methods("GET")
	limitUpdateAPI.HandleFunc("/users/{useremail}/limits", server.userLimits).Methods("GET")
	limitUpdateAPI.HandleFunc("/users/{useremail}/limits", server.updateLimits).Methods("PUT")
	limitUpdateAPI.HandleFunc("/users/{useremail}/upgrade", server.upgradeUserAccount).Methods("POST")
	limitUpdateAPI.HandleFunc("/users/{useremail}/billing-freeze", server.billingFreezeUser).Methods("PUT")
	limitUpdateAPI.HandleFunc("/users/{useremail}/billing-freeze", server.billingUnfreezeUser).Methods("DELETE")
	limitUpdateAPI.HandleFunc("/users/{useremail}/billing-warning", server.billingUnWarnUser).Methods("DELETE")
	limitUpdateAPI.HandleFunc("/users/{useremail}/violation-freeze", server.violationFreezeUser).Methods("PUT")
	limitUpdateAPI.HandleFunc("/users/{useremail}/violation-freeze", server.violationUnfreezeUser).Methods("DELETE")
	limitUpdateAPI.HandleFunc("/users/{useremail}/legal-freeze", server.legalFreezeUser).Methods("PUT")
	limitUpdateAPI.HandleFunc("/users/{useremail}/legal-freeze", server.legalUnfreezeUser).Methods("DELETE")
	limitUpdateAPI.HandleFunc("/users/{useremail}/trial-expiration-freeze", server.trialExpirationFreezeUser).Methods("PUT")
	limitUpdateAPI.HandleFunc("/users/{useremail}/trial-expiration-freeze", server.trialExpirationUnfreezeUser).Methods("DELETE")
	limitUpdateAPI.HandleFunc("/users/pending-deletion", server.usersPendingDeletion).Methods("GET")
	limitUpdateAPI.HandleFunc("/projects/{project}/limit", server.getProjectLimit).Methods("GET")
	limitUpdateAPI.HandleFunc("/projects/{project}/limit", server.putProjectLimit).Methods("PUT")

	// Auth endpoints
	authAPI := api.NewRoute().Subrouter()
	authAPI.HandleFunc("/auth/login", server.loginHandler).Methods("POST")
	authAPI.HandleFunc("/auth/logout", server.logoutHandler).Methods("POST")

	// Current admin user endpoint (requires authentication)
	authAPIWithAuth := api.NewRoute().Subrouter()
	authAPIWithAuth.Use(server.withAuth([]string{config.Groups.LimitUpdate}, false))
	authAPIWithAuth.HandleFunc("/auth/me", server.getCurrentAdminHandler).Methods("GET")
	authAPIWithAuth.HandleFunc("/auth/me", server.updateCurrentAdminHandler).Methods("PUT")

	// Settings and Placements endpoints (public, no auth required for basic info)
	publicAPI := api.NewRoute().Subrouter()
	publicAPI.HandleFunc("/settings", server.getSettingsHandler).Methods("GET")
	publicAPI.HandleFunc("/placements", server.getPlacementsHandler).Methods("GET")

	// Static assets handler
	var staticHandler http.Handler
	if config.StaticDir == "" {
		// Embedded assets
		staticHandler = http.FileServer(http.FS(Assets))
	} else {
		// File system assets
		staticHandler = http.FileServer(http.Dir(config.StaticDir))
	}

	// 1. Register static assets path FIRST (before catch-all)
	// This handles /assets/*, /favicon.ico, etc.
	root.PathPrefix("/assets/").Handler(staticHandler).Methods("GET")
	root.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		staticHandler.ServeHTTP(w, r)
	}).Methods("GET")

	root.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip API routes - they're already handled by main router
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		// Serve index.html (SPA fallback)
		if config.StaticDir == "" {
			// Embedded assets
			indexFile, err := Assets.Open("index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer indexFile.Close()

			// Get file info for http.ServeContent
			info, err := indexFile.Stat()
			if err != nil {
				http.NotFound(w, r)
				return
			}

			// Create a ReadSeeker for http.ServeContent
			data, err := io.ReadAll(indexFile)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeContent(w, r, "index.html", info.ModTime(), bytes.NewReader(data))
		} else {
			// File system assets
			indexPath := filepath.Join(config.StaticDir, "index.html")
			http.ServeFile(w, r, indexPath)
		}
	})).Methods("GET")

	server.server.Handler = root
	return server, nil
}

// Run starts the admin endpoint.
func (server *Server) Run(ctx context.Context) error {
	if server.listener == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return Error.Wrap(server.server.Shutdown(context.Background()))
	})
	group.Go(func() error {
		defer cancel()
		err := server.server.Serve(server.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return Error.Wrap(err)
	})
	return group.Wait()
}

// SetNow allows tests to have the server act as if the current time is whatever they want.
func (server *Server) SetNow(nowFn func() time.Time) {
	server.nowFn = nowFn
}

// Close closes server and underlying listener.
func (server *Server) Close() error {
	return Error.Wrap(server.server.Close())
}

// SetAllowedOauthHost allows tests to set which address to recognize as belonging to the OAuth proxy.
func (server *Server) SetAllowedOauthHost(host string) {
	server.config.AllowedOauthHost = host
}

// adminTokenAuth validates JWT token and returns authenticated context with admin user.
func (server *Server) adminTokenAuth(ctx context.Context, tokenString string, authTime time.Time) (_ context.Context, err error) {
	defer mon.Task()(&ctx)(&err)

	claims, err := server.auth.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	adminUser, err := server.db.AdminUsers().GetByEmail(ctx, claims.Email)
	if err != nil {
		return nil, Error.New("admin user not found: %s", claims.Email)
	}

	if adminUser.Status != AdminActive {
		return nil, Error.New("admin account is not active: %s", claims.Email)
	}

	return WithAdminUser(ctx, adminUser), nil
}

// withAuth checks if the requester is authorized to perform an operation. If the request did not come from the oauth proxy, verify the auth token.
// Otherwise, check that the user has the required permissions to conduct the operation. `allowedGroups` is a list of groups that are authorized.
// If it is nil, then the api method is not accessible from the oauth proxy.
func (server *Server) withAuth(allowedGroups []string, requireAPIKey bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			ctx := r.Context()

			defer mon.Task()(&ctx)(&err)

			defer func() {
				if err != nil {
					// Remove cookie on auth failure (following console pattern)
					server.cookieAuth.RemoveTokenCookie(w)
					sendJSONError(w, "Unauthorized", err.Error(), http.StatusUnauthorized)
				}
			}()

			if server.config.AuthorizationToken == "" {
				sendJSONError(w, AuthorizationNotEnabled, "", http.StatusForbidden)
				return
			}

			if r.Host != server.config.AllowedOauthHost {
				// not behind the proxy; check for cookie token first (following console pattern)
				var tokenString string
				var foundInCookie bool

				// Try to get token from cookie first (like console)
				cookieTokenInfo, err := server.cookieAuth.GetToken(r)
				if err == nil {
					tokenString = cookieTokenInfo.Token
					foundInCookie = true
				} else {
					// Fall back to Authorization header (backward compatibility)
					authHeader := r.Header.Get("Authorization")
					if strings.HasPrefix(authHeader, "Bearer ") {
						tokenString = strings.TrimPrefix(authHeader, "Bearer ")
					}
				}

				if tokenString != "" {
					// Validate token and get authenticated context (like console's TokenAuth)
					newCtx, err := server.adminTokenAuth(ctx, tokenString, time.Now())
					if err != nil {
						if foundInCookie {
							server.cookieAuth.RemoveTokenCookie(w)
						}
						server.log.Warn("Invalid JWT token", zap.Error(err), zap.String("ip", getClientIP(r)))
						return
					}
					ctx = newCtx

					// Get admin user from context for logging
					adminUser, err := GetAdminUser(ctx)
					if err == nil {
						r.Header.Set("X-Admin-Email", adminUser.Email)
						if adminUser.Roles != nil {
							r.Header.Set("X-Admin-Role", *adminUser.Roles)
						}
					}
				} else {
					// No token found - try API key validation (backward compatibility)
					authHeader := r.Header.Get("Authorization")
					if !validateAPIKey(server.config.AuthorizationToken, authHeader) {
						sendJSONError(w, "Forbidden", "required a valid authorization token", http.StatusForbidden)
						return
					}
				}
			} else {
				var allowed bool
				userGroupsString := r.Header.Get("X-Forwarded-Groups")
				userGroups := strings.Split(userGroupsString, ",")

			AUTHENTICATED:
				for _, userGroup := range userGroups {
					if userGroup == "" {
						continue
					}
					for _, permGroup := range allowedGroups {
						if userGroup == permGroup {
							allowed = true
							break AUTHENTICATED
						}
					}
				}

				if !allowed {
					sendJSONError(w, "Forbidden", fmt.Sprintf(UnauthorizedNotInGroup, allowedGroups), http.StatusForbidden)
					return
				}

				// The operation requires to provide a valid authorization token.
				if requireAPIKey && !validateAPIKey(server.config.AuthorizationToken, r.Header.Get("Authorization")) {
					sendJSONError(
						w, "Forbidden",
						"you are part of one of the authorized groups, but this operation requires a valid authorization token",
						http.StatusForbidden,
					)
					return
				}
			}

			// Log admin action
			adminEmail := r.Header.Get("X-Admin-Email")
			if adminEmail == "" {
				adminEmail = r.Header.Get("X-Forwarded-Email")
			}
			server.log.Info("admin action",
				zap.String("user", adminEmail),
				zap.String("action", fmt.Sprintf("%s %s", r.Method, r.RequestURI)),
			)

			r.Header.Set("Cache-Control", "must-revalidate")
			// Pass authenticated context to handler (following console pattern with r.Clone)
			next.ServeHTTP(w, r.Clone(ctx))
		})
	}
}

func validateAPIKey(configured, sent string) bool {
	equality := subtle.ConstantTimeCompare([]byte(sent), []byte(configured))
	return equality == 1
}

// getSettingsHandler wraps Server.GetSettings for HTTP.
func (server *Server) getSettingsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	settings, httpErr := server.GetSettings(ctx)
	if httpErr.Err != nil {
		sendJSONError(w, "failed to get settings", httpErr.Err.Error(), httpErr.Status)
		return
	}

	data, err := json.Marshal(settings)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// getPlacementsHandler wraps Server.GetPlacements for HTTP.
func (server *Server) getPlacementsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	placements, httpErr := server.GetPlacements(ctx)
	if httpErr.Err != nil {
		sendJSONError(w, "failed to get placements", httpErr.Err.Error(), httpErr.Status)
		return
	}

	data, err := json.Marshal(placements)
	if err != nil {
		sendJSONError(w, "json encoding failed", err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

// responseWriterStatusCode is a wrapper of an http.ResponseWriter to track the
// response status code for having access to it after calling
// http.ResponseWriter.WriteHeader.
type responseWriterStatusCode struct {
	http.ResponseWriter
	code        int
	wroteHeader bool
}

func (w *responseWriterStatusCode) WriteHeader(code int) {
	if !w.wroteHeader {
		w.code = code
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *responseWriterStatusCode) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		// If Write is called before WriteHeader, default to 200
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// getClientIP gets the client IP from request headers or RemoteAddr.
// Simplified version that checks X-Forwarded-For and X-Real-Ip headers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	h := r.Header.Get("X-Forwarded-For")
	if h != "" {
		// Get the first IP value (client IP)
		ips := strings.SplitN(h, ",", 2)
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-Ip header (mostly sent by NGINX)
	h = r.Header.Get("X-Real-Ip")
	if h != "" {
		return h
	}

	return r.RemoteAddr
}

// newTraceRequestMiddleware returns middleware for tracing each request to a
// registered endpoint through Monkit. It also log in INFO level each request.
func newTraceRequestMiddleware(log *zap.Logger, root *mux.Router) mux.MiddlewareFunc {
	log = log.Named("trace-request-middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			begin := time.Now()
			ctx := r.Context()
			respWCode := responseWriterStatusCode{ResponseWriter: w, code: 0}
			defer func() {
				// Preallocate the maximum fields that we are going to use for avoiding
				// reallocations
				fields := make([]zapcore.Field, 0, 6)
				fields = append(fields,
					zap.String("method", r.Method),
					zap.String("URI", r.RequestURI),
					zap.String("IP", getClientIP(r)),
					zap.Int("response-code", respWCode.code),
					zap.Duration("elapse", time.Since(begin)),
					zap.String("path", r.URL.Path),
				)

				span := monkit.SpanFromCtx(ctx)
				if span != nil {
					fields = append(fields, zap.Int64("trace-id", span.Trace().Id()))
				}

				log.Info("client HTTP request", fields...)
			}()

			match := mux.RouteMatch{}
			root.Match(r, &match)

			pathTpl, err := match.Route.GetPathTemplate()
			if err != nil {
				log.Warn("error when getting the route template path",
					zap.Error(err), zap.String("request-uri", r.RequestURI),
				)
				next.ServeHTTP(&respWCode, r)
				return
			}

			// Limit the values accepted as an HTTP method for avoiding to create an
			// unbounded amount of metrics.
			boundMethod := r.Method
			switch r.Method {
			case http.MethodDelete:
			case http.MethodGet:
			case http.MethodHead:
			case http.MethodOptions:
			case http.MethodPatch:
			case http.MethodPost:
			case http.MethodPut:
			default:
				boundMethod = "INVALID"
			}

			stop := mon.TaskNamed("visit_task", monkit.NewSeriesTag("path", pathTpl), monkit.NewSeriesTag("method", boundMethod))(&ctx)
			r = r.WithContext(ctx)

			defer func() {
				var err error
				if respWCode.code >= http.StatusBadRequest {
					err = fmt.Errorf("%d", respWCode.code)
				}

				stop(&err)
				// Count the status codes returned by each endpoint.
				mon.Event("visit_event_by_code",
					monkit.NewSeriesTag("path", pathTpl),
					monkit.NewSeriesTag("method", boundMethod),
					monkit.NewSeriesTag("code", strconv.Itoa(respWCode.code)),
				)
			}()

			// Count the requests to each endpoint.
			mon.Event("visit_event", monkit.NewSeriesTag("path", pathTpl), monkit.NewSeriesTag("method", boundMethod))

			next.ServeHTTP(&respWCode, r)
		})
	}
}
