// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

// Package developer implements developer console endpoints for satellite.
package developer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/storj/private/emptyfs"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consolewebauth"
	"storj.io/storj/satellite/mailservice"
)

// Note: Error and mon are defined in service.go

// Assets contains either the built developer UI or it is nil.
var Assets fs.FS = emptyfs.FS{}

// Config defines configuration for developer server.
type Config struct {
	Address   string `help:"developer peer http listening address" releaseDefault:"" devDefault:""`
	StaticDir string `help:"an alternate directory path which contains the static assets to serve. When empty, it uses the embedded assets" releaseDefault:"" devDefault:""`

	JWTSecretKey string `internal:"true" help:"secret key for signing JWT tokens"`
	RateLimit    web.RateLimiterConfig
}

// DB is databases needed for the developer server.
type DB interface {
	// Console returns database for satellite console (using interface{} to avoid import cycle)
	Console() interface{}
}

// Server provides endpoints for developer console.
type Server struct {
	log *zap.Logger

	listener net.Listener
	server   http.Server

	db             DB
	analytics      *analytics.Service
	freezeAccounts interface{} // *console.AccountFreezeService - using interface{} to avoid import cycle
	service        *Service
	consoleService interface{} // *console.Service - using interface{} to avoid import cycle

	config            Config
	cookieAuth        *consolewebauth.CookieAuth
	mailService       *mailservice.Service
	ipRateLimiter     *web.RateLimiter
	userIDRateLimiter *web.RateLimiter
}

// DeveloperServerConfig contains configuration values needed for developer server endpoints.
type DeveloperServerConfig struct {
	ExternalAddress             string
	SatelliteName               string
	LetUsKnowURL                string
	TermsAndConditionsURL       string
	ContactInfoURL              string
	GeneralRequestURL           string
	DeveloperRegisterAPIKey     string
	SignupActivationCodeEnabled bool
}

// NewServer returns a new developer Server.
func NewServer(
	log *zap.Logger,
	listener net.Listener,
	db DB,
	freezeAccounts interface{}, // *console.AccountFreezeService - using interface{} to avoid import cycle
	analyticsService *analytics.Service,
	config Config,
	service *Service,
	consoleService interface{}, // *console.Service - using interface{} to avoid import cycle
	mailService *mailservice.Service,
	serverConfig DeveloperServerConfig,
	badPasswords map[string]struct{},
) (*Server, error) {
	server := &Server{
		log: log,

		listener: listener,

		db:             db,
		analytics:      analyticsService,
		freezeAccounts: freezeAccounts,
		service:        service,
		consoleService: consoleService,
		mailService:    mailService,

		config:            config,
		ipRateLimiter:     web.NewIPRateLimiter(config.RateLimit, log),
		userIDRateLimiter: newUserIDRateLimiter(config.RateLimit, log),
	}

	// Initialize cookie auth (following console pattern)
	server.cookieAuth = consolewebauth.NewCookieAuth(consolewebauth.CookieSettings{
		Name: "_developer_tokenKey",
		Path: "/",
	}, "") // AuthCookieDomain - can be set from config if needed

	root := mux.NewRouter()

	// CORS middleware
	root.Use(server.withCORS)

	// Developer API endpoints
	// Extract services using type assertion
	var consoleServicePtr *console.Service
	var accountFreezeServicePtr *console.AccountFreezeService

	if cs, ok := consoleService.(*console.Service); ok {
		consoleServicePtr = cs
	}
	if afs, ok := freezeAccounts.(*console.AccountFreezeService); ok {
		accountFreezeServicePtr = afs
	}

	// Only require accountFreezeService - consoleService is optional (not used in auth controller)
	if accountFreezeServicePtr != nil {
		developerAuthController := NewDeveloperAuth(
			log,
			consoleServicePtr, // Can be nil - not actually used in auth controller
			service,
			accountFreezeServicePtr,
			mailService,
			server.cookieAuth,
			analyticsService,
			serverConfig.SatelliteName,
			serverConfig.ExternalAddress,
			serverConfig.LetUsKnowURL,
			serverConfig.TermsAndConditionsURL,
			serverConfig.ContactInfoURL,
			serverConfig.GeneralRequestURL,
			serverConfig.DeveloperRegisterAPIKey,
			serverConfig.SignupActivationCodeEnabled,
			badPasswords,
		)
		developerAuthRouter := root.PathPrefix("/api/v0/developer/auth").Subrouter()
		developerAuthRouter.Use(server.withCORS)

		developerAuthRouter.Handle("/account", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.GetAccount))).Methods(http.MethodGet, http.MethodOptions)
		developerAuthRouter.Handle("/account", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.UpdateAccount))).Methods(http.MethodPatch, http.MethodOptions)
		developerAuthRouter.Handle("/account/change-password", server.withAuthDeveloper(server.userIDRateLimiter.Limit(http.HandlerFunc(developerAuthController.ChangePassword)))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/logout", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.Logout))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/token", server.ipRateLimiter.Limit(http.HandlerFunc(developerAuthController.Token))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/register", server.ipRateLimiter.Limit(http.HandlerFunc(developerAuthController.Register))).Methods(http.MethodPost, http.MethodOptions)

		developerAuthRouter.Handle("/code-activation", server.ipRateLimiter.Limit(http.HandlerFunc(developerAuthController.ActivateAccount))).Methods(http.MethodPatch, http.MethodOptions)
		developerAuthRouter.Handle("/refresh-session", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.RefreshSession))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/verify-reset-token", http.HandlerFunc(developerAuthController.VerifyResetToken)).Methods(http.MethodGet, http.MethodOptions)
		developerAuthRouter.Handle("/reset-password-with-token", server.ipRateLimiter.Limit(http.HandlerFunc(developerAuthController.ResetPasswordWithToken))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/reset-password-after-login", server.withAuthDeveloper(server.userIDRateLimiter.Limit(http.HandlerFunc(developerAuthController.ResetPasswordAfterFirstLogin)))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.CreateOAuthClient))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.ListOAuthClients))).Methods(http.MethodGet, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.GetOAuthClient))).Methods(http.MethodGet, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.UpdateOAuthClient))).Methods(http.MethodPut, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.DeleteOAuthClient))).Methods(http.MethodDelete, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}/status", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.UpdateOAuthClientStatus))).Methods(http.MethodPatch, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}/regenerate-secret", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.RegenerateOAuthClientSecret))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}/redirect-uris", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.AddRedirectURI))).Methods(http.MethodPost, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}/redirect-uris", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.UpdateRedirectURI))).Methods(http.MethodPut, http.MethodOptions)
		developerAuthRouter.Handle("/oauth2/clients/{id}/redirect-uris", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.DeleteRedirectURI))).Methods(http.MethodDelete, http.MethodOptions)
		// Access logs endpoints
		developerAuthRouter.Handle("/access-logs", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.ListAccessLogs))).Methods(http.MethodGet, http.MethodOptions)
		developerAuthRouter.Handle("/access-logs/statistics", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.GetAccessLogStatistics))).Methods(http.MethodGet, http.MethodOptions)
		developerAuthRouter.Handle("/access-logs/export", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.ExportAccessLogs))).Methods(http.MethodGet, http.MethodOptions)
	}

	// Static assets handler
	var staticHandler http.Handler
	if config.StaticDir == "" {
		// Embedded assets
		staticHandler = http.FileServer(http.FS(Assets))
	} else {
		// File system assets
		// For Vue.js builds, check both build/ and root directory
		buildDir := filepath.Join(config.StaticDir, "build")
		if _, err := os.Stat(buildDir); err == nil {
			// Use build/ directory (Vue.js production build)
			staticHandler = http.FileServer(http.Dir(buildDir))
		} else {
			// Use root directory
			staticHandler = http.FileServer(http.Dir(config.StaticDir))
		}
	}

	// 1. Register static assets path FIRST (before catch-all)
	// This handles /static/*, /assets/*, /favicon.ico, etc.
	// Note: Don't strip prefix for /assets/ - Vue.js build puts files in build/assets/ directory
	root.PathPrefix("/static/").Handler(http.StripPrefix("/static", staticHandler)).Methods("GET")
	root.PathPrefix("/assets/").Handler(staticHandler).Methods("GET")
	root.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		staticHandler.ServeHTTP(w, r)
	}).Methods("GET")

	// 2. SPA catch-all - serves index.html for all routes
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
			// For Vue.js builds, check both build/ and root directory
			var indexPath string
			buildIndexPath := filepath.Join(config.StaticDir, "build", "index.html")
			rootIndexPath := filepath.Join(config.StaticDir, "index.html")

			// Prefer build/ directory (Vue.js production build)
			if _, err := os.Stat(buildIndexPath); err == nil {
				indexPath = buildIndexPath
			} else {
				indexPath = rootIndexPath
			}

			http.ServeFile(w, r, indexPath)
		}
	})).Methods("GET")

	server.server.Handler = root
	return server, nil
}

// withCORS handles setting CORS-related headers on an http request.
func (server *Server) withCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, API-KEY")
		w.Header().Set("Access-Control-Expose-Headers", "*, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// withAuthDeveloper is middleware that authenticates developer requests.
func (server *Server) withAuthDeveloper(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx := r.Context()

		defer mon.Task()(&ctx)(&err)

		defer func() {
			if err != nil {
				serveJSONError(ctx, w, http.StatusUnauthorized, Error.Wrap(err))
				server.cookieAuth.RemoveTokenCookie(w)
			}
		}()

		tokenInfo, err := server.cookieAuth.GetToken(r)
		if err != nil {
			return
		}

		newCtx, err := server.service.TokenAuthForDeveloper(ctx, tokenInfo.Token, time.Now())
		if err != nil {
			return
		}
		ctx = newCtx

		handler.ServeHTTP(w, r.Clone(ctx))
	})
}

// newUserIDRateLimiter constructs a RateLimiter that limits based on developer ID.
func newUserIDRateLimiter(config web.RateLimiterConfig, log *zap.Logger) *web.RateLimiter {
	return web.NewRateLimiter(config, log, func(r *http.Request) (string, error) {
		developer, err := console.GetDeveloper(r.Context())
		if err != nil {
			return "", err
		}
		return developer.ID.String(), nil
	})
}

// serveJSONError writes JSON error to response.
func serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	errMsg := err.Error()
	if errMsg == "" {
		errMsg = http.StatusText(status)
	}

	response := map[string]string{
		"error": errMsg,
	}

	json.NewEncoder(w).Encode(response)
}

// Run starts the developer endpoint.
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
		server.ipRateLimiter.Run(ctx)
		return nil
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

// Close closes server and underlying listener.
func (server *Server) Close() error {
	return Error.Wrap(server.server.Close())
}
