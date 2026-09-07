// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

// Package seller implements seller console endpoints for satellite.
package seller

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

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/StorXNetwork/StorXMonitor/private/emptyfs"
	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/csrf"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
	"github.com/StorXNetwork/common/errs2"
)

// Assets contains either the built seller UI or it is nil.
var Assets fs.FS = emptyfs.FS{}

// Config defines configuration for seller server.
type Config struct {
	Address   string `help:"seller peer http listening address" releaseDefault:"" devDefault:""`
	StaticDir string `help:"an alternate directory path which contains the static assets to serve. When empty, it uses the embedded assets" releaseDefault:"" devDefault:""`
	// BrandingAssetsDir is the parent directory; uploads are stored flat under {dir}/reseller/.
	BrandingAssetsDir string `help:"parent directory for reseller branding uploads (logos, favicons); files go in reseller/{resellerId}/" releaseDefault:"" devDefault:""`

	JWTSecretKey          string `internal:"true" help:"secret key for signing JWT tokens"`
	CSRFProtectionEnabled bool   `help:"whether CSRF protection is enabled for seller endpoints" default:"false" testDefault:"false"`
	RateLimit             web.RateLimiterConfig
	Auth                  AuthConfig
}

// Server provides endpoints for seller console.
type Server struct {
	log *zap.Logger

	listener net.Listener
	server   http.Server

	store     DB
	analytics *analytics.Service
	service   *Service

	config        Config
	cookieAuth    *consolewebauth.CookieAuth
	csrfService   *csrf.Service
	ipRateLimiter *web.RateLimiter
}

// SellerServerConfig contains configuration values needed for seller server endpoints.
type SellerServerConfig struct {
	ExternalAddress       string
	SatelliteName         string
	LetUsKnowURL          string
	TermsAndConditionsURL string
	ContactInfoURL        string
	GeneralRequestURL     string

	GoogleClientID         string
	GoogleClientSecret     string
	GoogleOAuthRedirectURL string
	ClientOrigin           string
}

// NewServer returns a new seller Server.
func NewServer(
	log *zap.Logger,
	listener net.Listener,
	store DB,
	analyticsService *analytics.Service,
	config Config,
	service *Service,
	serverConfig SellerServerConfig,
	badPasswords map[string]struct{},
	badPasswordsEncoded string,
	csrfService *csrf.Service,
) (*Server, error) {
	socialmedia.SetClientOrigin(serverConfig.ClientOrigin)
	socialmedia.SetGoogleSocialMediaConfig(
		serverConfig.GoogleClientID,
		serverConfig.GoogleClientSecret,
		"",
		"",
	)
	socialmedia.SetGoogleSellerOAuthRedirectURL(serverConfig.GoogleOAuthRedirectURL)

	server := &Server{
		log: log,

		listener: listener,

		store:     store,
		analytics: analyticsService,
		service:   service,

		config:        config,
		csrfService:   csrfService,
		ipRateLimiter: web.NewIPRateLimiter(config.RateLimit, log),
	}

	server.cookieAuth = consolewebauth.NewCookieAuth(consolewebauth.CookieSettings{
		Name: "_seller_tokenKey",
		Path: "/",
	}, consolewebauth.CookieSettings{
		Name: "seller_sso_state",
		Path: "/",
	}, consolewebauth.CookieSettings{
		Name: "seller_sso_email_token",
		Path: "/",
	}, "")

	authController := NewSellerAuth(log, service, server.cookieAuth, serverConfig.ExternalAddress, badPasswords, badPasswordsEncoded)

	brandingAssetsRoot := config.BrandingAssetsDir
	if brandingAssetsRoot == "" {
		if config.StaticDir != "" {
			brandingAssetsRoot = config.StaticDir
		} else {
			brandingAssetsRoot = "."
		}
	}
	brandingAssets, err := NewBrandingAssets(brandingAssetsRoot)
	if err != nil {
		return nil, err
	}

	brandingController := NewSellerBranding(log, service, brandingAssets)
	domainController := NewSellerDomain(log, service)

	root := mux.NewRouter()
	root.Use(server.withCORS)

	sellerAPIRouter := root.PathPrefix("/api/v0/seller").Subrouter()
	sellerAPIRouter.Use(server.withCORS)
	sellerAPIRouter.Handle("/status", server.ipRateLimiter.Limit(http.HandlerFunc(server.statusHandler))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/config", server.ipRateLimiter.Limit(http.HandlerFunc(server.frontendConfigHandler))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/branding", server.withAuthSeller(http.HandlerFunc(brandingController.GetBranding))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/branding/create", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.CreateBranding)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAPIRouter.Handle("/branding/update", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.UpdateBranding)))).Methods(http.MethodPut, http.MethodOptions)
	sellerAPIRouter.Handle("/branding/delete", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.DeleteBranding)))).Methods(http.MethodDelete, http.MethodOptions)
	sellerAPIRouter.Handle("/branding/assets/{resellerId}/{filename}", http.HandlerFunc(brandingController.ServeBrandingAsset)).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/branding/active-theme", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.SetActiveTheme)))).Methods(http.MethodPut, http.MethodOptions)
	sellerAPIRouter.Handle("/mail-settings", server.withAuthSeller(http.HandlerFunc(brandingController.GetMailSettings))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/mail-settings/check-host", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.CheckMailHost)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAPIRouter.Handle("/mail-settings/test", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.SendTestMail)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAPIRouter.Handle("/mail-settings", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.UpdateMailSettings)))).Methods(http.MethodPut, http.MethodOptions)
	sellerAPIRouter.Handle("/themes/presets", server.withAuthSeller(http.HandlerFunc(brandingController.ListThemePresets))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/themes/custom", server.withAuthSeller(http.HandlerFunc(brandingController.ListCustomThemes))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/themes/custom", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.CreateCustomTheme)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAPIRouter.Handle("/themes/custom/{id}", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.UpdateCustomTheme)))).Methods(http.MethodPut, http.MethodOptions)
	sellerAPIRouter.Handle("/themes/custom/{id}", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(brandingController.DeleteCustomTheme)))).Methods(http.MethodDelete, http.MethodOptions)
	sellerAPIRouter.Handle("/domain", server.withAuthSeller(http.HandlerFunc(domainController.GetDomain))).Methods(http.MethodGet, http.MethodOptions)
	sellerAPIRouter.Handle("/domain/connect", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(domainController.ConnectDomain)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAPIRouter.Handle("/domain/update", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(domainController.UpdateDomain)))).Methods(http.MethodPut, http.MethodOptions)

	sellerAuthRouter := sellerAPIRouter.PathPrefix("/auth").Subrouter()
	sellerAuthRouter.Use(server.withCORS)
	sellerAuthRouter.Handle("/google", server.ipRateLimiter.Limit(http.HandlerFunc(authController.GoogleAuth))).Methods(http.MethodGet, http.MethodOptions)
	sellerAuthRouter.Handle("/token", server.withCSRFProtection(server.ipRateLimiter.Limit(http.HandlerFunc(authController.Token)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/register", server.ipRateLimiter.Limit(http.HandlerFunc(authController.Register))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/forgot-password", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ForgotPassword))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/reset-password", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ResetPassword))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/code-activation", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ActivateAccount))).Methods(http.MethodPatch, http.MethodOptions)
	sellerAuthRouter.Handle("/resend-email", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ResendEmail))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/bad-passwords", server.ipRateLimiter.Limit(http.HandlerFunc(authController.GetBadPasswords))).Methods(http.MethodGet, http.MethodOptions)
	sellerAuthRouter.Handle("/logout", server.withAuthSeller(http.HandlerFunc(authController.Logout))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/refresh-session", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.RefreshSession)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/sessions", server.withAuthSeller(http.HandlerFunc(authController.GetActiveSessions))).Methods(http.MethodGet, http.MethodOptions)
	sellerAuthRouter.Handle("/invalidate-session/{id}", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.InvalidateSessionByID)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/change-email", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.ChangeEmail)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/account", server.withAuthSeller(http.HandlerFunc(authController.GetAccount))).Methods(http.MethodGet, http.MethodOptions)
	sellerAuthRouter.Handle("/account", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.UpdateAccount)))).Methods(http.MethodPatch, http.MethodOptions)
	sellerAuthRouter.Handle("/account/delete-request", server.withAuthSeller(http.HandlerFunc(authController.DeleteAccountRequest))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/account", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.DeleteAccount)))).Methods(http.MethodDelete, http.MethodOptions)
	sellerAuthRouter.Handle("/account/change-password", server.withCSRFProtection(server.withAuthSeller(server.ipRateLimiter.Limit(http.HandlerFunc(authController.ChangePassword))))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/account/set-password", server.withCSRFProtection(server.withAuthSeller(server.ipRateLimiter.Limit(http.HandlerFunc(authController.SetPassword))))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/mfa/enable", server.withCSRFProtection(server.withAuthSeller(server.ipRateLimiter.Limit(http.HandlerFunc(authController.EnableUserMFA))))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/mfa/disable", server.withCSRFProtection(server.withAuthSeller(server.ipRateLimiter.Limit(http.HandlerFunc(authController.DisableUserMFA))))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/mfa/generate-secret-key", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.GenerateMFASecretKey)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/mfa/generate-recovery-codes", server.withCSRFProtection(server.withAuthSeller(http.HandlerFunc(authController.GenerateMFARecoveryCodes)))).Methods(http.MethodPost, http.MethodOptions)
	sellerAuthRouter.Handle("/mfa/regenerate-recovery-codes", server.withCSRFProtection(server.withAuthSeller(server.ipRateLimiter.Limit(http.HandlerFunc(authController.RegenerateMFARecoveryCodes))))).Methods(http.MethodPost, http.MethodOptions)

	var staticHandler http.Handler
	if config.StaticDir == "" {
		staticHandler = http.FileServer(http.FS(Assets))
	} else {
		buildDir := filepath.Join(config.StaticDir, "build")
		if _, err := os.Stat(buildDir); err == nil {
			staticHandler = http.FileServer(http.Dir(buildDir))
		} else {
			staticHandler = http.FileServer(http.Dir(config.StaticDir))
		}
	}

	root.PathPrefix("/static/").Handler(http.StripPrefix("/static", staticHandler)).Methods(http.MethodGet)
	root.PathPrefix("/assets/").Handler(staticHandler).Methods(http.MethodGet)
	root.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		staticHandler.ServeHTTP(w, r)
	}).Methods(http.MethodGet)

	root.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		if config.StaticDir == "" {
			indexFile, err := Assets.Open("index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer indexFile.Close()

			info, err := indexFile.Stat()
			if err != nil {
				http.NotFound(w, r)
				return
			}

			data, err := io.ReadAll(indexFile)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeContent(w, r, "index.html", info.ModTime(), bytes.NewReader(data))
			return
		}

		var indexPath string
		buildIndexPath := filepath.Join(config.StaticDir, "build", "index.html")
		rootIndexPath := filepath.Join(config.StaticDir, "index.html")

		if _, err := os.Stat(buildIndexPath); err == nil {
			indexPath = buildIndexPath
		} else {
			indexPath = rootIndexPath
		}

		http.ServeFile(w, r, indexPath)
	})).Methods(http.MethodGet)

	server.server.Handler = root

	seedThemePresets(log, store)

	return server, nil
}

// frontendConfigHandler returns seller frontend bootstrap config (captcha site keys, CSRF token, feature flags).
//
// @Summary      Get seller frontend configuration
// @Description  **Route:** `GET /api/v0/seller/config`. Public bootstrap (no auth). Call before `POST /seller/auth/token`: read `captcha.login` site keys, `csrfProtectionEnabled`, and `csrfToken` (sets `csrf_token` cookie when enabled). Controlled by `seller.csrf-protection-enabled` (not console CSRF).
// @Tags         reseller
// @Produce      json
// @Success      200  {object}  SellerFrontendConfig
// @Failure      500  {object}  SellerAuthErrorResponse
// @Router       /seller/config [get]
func (server *Server) frontendConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	csrfToken := ""
	if server.config.CSRFProtectionEnabled && server.csrfService != nil {
		existing := server.csrfService.GetCookie(r)
		if existing != "" {
			csrfToken = existing
		} else {
			token, err := server.csrfService.SetCookie(w)
			if err != nil {
				server.log.Error("failed to set CSRF cookie", zap.Error(err))
			} else {
				csrfToken = token
			}
		}
	}

	cfg := server.service.BuildFrontendConfig(server.config.CSRFProtectionEnabled, csrfToken)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(cfg); err != nil {
		server.log.Error("failed to encode seller frontend config", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// statusHandler returns seller peer health.
//
// @Summary      Seller service status
// @Description  **Route:** `GET /api/v0/seller/status`. Public health check for the seller peer.
// @Tags         reseller
// @Produce      json
// @Success      200  {object}  SellerStatusSwaggerResponse
// @Failure      500  {object}  SellerAuthErrorResponse
// @Router       /seller/status [get]
func (server *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	status, err := server.service.Status(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, Error.Wrap(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		server.log.Error("failed to encode seller status response", zap.Error(err))
	}
}

// withCSRFProtection validates the CSRF token using double-submit cookie pattern.
func (server *Server) withCSRFProtection(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !server.config.CSRFProtectionEnabled {
			handler.ServeHTTP(w, r)
			return
		}

		var err error
		ctx := r.Context()
		defer mon.Task()(&ctx)(&err)

		csrfCookie, err := r.Cookie(csrf.CookieName)
		if err != nil {
			web.ServeJSONError(ctx, server.log, w, http.StatusForbidden, errs.New("CSRF token cookie missing"))
			return
		}

		csrfHeaderToken := r.Header.Get("X-CSRF-Token")
		if csrfHeaderToken != csrfCookie.Value {
			web.ServeJSONError(ctx, server.log, w, http.StatusForbidden, errs.New("Invalid CSRF token"))
			return
		}

		if csrfHeaderToken != "" {
			if err = server.service.ValidateSecurityToken(csrfHeaderToken); err != nil {
				web.ServeJSONError(ctx, server.log, w, http.StatusForbidden, err)
				return
			}
		}

		handler.ServeHTTP(w, r)
	})
}

// withCORS handles setting CORS-related headers on an http request.
func (server *Server) withCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, API-KEY")
		w.Header().Set("Access-Control-Expose-Headers", "*, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

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

	_ = json.NewEncoder(w).Encode(response)
}

// Run starts the seller endpoint.
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
