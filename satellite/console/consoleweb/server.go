// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/StorXNetwork/common/errs2"
	"github.com/StorXNetwork/common/http/requestid"
	"github.com/StorXNetwork/common/memory"
	"github.com/StorXNetwork/common/storxnetwork"

	"github.com/StorXNetwork/StorXMonitor/private/post"
	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/abtesting"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/csrf"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/sso"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/privateapi"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/socialmedia"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consoleapi/utils"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/staticapi"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/pushnotifications"
	"github.com/StorXNetwork/StorXMonitor/satellite/developer"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice/hubspotmails"
	"github.com/StorXNetwork/StorXMonitor/satellite/oidc"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/paymentsconfig"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/stripe"
	"github.com/StorXNetwork/StorXMonitor/satellite/tenancy"
	"github.com/StorXNetwork/common/uuid"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

var (
	// Error is satellite console error type.
	Error = errs.Class("consoleweb")

	mon = monkit.Package()
)

// Config contains configuration for console web server.
type Config struct {
	Address                   string  `help:"server address of the http api gateway and frontend app" devDefault:"127.0.0.1:0" releaseDefault:":10100"`
	FrontendAddress           string  `help:"server address of the front-end app" devDefault:"127.0.0.1:0" releaseDefault:":10200"`
	DeveloperExternalAddress  string  `help:"external endpoint for developer service (falls back to ExternalAddress if not set)" default:""`
	ExternalAddress           string  `help:"external endpoint of the satellite if hosted" default:""`
	FrontendEnable            bool    `help:"feature flag to toggle whether console back-end server should also serve front-end endpoints" default:"true"`
	BackendReverseProxy       string  `help:"the target URL of console back-end reverse proxy for local development when running a UI server" default:""`
	BillingUpgradeURL         string  `help:"full URL to billing/upgrade page (e.g., http://localhost:10002/plans)" default:""`
	BandwidthWarningThreshold float64 `help:"percentage threshold for bandwidth warning popup (0-100)" default:"80.0" testDefault:"80.0"`
	StorageWarningThreshold   float64 `help:"percentage threshold for storage warning popup (0-100)" default:"80.0" testDefault:"80.0"`

	PaymentGateway_APIKey                  string `help:"api key for payment gateway" default:""`
	PaymentGateway_APISecret               string `help:"api secret for payment gateway" default:""`
	PaymentGateway_Pay_ReqUrl              string `help:"url for payment gateway request" default:""`
	PaymentGateway_Pay_StatusUrl           string `help:"url for payment gateway status" default:""`
	PaymentGateway_Pay_Success_RedirectUrl string `help:"url for payment gateway success redirect" default:""`
	PaymentGateway_Pay_Failed_RedirectUrl  string `help:"url for payment gateway failed redirect" default:""`

	ZohoClientID     string `help:"client id for zoho oauth" default:""`
	ZohoClientSecret string `help:"client secret for zoho oauth" default:""`
	ZohoRefreshToken string `help:"refresh token for zoho oauth" default:""`

	ClientOrigin string `help:"client origin for redirection URLs" default:""`

	BackupToolsURL string `help:"Backup-Tools service URL for AutoSync stats (e.g., http://localhost:8000)" default:""`

	GoogleClientID               string `help:"client id for google oauth" default:""`
	GoogleClientSecret           string `help:"client secret for google oauth" default:""`
	GoogleSigupRedirectURLstring string `help:"redirect url for google oauth" default:""`
	GoggleLoginRedirectURLstring string `help:"redirect url for google oauth" default:""`

	FacebookClientID               string `help:"client id for facebook oauth" default:""`
	FacebookClientSecret           string `help:"client secret for facebook oauth" default:""`
	FacebookSigupRedirectURLstring string `help:"redirect url for facebook oauth" default:""`
	FacebookLoginRedirectURLstring string `help:"redirect url for facebook oauth" default:""`

	LinkedinClientID                         string `help:"client id for linkedin oauth" default:""`
	LinkedinClientSecret                     string `help:"client secret for linkedin oauth" default:""`
	LinkedinSigupRedirectURLstring           string `help:"redirect url for linkedin oauth" default:""`
	LinkedinLoginRedirectURLstring           string `help:"redirect url for linkedin oauth" default:""`
	LinkedinLoginIdTokenRedirectURLstring    string `help:"redirect url for linkedin oauth" default:""`
	LinkedinRegisterIdTokenRedirectURLstring string `help:"redirect url for linkedin oauth" default:""`

	UnstoppableDomainClientID                string `help:"redirect url for unstoppable domain oauth" default:""`
	UnstoppableDomainClientSecret            string `help:"redirect url for unstoppable domain oauth" default:""`
	UnstoppableDomainSignupRedirectURLstring string `help:"redirect url for unstoppable domain oauth" default:""`
	UnstoppableDomainLoginRedirectURLstring  string `help:"redirect url for unstoppable domain oauth" default:""`

	XClientID                string `help:"redirect url for x oauth" default:""`
	XClientSecret            string `help:"redirect url for x oauth" default:""`
	XSignupRedirectURLstring string `help:"redirect url for x oauth" default:""`
	XLoginRedirectURLstring  string `help:"redirect url for x oauth" default:""`

	PipeDriveClientID     string `help:"redirect url for x oauth" default:""`
	PipeDriveClientSecret string `help:"redirect url for x oauth" default:""`
	PipeDriveRedirectUrl  string `help:"redirect url for x oauth" default:""`

	Web3AuthContractAddress string `help:"contract address for web3 auth" default:""`
	Web3AuthAddress         string `help:"address for web3 auth" default:""`
	Web3AuthNetworkRPC      string `help:"network rpc for web3 auth" default:""`

	StaticDir string `help:"path to static resources" default:""`
	Watch     bool   `help:"whether to load templates on each request" default:"false" devDefault:"true"`

	AuthToken        string `help:"auth token needed for access to registration token creation endpoint" default:"" testDefault:"very-secret-token"`
	AuthTokenSecret  string `help:"secret used to sign auth tokens" releaseDefault:"" devDefault:"my-suppa-secret-key"`
	AuthCookieDomain string `help:"optional domain for cookies to use" default:""`

	ContactInfoURL                  string        `help:"url link to contacts page" default:"https://forum.storx.io"`
	ScheduleMeetingURL              string        `help:"url link to schedule a meeting with a storxnetwork representative" default:"https://meetings.hubspot.com/tom144/meeting-with-tom-troy"`
	LetUsKnowURL                    string        `help:"url link to let us know page" default:"https://storjlabs.atlassian.net/servicedesk/customer/portals"`
	SEO                             string        `help:"used to communicate with web crawlers and other web robots" default:"User-agent: *\nDisallow: \nDisallow: /cgi-bin/"`
	SatelliteName                   string        `help:"used to display at web satellite console" default:"Storj"`
	SatelliteOperator               string        `help:"name of organization which set up satellite" default:"Storj Labs" `
	TermsAndConditionsURL           string        `help:"url link to terms and conditions page" default:"https://www.storj.io/terms-of-service/"`
	AccountActivationRedirectURL    string        `help:"url link for account activation redirect" default:""`
	PartneredSatellites             Satellites    `help:"names and addresses of partnered satellites in JSON list format" default:"[{\"name\":\"US1\",\"address\":\"https://us1.storj.io\"},{\"name\":\"EU1\",\"address\":\"https://eu1.storj.io\"},{\"name\":\"AP1\",\"address\":\"https://ap1.storj.io\"}]"`
	GeneralRequestURL               string        `help:"url link to general request page" default:"https://supportdcs.storj.io/hc/en-us/requests/new?ticket_form_id=360000379291"`
	ProjectLimitsIncreaseRequestURL string        `help:"url link to project limit increase request page" default:"https://supportdcs.storj.io/hc/en-us/requests/new?ticket_form_id=360000683212"`
	GatewayCredentialsRequestURL    string        `help:"url link for gateway credentials requests" default:"https://auth.storjsatelliteshare.io" devDefault:"http://localhost:8000"`
	IsBetaSatellite                 bool          `help:"indicates if satellite is in beta" default:"false"`
	BetaSatelliteFeedbackURL        string        "help:\"url link for beta satellite feedback\" default:\"\""
	BetaSatelliteSupportURL         string        "help:\"url link for beta satellite support\" default:\"\""
	DocumentationURL                string        `help:"url link to documentation" default:"https://docs.storj.io/"`
	CouponCodeBillingUIEnabled      bool          `help:"indicates if user is allowed to add coupon codes to account from billing" default:"true"`
	CouponCodeSignupUIEnabled       bool          `help:"indicates if user is allowed to add coupon codes to account from signup" default:"false"`
	FileBrowserFlowDisabled         bool          `help:"indicates if file browser flow is disabled" default:"false"`
	LinksharingURL                  string        `help:"url link for linksharing requests within the application" default:"https://link.storjsatelliteshare.io" devDefault:"http://localhost:8001"`
	PublicLinksharingURL            string        `help:"url link for linksharing requests for external sharing" default:"https://link.storjshare.io" devDefault:"http://localhost:8001"`
	ComputeGatewayURL               string        `help:"url link for compute gateway requests" default:"" devDefault:"http://localhost:20300"`
	PathwayOverviewEnabled          bool          `help:"indicates if the overview onboarding step should render with pathways" default:"true"`
	LimitsAreaEnabled               bool          `help:"indicates whether limit card section of the UI is enabled" default:"true"`
	GeneratedAPIEnabled             bool          `help:"indicates if generated console api should be used" default:"true"`
	RestAPIKeysUIEnabled            bool          `help:"whether the rest API keys UI is enabled" default:"false"`
	OptionalSignupSuccessURL        string        `help:"optional url to external registration success page" default:""`
	HomepageURL                     string        `help:"url link to storj.io homepage" default:"https://www.storj.io"`
	ValdiSignUpURL                  string        `help:"url link to Valdi sign up page" default:""`
	CloudGpusEnabled                bool          `help:"whether to enable cloud GPU functionality" default:"false"`
	NativeTokenPaymentsEnabled      bool          `help:"indicates if storxnetwork native token payments system is enabled" default:"false"`
	GalleryViewEnabled              bool          `help:"whether to show new gallery view" default:"true"`
	LimitIncreaseRequestEnabled     bool          `help:"whether to allow request limit increases directly from the UI" default:"false"`
	AllowedUsageReportDateRange     time.Duration `help:"allowed usage report request date range" default:"9360h"`
	EnableRegionTag                 bool          `help:"whether to show region tag in UI" default:"false"`
	EmissionImpactViewEnabled       bool          `help:"whether emission impact view should be shown" default:"true"`
	SegmentsUIEnabled               bool          `help:"whether segments UI should be shown in project dashboard" default:"true"`
	BucketLimitsUIEnabled           bool          `help:"whether bucket limits UI should be shown in project dashboard" default:"true"`
	DaysBeforeTrialEndNotification  int           `help:"days left before trial end notification" default:"3"`
	BadPasswordsFile                string        `help:"path to a local file with bad passwords list, empty path == skip check" default:""`
	NoLimitsUiEnabled               bool          `help:"whether to show unlimited-limits UI for pro users" default:"false"`
	AltObjBrowserPagingEnabled      bool          `help:"whether simplified native s3 pagination should be enabled for the huge buckets in the object browser" default:"false"`
	AltObjBrowserPagingThreshold    int           `help:"number of objects triggering simplified native S3 pagination" default:"10000"`
	DomainsPageEnabled              bool          `help:"whether domains page should be shown" default:"false"`
	ActiveSessionsViewEnabled       bool          `help:"whether active sessions table view should be shown" default:"false"`
	ObjectLockUIEnabled             bool          `help:"whether object lock UI should be shown, regardless of whether the feature is enabled" default:"true"`
	CunoFSBetaEnabled               bool          `help:"whether prompt to join cunoFS beta is visible" default:"false"`
	ObjectMountConsultationEnabled  bool          `help:"whether object mount consultation request form is visible" default:"false"`
	CSRFProtectionEnabled           bool          `help:"whether CSRF protection is enabled for some of the endpoints" default:"false" testDefault:"false"`
	BillingStripeCheckoutEnabled    bool          `help:"whether billing stripe checkout feature is enabled" default:"false"`
	DownloadPrefixEnabled           bool          `help:"whether prefix (bucket/folder) download is enabled" default:"false"`
	ZipDownloadLimit                int           `help:"maximum number of objects allowed for a zip format download" default:"1000"`
	LiveCheckBadPasswords           bool          `help:"whether to check if provided password is in bad passwords list" default:"false"`
	UseGeneratedPrivateAPI          bool          `help:"whether to use generated private API" default:"false"`
	GhostSessionCheckEnabled        bool          `help:"whether to enable ghost session detection and notification" default:"false"`
	GhostSessionCacheLimit          int           `help:"maximum number of ghost session email timestamps to keep in memory" default:"10000"`

	OauthCodeExpiry         time.Duration `help:"how long oauth authorization codes are issued for" default:"10m"`
	OauthAccessTokenExpiry  time.Duration `help:"how long oauth access tokens are issued for" default:"24h"`
	OauthRefreshTokenExpiry time.Duration `help:"how long oauth refresh tokens are issued for" default:"720h"`

	BodySizeLimit memory.Size `help:"The maximum body size allowed to be received by the API" default:"100.00 KB"`

	// CSP configs
	CSPEnabled       bool   `help:"indicates if Content Security Policy is enabled" devDefault:"false" releaseDefault:"true"`
	FrameAncestors   string `help:"allow domains to embed the satellite in a frame, space separated" default:"tardigrade.io storxnetwork.io"`
	ImgSrcSuffix     string `help:"additional values for Content Security Policy img-src, space separated" default:"*.tardigradeshare.io *.storjshare.io *.storjsatelliteshare.io"`
	ConnectSrcSuffix string `help:"additional values for Content Security Policy connect-src, space separated" default:"*.tardigradeshare.io *.storjshare.io *.storjapi.io *.storjsatelliteshare.io"`
	MediaSrcSuffix   string `help:"additional values for Content Security Policy media-src, space separated" default:"*.tardigradeshare.io *.storjshare.io *.storjsatelliteshare.io"`

	DeveloperAPIEnabled     bool   `help:"indicates if developer API is enabled" default:"false"`
	DeveloperRegisterAPIKey string `help:"developer register API key" default:""`

	SupportEmail string `help:"support email address"`

	// RateLimit defines the configuration for the IP and userID rate limiters.
	RateLimit web.RateLimiterConfig
	// AddCardRateLimiter defines the configuration for the AddCard rate limiter.
	AddCardRateLimiter AddCardRateLimiterConfig

	ABTesting abtesting.Config

	console.Config
}

// LoginURL returns the login URL for the console.
func (c *Config) LoginURL() (string, error) {
	return url.JoinPath(c.ExternalAddress, "login")
}

// SupportURL returns the support URL for the console.
func (c *Config) SupportURL() string {
	return c.GeneralRequestURL
}

// Server represents console web server.
//
// architecture: Endpoint
type Server struct {
	log *zap.Logger

	config              Config
	service             *console.Service
	developerService    *developer.Service
	mailService         *mailservice.Service
	consoleService      *consoleservice.Service
	hubspotMailService  *hubspotmails.Service
	notificationService *pushnotifications.Service
	analytics           *analytics.Service
	abTesting           *abtesting.Service
	csrfService         *csrf.Service

	listener            net.Listener
	server              http.Server
	router              *mux.Router
	cookieAuth          *consolewebauth.CookieAuth
	developerCookieAuth *consolewebauth.CookieAuth
	ipRateLimiter       *web.RateLimiter
	userIDRateLimiter   *web.RateLimiter
	addCardRateLimiter  *web.RateLimiter
	nodeURL             storxnetwork.NodeURL

	stripePublicKey                 string
	neededTokenPaymentConfirmations int

	AnalyticsConfig analytics.Config

	minimumChargeConfig paymentsconfig.MinimumChargeConfig
	usagePrices         payments.ProjectUsagePriceModel

	errorTemplate *template.Template

	//boris
	paymentMonitor *consoleapi.Payments

	// ghostSessionEmailSent tracks when ghost session emails were last sent to users.
	// Key: userID, Value: timestamp of last email sent
	ghostSessionEmailSent  map[uuid.UUID]time.Time
	ghostSessionEmailMutex sync.Mutex

	entitlementsEnabled   bool
	ssoEnabled            bool
	productPriceSummaries []string
}

// NewServer creates new instance of console server.
func NewServer(logger *zap.Logger, config Config, service *console.Service, consoleService *consoleservice.Service, oidcService *oidc.Service,
	mailService *mailservice.Service, hubspotMailService *hubspotmails.Service, analytics *analytics.Service, abTesting *abtesting.Service,
	accountFreezeService *console.AccountFreezeService, ssoService *sso.Service, csrfService *csrf.Service, listener net.Listener,
	stripePublicKey string, neededTokenPaymentConfirmations int, nodeURL storxnetwork.NodeURL,
	analyticsConfig analytics.Config, notificationService *pushnotifications.Service, packagePlans paymentsconfig.PackagePlans, stripe *stripe.Service, developerService *developer.Service,
	minimumChargeConfig paymentsconfig.MinimumChargeConfig, usagePrices payments.ProjectUsagePriceModel, pps ProductPriceSummaries,
	entitlementsEnabled bool, ssoEnabled bool) *Server {
	initAdditionalMimeTypes()

	server := Server{
		log:                             logger,
		config:                          config,
		listener:                        listener,
		service:                         service,
		developerService:                developerService,
		mailService:                     mailService,
		notificationService:             notificationService,
		consoleService:                  consoleService,
		hubspotMailService:              hubspotMailService,
		analytics:                       analytics,
		abTesting:                       abTesting,
		csrfService:                     csrfService,
		stripePublicKey:                 stripePublicKey,
		neededTokenPaymentConfirmations: neededTokenPaymentConfirmations,
		ipRateLimiter:                   web.NewIPRateLimiter(config.RateLimit, logger),
		userIDRateLimiter:               NewUserIDRateLimiter(config.RateLimit, logger),
		addCardRateLimiter:              NewAddCardRateLimiter(config.AddCardRateLimiter, logger),
		nodeURL:                         nodeURL,
		AnalyticsConfig:                 analyticsConfig,
		minimumChargeConfig:             minimumChargeConfig,
		usagePrices:                     usagePrices,
		ghostSessionEmailSent:           make(map[uuid.UUID]time.Time),
		entitlementsEnabled:             entitlementsEnabled,
		ssoEnabled:                      ssoEnabled,
		productPriceSummaries:           pps,
	}

	server.cookieAuth = consolewebauth.NewCookieAuth(consolewebauth.CookieSettings{
		Name: "_tokenKey",
		Path: "/",
	}, consolewebauth.CookieSettings{
		Name: "sso_state",
		Path: "/",
	}, consolewebauth.CookieSettings{
		Name: "sso_email_token",
		Path: "/",
	}, server.config.AuthCookieDomain)

	server.developerCookieAuth = consolewebauth.NewCookieAuth(consolewebauth.CookieSettings{
		Name: "_developer_tokenKey",
		Path: "/",
	}, consolewebauth.CookieSettings{
		Name: "developer_sso_state",
		Path: "/",
	}, consolewebauth.CookieSettings{
		Name: "developer_sso_email_token",
		Path: "/",
	}, server.config.AuthCookieDomain)

	if server.config.ExternalAddress != "" {
		if !strings.HasSuffix(server.config.ExternalAddress, "/") {
			server.config.ExternalAddress += "/"
		}
	} else {
		server.config.ExternalAddress = "http://" + server.listener.Addr().String() + "/"
	}

	if server.config.AccountActivationRedirectURL == "" {
		server.config.AccountActivationRedirectURL = server.config.ExternalAddress + "login?activated=true"
	}

	router := mux.NewRouter()
	server.router = router

	// Add Swagger UI
	router.PathPrefix("/swagger/").Handler(http.StripPrefix("/swagger/", http.FileServer(http.Dir("swagger-ui"))))

	// N.B. This middleware has to be the first one because it has to be called
	// the earliest in the HTTP chain.
	router.Use(newTraceRequestMiddleware(logger, router))

	router.Use(tenancy.Middleware(config.WhiteLabel.HostNameIDLookup))
	router.Use(requestid.AddToContext)
	// by default, set Cache-Control=no-store for all requests
	// if requests should be cached (e.g. static assets), the cache control header can be overridden
	router.Use(cacheNoStoreMiddleware)

	// limit body size
	router.Use(newBodyLimiterMiddleware(logger.Named("body-limiter-middleware"), config.BodySizeLimit))

	if server.config.GeneratedAPIEnabled {
		consoleapi.NewProjectManagement(logger, mon, server.service, router, &apiAuth{&server})
		consoleapi.NewAPIKeyManagement(logger, mon, server.service, router, &apiAuth{&server})
		consoleapi.NewUserManagement(logger, mon, server.service, router, &apiAuth{&server})
	}

	if server.config.UseGeneratedPrivateAPI {
		privateapi.NewAuthManagement(logger, mon, server.consoleService.Users(), router, &apiCORS{&server}, &apiAuth{&server})
	}

	router.Handle("/api/v0/config", server.withCORS(http.HandlerFunc(server.frontendConfigHandler)))
	router.Handle("/api/v0/config/branding", server.withCORS(http.HandlerFunc(server.getBranding)))
	router.Handle("/api/v0/{kind}-config/{partner}", server.withCORS(http.HandlerFunc(server.partnerUIConfigHandler)))
	router.HandleFunc("/registrationToken/", server.createRegistrationTokenHandler)
	router.HandleFunc("/robots.txt", server.seoHandler)

	projectsController := consoleapi.NewProjects(logger, service)

	// Public endpoint for Backup-Tools (no auth required - validates access grant itself)
	publicProjectsRouter := router.PathPrefix("/api/v0/public/projects").Subrouter()
	publicProjectsRouter.Use(server.withCORS)
	publicProjectsRouter.Handle("/project-id-from-access-grant", http.HandlerFunc(projectsController.GetProjectIDFromAccessGrant)).Methods(http.MethodPost, http.MethodOptions)

	// Authenticated routes
	projectsRouter := router.PathPrefix("/api/v0/projects").Subrouter()
	projectsRouter.Use(server.withCORS)
	projectsRouter.Use(server.withAuth)
	projectsRouter.Handle("", http.HandlerFunc(projectsController.GetUserProjects)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("", server.withCSRFProtection(http.HandlerFunc(projectsController.CreateProject))).Methods(http.MethodPost, http.MethodOptions)
	projectsRouter.Handle("/{id}", server.withCSRFProtection(http.HandlerFunc(projectsController.UpdateProject))).Methods(http.MethodPatch, http.MethodOptions)
	projectsRouter.Handle("/{id}", server.withCSRFProtection(http.HandlerFunc(projectsController.DeleteProject))).Methods(http.MethodDelete, http.MethodOptions)
	projectsRouter.Handle("/{id}/limits", server.withCSRFProtection(http.HandlerFunc(projectsController.UpdateUserSpecifiedLimits))).Methods(http.MethodPatch, http.MethodOptions)
	projectsRouter.Handle("/{id}/limit-increase", http.HandlerFunc(projectsController.RequestLimitIncrease)).Methods(http.MethodPost, http.MethodOptions)
	projectsRouter.Handle("/{id}/members", server.withCSRFProtection(http.HandlerFunc(projectsController.DeleteMembersAndInvitations))).Methods(http.MethodDelete, http.MethodOptions)
	projectsRouter.Handle("/{id}/salt", http.HandlerFunc(projectsController.GetSalt)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/{id}/members", http.HandlerFunc(projectsController.GetMembersAndInvitations)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/{id}/members/{memberID}", server.withCSRFProtection(http.HandlerFunc(projectsController.UpdateMemberRole))).Methods(http.MethodPatch, http.MethodOptions)
	projectsRouter.Handle("/{id}/members/{memberID}", http.HandlerFunc(projectsController.GetMember)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/{id}/invite/{email}", server.withCSRFProtection(server.userIDRateLimiter.Limit(http.HandlerFunc(projectsController.InviteUser)))).Methods(http.MethodPost, http.MethodOptions)
	projectsRouter.Handle("/{id}/reinvite", server.withCSRFProtection(server.userIDRateLimiter.Limit(http.HandlerFunc(projectsController.ReinviteUsers)))).Methods(http.MethodPost, http.MethodOptions)
	projectsRouter.Handle("/{id}/invite-link", http.HandlerFunc(projectsController.GetInviteLink)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/{id}/emission", http.HandlerFunc(projectsController.GetEmissionImpact)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/{id}/config", http.HandlerFunc(projectsController.GetConfig)).Methods(http.MethodGet, http.MethodOptions)
	if entitlementsEnabled {
		projectsRouter.Handle("/{id}/migrate-pricing", server.withCSRFProtection(http.HandlerFunc(projectsController.MigratePricing))).Methods(http.MethodPost, http.MethodOptions)
	}

	projectsRouter.Handle("/invitations", http.HandlerFunc(projectsController.GetUserInvitations)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/invitations/{id}/respond", server.withCSRFProtection(http.HandlerFunc(projectsController.RespondToInvitation))).Methods(http.MethodPost, http.MethodOptions)

	usageLimitsController := consoleapi.NewUsageLimits(logger, service, server.config.AllowedUsageReportDateRange)
	projectsRouter.Handle("/{id}/usage-limits", http.HandlerFunc(usageLimitsController.ProjectUsageLimits)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/usage-limits", http.HandlerFunc(usageLimitsController.TotalUsageLimits)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/{id}/daily-usage", http.HandlerFunc(usageLimitsController.DailyUsage)).Methods(http.MethodGet, http.MethodOptions)
	projectsRouter.Handle("/usage-report", server.userIDRateLimiter.Limit(http.HandlerFunc(usageLimitsController.UsageReport))).Methods(http.MethodGet, http.MethodOptions)

	// starting zoho refresh token goroutine
	go consoleapi.ZohoRefreshTokenInit(context.Background(), config.ZohoClientID, config.ZohoClientSecret, config.ZohoRefreshToken, logger)

	// set social media config
	socialmedia.SetClientOrigin(config.ClientOrigin)
	socialmedia.SetGoogleSocialMediaConfig(config.GoogleClientID, config.GoogleClientSecret, config.GoogleSigupRedirectURLstring, config.GoggleLoginRedirectURLstring)
	socialmedia.SetFacebookSocialMediaConfig(config.FacebookClientID, config.FacebookClientSecret, config.FacebookSigupRedirectURLstring, config.FacebookLoginRedirectURLstring)
	socialmedia.SetLinkedinSocialMediaConfig(config.LinkedinClientID, config.LinkedinClientSecret, config.LinkedinSigupRedirectURLstring, config.LinkedinLoginRedirectURLstring, config.LinkedinRegisterIdTokenRedirectURLstring, config.LinkedinLoginIdTokenRedirectURLstring)
	socialmedia.SetUnstoppableDomainSocialMediaConfig(config.UnstoppableDomainClientID, config.UnstoppableDomainClientSecret, config.UnstoppableDomainSignupRedirectURLstring, config.UnstoppableDomainLoginRedirectURLstring)
	socialmedia.SetXSocialMediaConfig(config.XClientID, config.XClientSecret, config.XSignupRedirectURLstring, config.XLoginRedirectURLstring)
	socialmedia.SetPipeDriveSocialMediaConfig(config.PipeDriveClientID, config.PipeDriveClientSecret, config.PipeDriveRedirectUrl)
	badPasswords, badPasswordsEncoded, err := server.loadBadPasswords()
	if err != nil {
		server.log.Error("unable to load bad passwords list", zap.Error(err))
	}

	if server.config.CloudGpusEnabled {
		valdiController := consoleapi.NewValdi(logger, service)
		valdiRouter := router.PathPrefix("/api/v0/valdi").Subrouter()
		valdiRouter.Use(server.withCORS)
		valdiRouter.Use(server.withAuth)
		valdiRouter.Handle("/api-keys/{project-id}", server.userIDRateLimiter.Limit(http.HandlerFunc(valdiController.GetAPIKey))).Methods(http.MethodGet, http.MethodOptions)
	}

	authController := consoleapi.NewAuth(logger, service, accountFreezeService, mailService, server.cookieAuth, server.analytics, ssoService, csrfService, config.SatelliteName, server.config.ExternalAddress, config.LetUsKnowURL, config.TermsAndConditionsURL, config.ContactInfoURL, config.GeneralRequestURL, config.SignupActivationCodeEnabled, config.MemberAccountsEnabled, badPasswords, badPasswordsEncoded, config.ValidAnnouncementNames, config.WhiteLabel, config.SingleWhiteLabel)
	authRouter := router.PathPrefix("/api/v0/auth").Subrouter()
	authRouter.Use(server.withCORS)

	// removing this as we are not supporting this as of now.
	// router.HandleFunc("/registerbutton_facebook", authController.InitFacebookRegister)
	// router.HandleFunc("/facebook_register", authController.HandleFacebookRegister)
	// router.HandleFunc("/loginbutton_facebook", authController.InitFacebookLogin)
	// router.HandleFunc("/facebook_login", authController.HandleFacebookLogin)

	web3AuthController := consoleapi.NewWeb3Auth(logger, service, server.cookieAuth, "secret")
	emailWebhookController := consoleapi.NewEmailWebhook(service, mailService, server.config.Config, server.config.ExternalAddress, server.config.SupportEmail)
	pushNotificationWebhookController := consoleapi.NewPushNotificationWebhook(service, notificationService, server.config.Config, server.config.ExternalAddress, server.config.SupportEmail)
	router.HandleFunc("/upload_backup_share", web3AuthController.UploadBackupShare)
	router.HandleFunc("/get_backup_share", web3AuthController.GetBackupShare)
	router.HandleFunc("/upload_social_share", web3AuthController.UploadSocialShare)
	router.HandleFunc("/get_social_share", web3AuthController.GetSocialShare)
	router.HandleFunc("/get_sign_message_web3auth", web3AuthController.GetSignMessage)
	authRouter.Handle("/web3auth", server.ipRateLimiter.Limit(http.HandlerFunc(web3AuthController.Token))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/migrate-to-web3", server.ipRateLimiter.Limit(http.HandlerFunc(authController.MigrateToWeb3))).Methods(http.MethodPost, http.MethodOptions)

	router.Handle("/apple_register", server.ipRateLimiter.Limit(http.HandlerFunc(authController.HandleAppleRegister))).Methods(http.MethodGet, http.MethodOptions)
	router.Handle("/apple_login", server.ipRateLimiter.Limit(http.HandlerFunc(authController.LoginUserApple))).Methods(http.MethodGet, http.MethodOptions)

	router.HandleFunc("/registerbutton_linkedin", authController.InitLinkedInRegister)
	router.HandleFunc("/linkedin_register", authController.HandleLinkedInRegister)
	router.HandleFunc("/loginbutton_linkedin", authController.InitLinkedInLogin)
	router.HandleFunc("/linkedin_login", authController.HandleLinkedInLogin)
	router.HandleFunc("/linkedin_login/mobile", authController.HandleLinkedInLoginWithAuthToken)
	authRouter.Handle("/linkedin_register/mobile", server.ipRateLimiter.Limit(http.HandlerFunc(authController.HandleLinkedInRegisterWithAuthToken))).Methods(http.MethodPost, http.MethodOptions)

	// authRouter.Handle("/register-google", server.ipRateLimiter.Limit(http.HandlerFunc(authController.RegisterGoogle))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/login-google", server.ipRateLimiter.Limit(http.HandlerFunc(authController.LoginUserConfirm))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/register-google-app", server.ipRateLimiter.Limit(http.HandlerFunc(authController.RegisterGoogleForApp))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/login-google-app", server.ipRateLimiter.Limit(http.HandlerFunc(authController.LoginUserConfirmForApp))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/linkedin_id_token", server.ipRateLimiter.Limit(http.HandlerFunc(authController.HandleLinkedInIdTokenFromCode))).Methods(http.MethodPost, http.MethodOptions)

	authRouter.Handle("/account", server.withAuth(http.HandlerFunc(authController.GetAccount))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/send-email", (http.HandlerFunc(emailWebhookController.SendEmailByType))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/send-notification", (http.HandlerFunc(pushNotificationWebhookController.SendNotification))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/account", server.withAuth(http.HandlerFunc(authController.UpdateAccount))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/user", (http.HandlerFunc(authController.DeleteAccount))).Methods(http.MethodDelete, http.MethodOptions)
	authRouter.Handle("/account/setup", server.withAuth(http.HandlerFunc(authController.SetupAccount))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/account/info", server.withAuth(http.HandlerFunc(authController.UpdateAccountInfo))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/account/freezestatus", server.withAuth(http.HandlerFunc(authController.GetFreezeStatus))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/account/delete-request", server.withAuth(http.HandlerFunc(authController.DeleteAccountRequest))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/account/change-password", server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.ChangePassword)))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/account/settings", server.withAuth(http.HandlerFunc(authController.GetUserSettings))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/account/settings", server.withAuth(http.HandlerFunc(authController.SetUserSettings))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/account/onboarding", server.withAuth(http.HandlerFunc(authController.SetOnboardingStatus))).Methods(http.MethodPatch, http.MethodOptions)

	// Dashboard controller
	dashboardController := consoleapi.NewDashboard(logger, service, server.cookieAuth)
	dashboardRouter := router.PathPrefix("/api/v0/dashboard").Subrouter()
	dashboardRouter.Use(server.withCORS)
	dashboardRouter.Use(server.withAuth)
	dashboardRouter.Handle("/stats", http.HandlerFunc(dashboardController.GetDashboardStats)).Methods(http.MethodGet, http.MethodOptions)

	// User developer access management
	authRouter.Handle("/developer-access", server.withAuth(http.HandlerFunc(authController.GetUserDeveloperAccess))).Methods(http.MethodGet, http.MethodOptions)                           // Alias for frontend compatibility
	authRouter.Handle("/developer-access/{clientId}/history", server.withAuth(http.HandlerFunc(authController.GetUserDeveloperAccessHistory))).Methods(http.MethodGet, http.MethodOptions) // Alias for frontend compatibility
	authRouter.Handle("/developer-access/{clientId}/revoke", server.withAuth(http.HandlerFunc(authController.RevokeUserDeveloperAccess))).Methods(http.MethodDelete, http.MethodOptions)   // Alias for frontend compatibility

	authRouter.Handle("/mfa/enable", server.withAuth(http.HandlerFunc(authController.EnableUserMFA))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/mfa/disable", server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.DisableUserMFA)))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/mfa/generate-secret-key", server.withAuth(http.HandlerFunc(authController.GenerateMFASecretKey))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/mfa/generate-recovery-codes", server.withAuth(http.HandlerFunc(authController.GenerateMFARecoveryCodes))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/mfa/regenerate-recovery-codes", server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.RegenerateMFARecoveryCodes)))).Methods(http.MethodPost, http.MethodOptions)
	// DEPRECATED if server.config.UseGeneratedPrivateAPI == true.
	authRouter.Handle("/account", server.withAuth(http.HandlerFunc(authController.GetAccount))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/account", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.UpdateAccount)))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/account", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.DeleteAccount)))).Methods(http.MethodDelete, http.MethodOptions)
	authRouter.Handle("/account/setup", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.SetupAccount)))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/account/change-password", server.withCSRFProtection(server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.ChangePassword))))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/account/settings", server.withAuth(http.HandlerFunc(authController.GetUserSettings))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/account/settings", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.SetUserSettings)))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/account/onboarding", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.SetOnboardingStatus)))).Methods(http.MethodPatch, http.MethodOptions)
	// authRouter.Handle("/mfa/enable", server.withCSRFProtection(server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.EnableUserMFA))))).Methods(http.MethodPost, http.MethodOptions)
	// authRouter.Handle("/mfa/disable", server.withCSRFProtection(server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.DisableUserMFA))))).Methods(http.MethodPost, http.MethodOptions)
	// authRouter.Handle("/mfa/generate-secret-key", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.GenerateMFASecretKey)))).Methods(http.MethodPost, http.MethodOptions)
	// authRouter.Handle("/mfa/regenerate-recovery-codes", server.withCSRFProtection(server.withAuth(server.userIDRateLimiter.Limit(http.HandlerFunc(authController.RegenerateMFARecoveryCodes))))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/logout", server.withAuth(http.HandlerFunc(authController.Logout))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/token", server.withCSRFProtection(server.ipRateLimiter.Limit(http.HandlerFunc(authController.Token)))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/token-by-api-key", server.ipRateLimiter.Limit(http.HandlerFunc(authController.TokenByAPIKey))).Methods(http.MethodPost, http.MethodOptions)

	authRouter.Handle("/bad-passwords", server.ipRateLimiter.Limit(http.HandlerFunc(authController.GetBadPasswords))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/code-activation", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ActivateAccount))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/forgot-password", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ForgotPassword))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/resend-email", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ResendEmail))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/reset-password", server.ipRateLimiter.Limit(http.HandlerFunc(authController.ResetPassword))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/refresh-session", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.RefreshSession)))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/sessions", server.withAuth(http.HandlerFunc(authController.GetActiveSessions))).Methods(http.MethodGet, http.MethodOptions)
	authRouter.Handle("/invalidate-session/{id}", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.InvalidateSessionByID)))).Methods(http.MethodPost, http.MethodOptions)
	authRouter.Handle("/limit-increase", server.withAuth(http.HandlerFunc(authController.RequestLimitIncrease))).Methods(http.MethodPatch, http.MethodOptions)
	authRouter.Handle("/change-email", server.withCSRFProtection(server.withAuth(http.HandlerFunc(authController.ChangeEmail)))).Methods(http.MethodPost, http.MethodOptions)

	domainsController := consoleapi.NewDomains(logger, service, config.DomainsPageEnabled)
	domainsRouter := router.PathPrefix("/api/v0/domains").Subrouter()
	domainsRouter.Use(server.withCORS)
	domainsRouter.Use(server.withAuth)
	domainsRouter.Handle("/check-dns", http.HandlerFunc(domainsController.CheckDNSRecords)).Methods(http.MethodPost, http.MethodOptions)
	domainsRouter.Handle("/project/{projectID}", server.withCSRFProtection(http.HandlerFunc(domainsController.CreateDomain))).Methods(http.MethodPost, http.MethodOptions)
	domainsRouter.Handle("/project/{projectID}", server.withCSRFProtection(http.HandlerFunc(domainsController.DeleteDomain))).Methods(http.MethodDelete, http.MethodOptions)
	domainsRouter.Handle("/project/{projectID}/paged", http.HandlerFunc(domainsController.GetProjectDomains)).Methods(http.MethodGet, http.MethodOptions)
	domainsRouter.Handle("/project/{projectID}/names", http.HandlerFunc(domainsController.GetProjectAllDomainNames)).Methods(http.MethodGet, http.MethodOptions)

	// Developer endpoints moved to satellite/developer/server.go
	// These endpoints are now handled by the separate developer server
	newsletterController := consoleapi.NewNewsletter(logger, service)
	newsletterRouter := router.PathPrefix("/api/v0/newsletter").Subrouter()
	newsletterRouter.Use(server.withCORS)
	newsletterRouter.Handle("/{action}", http.HandlerFunc(newsletterController.HandleSubscription)).Methods(http.MethodPost, http.MethodOptions)

	// Push Notifications API
	pushNotificationsController := consoleapi.NewPushNotifications(logger, service)
	pushNotificationsRouter := router.PathPrefix("/api/v0/fcm-token").Subrouter()
	pushNotificationsRouter.Use(server.withCORS)
	pushNotificationsRouter.Use(server.withAuth)

	pushNotificationsRouter.Handle("", http.HandlerFunc(pushNotificationsController.RegisterToken)).Methods(http.MethodPost, http.MethodOptions)
	pushNotificationsRouter.Handle("/{tokenId}", http.HandlerFunc(pushNotificationsController.UpdateToken)).Methods(http.MethodPut, http.MethodOptions)
	pushNotificationsRouter.Handle("", http.HandlerFunc(pushNotificationsController.GetTokens)).Methods(http.MethodGet, http.MethodOptions)
	pushNotificationsRouter.Handle("/{tokenId}", http.HandlerFunc(pushNotificationsController.DeleteToken)).Methods(http.MethodDelete, http.MethodOptions)

	// User Notification Preferences API
	userNotificationPreferencesController := consoleapi.NewUserNotificationPreferences(logger, service)
	userNotificationPreferencesRouter := router.PathPrefix("/api/v0/user/notification-preferences").Subrouter()
	userNotificationPreferencesRouter.Use(server.withCORS)
	userNotificationPreferencesRouter.Use(server.withAuth)

	userNotificationPreferencesRouter.Handle("", http.HandlerFunc(userNotificationPreferencesController.GetUserPreferences)).Methods(http.MethodGet, http.MethodOptions)
	userNotificationPreferencesRouter.Handle("", http.HandlerFunc(userNotificationPreferencesController.UpsertUserPreference)).Methods(http.MethodPut, http.MethodOptions)

	// Notifications API
	notificationsController := consoleapi.NewNotifications(logger, service)
	notificationsRouter := router.PathPrefix("/api/v0/notifications").Subrouter()
	notificationsRouter.Use(server.withCORS)
	notificationsRouter.Use(server.withAuth)

	notificationsRouter.Handle("", http.HandlerFunc(notificationsController.ListNotifications)).Methods(http.MethodGet, http.MethodOptions)
	notificationsRouter.Handle("/count", http.HandlerFunc(notificationsController.GetUnreadCount)).Methods(http.MethodGet, http.MethodOptions)
	notificationsRouter.Handle("/{id}", http.HandlerFunc(notificationsController.GetNotificationDetails)).Methods(http.MethodGet, http.MethodOptions)
	notificationsRouter.Handle("/{id}/dismiss", http.HandlerFunc(notificationsController.DismissNotification)).Methods(http.MethodPut, http.MethodOptions)
	notificationsRouter.Handle("/read-all", http.HandlerFunc(notificationsController.MarkAllAsRead)).Methods(http.MethodPut, http.MethodOptions)

	/*
		if config.DeveloperAPIEnabled {
			developerAuthController := consoleapi.NewDeveloperAuth(logger, service, server.developerService, accountFreezeService, mailService, server.developerCookieAuth,
				server.analytics, config.SatelliteName, server.config.ExternalAddress, config.LetUsKnowURL, config.TermsAndConditionsURL,
				config.ContactInfoURL, config.GeneralRequestURL, config.DeveloperRegisterAPIKey, config.SignupActivationCodeEnabled, badPasswords)
			developerAuthRouter := router.PathPrefix("/api/v0/developer/auth").Subrouter()
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
			developerAuthRouter.Handle("/oauth2/clients/{id}", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.DeleteOAuthClient))).Methods(http.MethodDelete, http.MethodOptions)
			developerAuthRouter.Handle("/oauth2/clients/{id}/status", server.withAuthDeveloper(http.HandlerFunc(developerAuthController.UpdateOAuthClientStatus))).Methods(http.MethodPatch, http.MethodOptions)
		}
	*/

	oauth2API := consoleapi.NewOAuth2API(service)
	oauth2Router := router.PathPrefix("/api/v0/oauth2").Subrouter()
	oauth2Router.Use(server.withCORS)

	// these endpoints will be accessed by users only so we need to use WithAuth middleware
	oauth2Router.Handle("/request", server.withAuth(http.HandlerFunc(oauth2API.CreateOAuth2Request))).Methods(http.MethodPost, http.MethodOptions)
	oauth2Router.Handle("/consent", server.withAuth(http.HandlerFunc(oauth2API.ConsentOAuth2Request))).Methods(http.MethodPost, http.MethodOptions)
	// token endpoint is accessed by client applications, no auth middleware needed but rate limiting is required
	oauth2Router.Handle("/token", server.ipRateLimiter.Limit(server.withAuth(http.HandlerFunc(oauth2API.ExchangeOAuth2Code)))).Methods(http.MethodPost, http.MethodOptions)

	if config.ABTesting.Enabled {
		abController := consoleapi.NewABTesting(logger, abTesting)
		abRouter := router.PathPrefix("/api/v0/ab").Subrouter()
		abRouter.Use(server.withCORS)
		abRouter.Use(server.withAuth)
		abRouter.Handle("/values", http.HandlerFunc(abController.GetABValues)).Methods(http.MethodGet, http.MethodOptions)
		abRouter.Handle("/hit/{action}", http.HandlerFunc(abController.SendHit)).Methods(http.MethodPost, http.MethodOptions)
	}

	if config.BillingFeaturesEnabled {
		gatewayConfig := consoleapi.NewGatewayConfig(config.PaymentGateway_APIKey, config.PaymentGateway_APISecret,
			config.PaymentGateway_Pay_ReqUrl, config.PaymentGateway_Pay_StatusUrl, config.PaymentGateway_Pay_Success_RedirectUrl,
			config.PaymentGateway_Pay_Failed_RedirectUrl)
		paymentController := consoleapi.NewPayments(logger, service, accountFreezeService, packagePlans, stripe, gatewayConfig, mailService)
		server.paymentMonitor = paymentController

		paymentsRouter := router.PathPrefix("/api/v0/payments").Subrouter()
		paymentsRouter.Use(server.withCORS)
		paymentsRouter.Use(server.withAuth)

		allowedRoutes := []string{"/api/v0/payments/account"} // var partners can still setup stripe account
		varBlocker := newVarBlockerMiddleWare(&server, config.VarPartners, allowedRoutes)
		paymentsRouter.Use(varBlocker.withVarBlocker)
		// paymentsRouter.Handle("/payment-methods", server.userIDRateLimiter.Limit(http.HandlerFunc(paymentController.AddCardByPaymentMethodID))).Methods(http.MethodPost, http.MethodOptions)
		// paymentsRouter.Handle("/cards", server.userIDRateLimiter.Limit(http.HandlerFunc(paymentController.AddCreditCard))).Methods(http.MethodPost, http.MethodOptions)
		// paymentsRouter.HandleFunc("/cards", paymentController.MakeCreditCardDefault).Methods(http.MethodPatch, http.MethodOptions)
		// paymentsRouter.HandleFunc("/cards", paymentController.ListCreditCards).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/cards/{cardId}", paymentController.RemoveCreditCard).Methods(http.MethodDelete, http.MethodOptions)
		// paymentsRouter.HandleFunc("/account/charges", paymentController.ProjectsCharges).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/account/balance", paymentController.AccountBalance).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/account", paymentController.SetupAccount).Methods(http.MethodPost, http.MethodOptions)
		// paymentsRouter.HandleFunc("/wallet", paymentController.GetWallet).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/wallet", paymentController.ClaimWallet).Methods(http.MethodPost, http.MethodOptions)
		// paymentsRouter.HandleFunc("/wallet/payments", paymentController.WalletPayments).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/wallet/payments-with-confirmations", paymentController.WalletPaymentsWithConfirmations).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/billing-history", paymentController.BillingHistory).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/invoice-history", paymentController.InvoiceHistory).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.Handle("/coupon/apply", server.userIDRateLimiter.Limit(http.HandlerFunc(paymentController.ApplyCouponCode))).Methods(http.MethodPatch, http.MethodOptions)
		// paymentsRouter.HandleFunc("/coupon", paymentController.GetCoupon).Methods(http.MethodGet, http.MethodOptions)
		// paymentsRouter.HandleFunc("/pricing", paymentController.GetProjectUsagePriceModel).Methods(http.MethodGet, http.MethodOptions)
		// if config.PricingPackagesEnabled {
		// 	paymentsRouter.HandleFunc("/purchase-package", paymentController.PurchasePackage).Methods(http.MethodPost, http.MethodOptions)
		// 	paymentsRouter.HandleFunc("/package-available", paymentController.PackageAvailable).Methods(http.MethodGet, http.MethodOptions)
		// }
		paymentsRouter.HandleFunc("/generate-payment-link", paymentController.GeneratePaymentLink).Methods(http.MethodPost, http.MethodOptions)
		paymentsRouter.HandleFunc("/coupons", paymentController.GetCoupons).Methods(http.MethodGet, http.MethodOptions)
		paymentsRouter.HandleFunc("/invoice-history", paymentController.BillingTransactionHistory).Methods(http.MethodGet, http.MethodOptions)
		router.HandleFunc("/payment-plans", paymentController.HandlePaymentPlans).Methods(http.MethodGet, http.MethodOptions)
	}

	bucketsController := consoleapi.NewBuckets(logger, service, server.config.BillingUpgradeURL, server.config.StorageWarningThreshold, server.config.BandwidthWarningThreshold, "secret")
	bucketsRouter := router.PathPrefix("/api/v0/buckets").Subrouter()
	bucketsRouter.Use(server.withCORS)
	bucketsRouter.Use(server.withAuth)
	bucketsRouter.HandleFunc("/bucket-names", bucketsController.AllBucketNames).Methods(http.MethodGet, http.MethodOptions)
	bucketsRouter.HandleFunc("/bucket-placements", bucketsController.GetBucketMetadata).Methods(http.MethodGet, http.MethodOptions)

	// This endpoint is deprecated. A project's available placement details are now added to the project config endpoint.
	// N.B. Keep this endpoint for some time to avoid errors in old console UI builds.
	bucketsRouter.HandleFunc("/placement-details", bucketsController.GetPlacementDetails).Methods(http.MethodGet, http.MethodOptions)

	bucketsRouter.HandleFunc("/bucket-metadata", bucketsController.GetBucketMetadata).Methods(http.MethodGet, http.MethodOptions)
	bucketsRouter.HandleFunc("/bucket-migration-status", bucketsController.UpdateBucketMigrationStatus).Methods(http.MethodPut, http.MethodOptions)
	bucketsRouter.HandleFunc("/immutability-rules", bucketsController.GetImmutabilityRules).Methods(http.MethodGet, http.MethodOptions)
	bucketsRouter.HandleFunc("/update-immutability-rules", bucketsController.UpdateImmutabilityRules).Methods(http.MethodPost, http.MethodOptions)
	bucketsRouter.HandleFunc("/usage-totals", bucketsController.GetBucketTotals).Methods(http.MethodGet, http.MethodOptions)
	bucketsRouter.HandleFunc("/usage-totals-for-reserved", bucketsController.GetBucketTotalsForReservedBucket).Methods(http.MethodGet, http.MethodOptions)
	bucketsRouter.HandleFunc("/check-upload", bucketsController.CheckUpload).Methods(http.MethodPost, http.MethodOptions)
	bucketsRouter.HandleFunc("/bucket-totals", bucketsController.GetSingleBucketTotals).Methods(http.MethodGet, http.MethodOptions)

	apiKeysController := consoleapi.NewAPIKeys(logger, service)
	apiKeysRouter := router.PathPrefix("/api/v0/api-keys").Subrouter()
	apiKeysRouter.Use(server.withCORS)
	apiKeysRouter.Use(server.withAuth)
	apiKeysRouter.Handle("/create/{projectID}", server.withCSRFProtection(http.HandlerFunc(apiKeysController.CreateAPIKey))).Methods(http.MethodPost, http.MethodOptions)
	apiKeysRouter.Handle("/delete-by-name", server.withCSRFProtection(http.HandlerFunc(apiKeysController.DeleteByNameAndProjectID))).Methods(http.MethodDelete, http.MethodOptions)
	apiKeysRouter.Handle("/delete-by-ids", server.withCSRFProtection(http.HandlerFunc(apiKeysController.DeleteByIDs))).Methods(http.MethodDelete, http.MethodOptions)
	apiKeysRouter.HandleFunc("/list-paged", apiKeysController.GetProjectAPIKeys).Methods(http.MethodGet, http.MethodOptions)
	apiKeysRouter.HandleFunc("/api-key-names", apiKeysController.GetAllAPIKeyNames).Methods(http.MethodGet, http.MethodOptions)
	apiKeysRouter.Handle("/{project_id}/access-grant", http.HandlerFunc(apiKeysController.GetAccessGrant)).Methods(http.MethodGet, http.MethodOptions)

	// apiKeysDeveloperRouter := router.PathPrefix("/api/v0/api-keys/developer").Subrouter()
	// apiKeysDeveloperRouter.Use(server.withCORS)
	// apiKeysDeveloperRouter.Use(server.withAutDeveloper)
	// apiKeysDeveloperRouter.Handle("/access-grant", http.HandlerFunc(apiKeysController.GetAccessGrantForDeveloper)).Methods(http.MethodPost, http.MethodOptions)

	if server.config.RestAPIKeysUIEnabled && server.config.UseNewRestKeysTable {
		restKeysController := consoleapi.NewRestAPIKeys(logger, service)
		restKeysRouter := router.PathPrefix("/api/v0/restkeys").Subrouter()
		restKeysRouter.Use(server.withCORS)
		restKeysRouter.Use(server.withAuth)
		restKeysRouter.Handle("", http.HandlerFunc(restKeysController.GetUserRestAPIKeys)).Methods(http.MethodGet, http.MethodOptions)
		restKeysRouter.Handle("", server.withCSRFProtection(http.HandlerFunc(restKeysController.CreateRestKey))).Methods(http.MethodPost, http.MethodOptions)
		restKeysRouter.Handle("", server.withCSRFProtection(http.HandlerFunc(restKeysController.RevokeRestKeys))).Methods(http.MethodDelete, http.MethodOptions)
	}

	analyticsController := consoleapi.NewAnalytics(logger, service, server.analytics)

	analyticsPath := "/api/v0/analytics"
	router.HandleFunc(analyticsPath+"/pageview", analyticsController.PageViewTriggered).Methods(http.MethodPost, http.MethodOptions)
	if analyticsConfig.HubSpot.AccountObjectCreatedWebhookEnabled {
		router.HandleFunc(analyticsConfig.HubSpot.AccountObjectCreatedWebhookEndpoint, analyticsController.AccountObjectCreated).Methods(http.MethodPost, http.MethodOptions)
	}
	analyticsRouter := router.PathPrefix(analyticsPath).Subrouter()
	analyticsRouter.Use(server.withCSRFProtection)
	analyticsRouter.Use(server.withCORS)
	analyticsRouter.Use(server.withAuth)
	analyticsRouter.HandleFunc("/event", analyticsController.EventTriggered).Methods(http.MethodPost, http.MethodOptions)
	analyticsRouter.HandleFunc("/page", analyticsController.PageEventTriggered).Methods(http.MethodPost, http.MethodOptions)
	analyticsRouter.HandleFunc("/join-cunofs-beta", analyticsController.JoinCunoFSBeta).Methods(http.MethodPost, http.MethodOptions)
	analyticsRouter.HandleFunc("/object-mount-consultation", analyticsController.RequestObjectMountConsultation).Methods(http.MethodPost, http.MethodOptions)
	analyticsRouter.HandleFunc("/join-placement-waitlist", analyticsController.JoinPlacementWaitlist).Methods(http.MethodPost, http.MethodOptions)
	analyticsRouter.Handle("/send-feedback", server.userIDRateLimiter.Limit(http.HandlerFunc(analyticsController.SendFeedback))).Methods(http.MethodPost, http.MethodOptions)

	oidc := oidc.NewEndpoint(
		server.nodeURL, server.config.ExternalAddress,
		logger, oidcService, service,
		server.config.OauthCodeExpiry, server.config.OauthAccessTokenExpiry, server.config.OauthRefreshTokenExpiry,
	)

	router.HandleFunc("/api/v0/.well-known/openid-configuration", oidc.WellKnownConfiguration)
	router.Handle("/api/v0/oauth/v2/authorize", server.withAuth(http.HandlerFunc(oidc.AuthorizeUser))).Methods(http.MethodPost)
	router.Handle("/api/v0/oauth/v2/tokens", server.ipRateLimiter.Limit(http.HandlerFunc(oidc.Tokens))).Methods(http.MethodPost)
	router.Handle("/api/v0/oauth/v2/userinfo", server.ipRateLimiter.Limit(http.HandlerFunc(oidc.UserInfo))).Methods(http.MethodGet)
	router.Handle("/api/v0/oauth/v2/clients/{id}", server.withAuth(http.HandlerFunc(oidc.GetClient))).Methods(http.MethodGet)

	if ssoEnabled {
		ssoRouter := router.PathPrefix("/sso").Subrouter()
		ssoRouter.Handle("/url", server.ipRateLimiter.Limit(http.HandlerFunc(authController.GetSsoUrl)))
		ssoRouter.Handle("/{provider}", server.ipRateLimiter.Limit(http.HandlerFunc(authController.BeginSsoFlow)))
		ssoRouter.Handle("/{provider}/callback", server.ipRateLimiter.Limit(http.HandlerFunc(authController.AuthenticateSso)))
	}

	if server.config.GeneratedAPIEnabled {
		rawUrl := server.config.ExternalAddress + "public/v1"
		target, err := url.Parse(rawUrl)
		if err != nil {
			server.log.Error("unable to parse satellite address", zap.String("url", rawUrl), zap.Error(err))
		} else {
			// this proxy is for backward compatibility with old code that uses the old /api/v0
			// prefix for the generated API. It proxies these requests to the new /public/v1 prefix.
			proxy := &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, "/api/v0")
					r.SetURL(target)
				},
			}
			router.PathPrefix(`/api/v0/{*}`).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxy.ServeHTTP(w, r)
			}))
		}
	}

	router.HandleFunc("/invited", server.handleInvited)
	router.HandleFunc("/activation", server.accountActivationHandler)
	router.HandleFunc("/cancel-password-recovery", server.cancelPasswordRecoveryHandler)
	router.Handle("/contactus", server.withCORS(http.HandlerFunc(server.handleContactUs)))
	router.Handle("/blog-list", server.withCORS(http.HandlerFunc(staticapi.HandleBlogList)))
	router.Handle("/guides", server.withCORS(http.HandlerFunc(staticapi.HandleGuides)))
	router.Handle("/resources-list", server.withCORS(http.HandlerFunc(staticapi.HandleResources)))
	router.Handle("/user-guideline-for-app", server.withCORS(http.HandlerFunc(staticapi.HandleUserGuidelineforApp)))

	if server.config.StaticDir != "" && server.config.FrontendEnable {
		fs := http.FileServer(http.Dir(server.config.StaticDir))
		router.PathPrefix("/static/").Handler(server.withCORS(server.brotliMiddleware(http.StripPrefix("/static", fs))))
		router.HandleFunc("/google665de0676f5e8d68.html", server.googleVerificationHandler("google665de0676f5e8d68.html"))
		router.HandleFunc("/googled09d42a140c27991.html", server.googleVerificationHandler("googled09d42a140c27991.html"))
		router.HandleFunc("/trust-source", server.trustSourceHandler)
		router.PathPrefix("/").Handler(server.withCORS(http.HandlerFunc(server.appHandler)))
	}

	server.server = http.Server{
		Handler:        server.withRequest(router),
		MaxHeaderBytes: ContentLengthLimit.Int(),
	}

	return &server
}

// Run starts the server that host webapp and api endpoint.
func (server *Server) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = server.loadErrorTemplate()
	if err != nil {
		return Error.Wrap(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return server.server.Shutdown(context.Background())
	})
	group.Go(func() error {
		server.ipRateLimiter.Run(ctx)
		return nil
	})
	group.Go(func() error {
		server.userIDRateLimiter.Run(ctx)
		return nil
	})
	group.Go(func() error {
		server.addCardRateLimiter.Run(ctx)
		return nil
	})
	group.Go(func() error {
		server.runGhostSessionCacheCleanup(ctx)
		return nil
	})
	group.Go(func() error {
		defer cancel()
		err := server.server.Serve(server.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return err
	})

	// paymentMonitor should be not nil before calling its methods
	if server.paymentMonitor != nil {
		server.paymentMonitor.StartMonitoringUserProjects(ctx)
	}

	return group.Wait()
}

// NewFrontendServer creates new instance of console front-end server.
// NB: The return type is currently consoleweb.Server, but it does not contain all the dependencies.
// It should only be used with RunFrontEnd and Close. We plan on moving this to its own type, but
// right now since we have a feature flag to allow the backend server to continue serving the frontend, it
// makes it easier if they are the same type.
func NewFrontendServer(logger *zap.Logger, config Config, listener net.Listener, nodeURL storxnetwork.NodeURL, csrfService *csrf.Service, stripePublicKey string) (server *Server, err error) {
	server = &Server{
		log:             logger,
		config:          config,
		listener:        listener,
		nodeURL:         nodeURL,
		stripePublicKey: stripePublicKey,
		csrfService:     csrfService,
	}

	router := mux.NewRouter()

	// N.B. This middleware has to be the first one because it has to be called
	// the earliest in the HTTP chain.
	router.Use(newTraceRequestMiddleware(logger, router))
	// by default, set Cache-Control=no-store for all requests
	// if requests should be cached (e.g. static assets), the cache control header can be overridden
	router.Use(cacheNoStoreMiddleware)

	// in local development, proxy certain requests to the console back-end server
	if config.BackendReverseProxy != "" {
		target, err := url.Parse(config.BackendReverseProxy)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)

		router.PathPrefix("/api").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		}))
		router.PathPrefix("/oauth").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		}))
		router.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
		router.HandleFunc("/invited", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
		router.HandleFunc("/activation", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
		router.HandleFunc("/cancel-password-recovery", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
		router.HandleFunc("/registrationToken/", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
		router.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
	}

	fs := http.FileServer(http.Dir(server.config.StaticDir))

	router.HandleFunc("/robots.txt", server.seoHandler)
	router.HandleFunc("/google665de0676f5e8d68.html", server.googleVerificationHandler("google665de0676f5e8d68.html"))
	router.HandleFunc("/googled09d42a140c27991.html", server.googleVerificationHandler("googled09d42a140c27991.html"))
	router.HandleFunc("/trust-source", server.trustSourceHandler)

	router.PathPrefix("/static/").Handler(server.brotliMiddleware(http.StripPrefix("/static", fs)))
	router.HandleFunc("/config", server.frontendConfigHandler)
	router.PathPrefix("/").Handler(server.withCORS(http.HandlerFunc(server.appHandler)))

	server.server = http.Server{
		Handler:        server.withRequest(router),
		MaxHeaderBytes: ContentLengthLimit.Int(),
	}
	return server, nil
}

// RunFrontend starts the server that runs the webapp.
func (server *Server) RunFrontend(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() error {
		<-ctx.Done()
		return server.server.Shutdown(context.Background())
	})
	group.Go(func() error {
		defer cancel()
		err := server.server.Serve(server.listener)
		if errs2.IsCanceled(err) || errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return err
	})
	return group.Wait()
}

// Close closes server and underlying listener.
func (server *Server) Close() error {
	return server.server.Close()
}

func cacheNoStoreMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		handler.ServeHTTP(w, r)
	})
}

// setAppHeaders sets the necessary headers for requests to the app.
func (server *Server) setAppHeaders(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()

	if server.config.CSPEnabled {
		connectSrc := fmt.Sprintf("connect-src 'self' %s %s %s", server.config.ConnectSrcSuffix, server.config.GatewayCredentialsRequestURL, server.config.ComputeGatewayURL)
		scriptSrc := "script-src 'sha256-wAqYV6m2PHGd1WDyFBnZmSoyfCK0jxFAns0vGbdiWUA=' 'nonce-dQw4w9WgXcQ' 'self' *.stripe.com"
		// Those are hashes of charts custom tooltip inline styles. They have to be updated if styles are updated.
		styleSrc := "style-src 'unsafe-hashes' 'sha256-7mY2NKmZ4PuyjGUa4FYC5u36SxXdoUM/zxrlr3BEToo=' 'sha256-PRTMwLUW5ce9tdiUrVCGKqj6wPeuOwGogb1pmyuXhgI=' 'sha256-kwpt3lQZ21rs4cld7/uEm9qI5yAbjYzx+9FGm/XmwNU=' 'sha256-Qf4xqtNKtDLwxce6HLtD5Y6BWpOeR7TnDpNSo+Bhb3s=' 'nonce-dQw4w9WgXcQ' 'self'"
		frameSrc := "frame-src 'self' *.stripe.com " + server.config.PublicLinksharingURL
		objectSrc := "object-src 'self' " + server.config.PublicLinksharingURL + " " + server.config.LinksharingURL

		appendValues := func(str string, vals ...string) string {
			for _, v := range vals {
				str = fmt.Sprintf("%s %s", str, v)
			}
			return str
		}

		if server.config.Captcha.Login.Hcaptcha.Enabled || server.config.Captcha.Registration.Hcaptcha.Enabled {
			hcap := "https://hcaptcha.com *.hcaptcha.com"
			connectSrc = appendValues(connectSrc, hcap)
			scriptSrc = appendValues(scriptSrc, hcap)
			styleSrc = appendValues(styleSrc, hcap)
			frameSrc = appendValues(frameSrc, hcap)
		}
		if server.config.Captcha.Login.Recaptcha.Enabled || server.config.Captcha.Registration.Recaptcha.Enabled {
			recap := "https://www.google.com/recaptcha/"
			recapSubdomain := "https://recaptcha.google.com/recaptcha/"
			gstatic := "https://www.gstatic.com/recaptcha/"
			scriptSrc = appendValues(scriptSrc, recap, gstatic)
			frameSrc = appendValues(frameSrc, recap, recapSubdomain)
		}
		cspValues := []string{
			"default-src 'self'",
			connectSrc,
			scriptSrc,
			styleSrc,
			frameSrc,
			objectSrc,
			"frame-ancestors " + server.config.FrameAncestors,
			"img-src 'self' data: blob: " + server.config.ImgSrcSuffix,
			"media-src 'self' blob: " + server.config.MediaSrcSuffix,
		}

		header.Set("Content-Security-Policy", strings.Join(cspValues, "; "))
	}

	header.Set(contentType, "text/html; charset=UTF-8")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "same-origin") // Only expose the referring url when navigating around the satellite itself.
}

// loadBadPasswords loads the bad passwords from a file into a map and encoded string.
func (server *Server) loadBadPasswords() (map[string]struct{}, string, error) {
	if server.config.BadPasswordsFile == "" {
		return nil, "", nil
	}

	bytes, err := os.ReadFile(server.config.BadPasswordsFile)
	if err != nil {
		return nil, "", err
	}

	badPasswords := make(map[string]struct{})
	parsedPasswords := strings.Split(string(bytes), "\n")
	for _, p := range parsedPasswords {
		if p != "" {
			badPasswords[p] = struct{}{}
		}
	}

	return badPasswords, base64.StdEncoding.EncodeToString(bytes), nil
}

// appHandler is web app http handler function.
func (server *Server) appHandler(w http.ResponseWriter, r *http.Request) {
	server.setAppHeaders(w, r)

	path := filepath.Join(server.config.StaticDir, "dist", "index.html")
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			server.log.Error("index.html was not generated. run 'npm run build' in the "+server.config.StaticDir+" directory", zap.Error(err))
		} else {
			server.log.Error("error loading index.html", zap.String("path", path), zap.Error(err))
		}
		return
	}

	defer func() {
		if err := file.Close(); err != nil {
			server.log.Error("error closing index.html", zap.String("path", path), zap.Error(err))
		}
	}()

	info, err := file.Stat()
	if err != nil {
		server.log.Error("failed to retrieve index.html file info", zap.Error(err))
		return
	}

	http.ServeContent(w, r, path, info.ModTime(), file)
}

// googleVerificationHandler handles the google verification file.
func (server *Server) googleVerificationHandler(googleHTML string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(`google-site-verification: ` + googleHTML))
	})
}

// oauth2IntegrationHandler handles the oauth2 integration.
func (server *Server) trustSourceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(`12w2YPMMyNGdeiMuQN2uBi5hkDpmdMBqd2kyZ7SbmBwtei7XTa4@217.147.93.13:10000`))
}

// varBlockerMiddleWare is a middleware that blocks requests from VAR partners.
type varBlockerMiddleWare struct {
	partners map[string]struct{}
	server   *Server
	// routes that should be allowed by the varBlocker regardless
	// of whether the request is from a VAR partner user or not
	allowedRoutes map[string]struct{}
}

// newVarBlockerMiddleWare creates a new instance of varBlocker.
func newVarBlockerMiddleWare(server *Server, varPartners []string, allowedRoutes []string) *varBlockerMiddleWare {
	partners := make(map[string]struct{}, len(varPartners))
	for _, partner := range varPartners {
		partners[partner] = struct{}{}
	}
	allowed := make(map[string]struct{}, len(allowedRoutes))
	for _, route := range allowedRoutes {
		allowed[route] = struct{}{}
	}
	return &varBlockerMiddleWare{
		partners:      partners,
		server:        server,
		allowedRoutes: allowed,
	}
}

// withVarBlocker blocks requests from VAR partners.
func (v *varBlockerMiddleWare) withVarBlocker(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx := r.Context()

		defer mon.Task()(&ctx)(&err)

		if _, ok := v.allowedRoutes[r.URL.Path]; !ok {
			user, err := console.GetUser(ctx)
			if err != nil {
				web.ServeJSONError(ctx, v.server.log, w, http.StatusForbidden, Error.Wrap(err))
				return
			}
			if _, ok := v.partners[string(user.UserAgent)]; ok {
				web.ServeJSONError(ctx, v.server.log, w, http.StatusForbidden, errs.New("VAR Partner not supported"))
				return
			}
		}

		handler.ServeHTTP(w, r.Clone(ctx))
	})
}

// withCORS handles setting CORS-related headers on an http request.
func (server *Server) withCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, API-KEY")
		w.Header().Set("Access-Control-Expose-Headers", "*, Authorization")

		if r.Method == http.MethodOptions {
			match := &mux.RouteMatch{}
			if server.router.Match(r, match) {
				methods, err := match.Route.GetMethods()
				if err == nil && len(methods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
				}
			}
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// withAuth performs initial authorization before every request.
func (server *Server) withAuth(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx := r.Context()

		defer mon.Task()(&ctx)(&err)

		defer func() {
			if err != nil {
				web.ServeJSONError(ctx, server.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
				server.cookieAuth.RemoveTokenCookie(w)
			}
		}()

		tokenInfo, err := server.cookieAuth.GetToken(r)
		if err != nil {
			return
		}

		newCtx, session, err := server.service.TokenAuth(ctx, tokenInfo.Token, time.Now())
		if err != nil {
			return
		}
		ctx = newCtx

		if server.config.GhostSessionCheckEnabled {
			if gsErr := server.checkGhostSession(ctx, r, session); gsErr != nil {
				server.log.Error("failed to check ghost session", zap.Error(gsErr))
			}
		}

		handler.ServeHTTP(w, r.Clone(ctx))
	})
}

// withAuthDeveloper middleware moved to satellite/developer/server.go
// This middleware is now handled by the separate developer server
/*
// withAuth performs initial authorization before every request.
func (server *Server) withAuthDeveloper(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		ctx := r.Context()

		defer mon.Task()(&ctx)(&err)

		defer func() {
			if err != nil {
				web.ServeJSONError(ctx, server.log, w, http.StatusUnauthorized, console.ErrUnauthorized.Wrap(err))
				server.developerCookieAuth.RemoveTokenCookie(w)
			}
		}()

		tokenInfo, err := server.developerCookieAuth.GetToken(r)
		if err != nil {
			return
		}

		newCtx, err := server.developerService.TokenAuthForDeveloper(ctx, tokenInfo.Token, time.Now())
		if err != nil {
			return
		}
		ctx = newCtx

		handler.ServeHTTP(w, r.Clone(ctx))
	})
}
*/

func (server *Server) checkGhostSession(ctx context.Context, r *http.Request, session *consoleauth.WebappSession) error {
	if session == nil {
		return nil
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		return err
	}
	userAgent := r.UserAgent()

	if session.UserAgent != userAgent || session.Address != ip {
		user, err := console.GetUser(ctx)
		if err != nil {
			return err
		}

		// Atomic check-and-send operation to prevent race conditions.
		server.ghostSessionEmailMutex.Lock()
		defer server.ghostSessionEmailMutex.Unlock()

		lastSent, exists := server.ghostSessionEmailSent[user.ID]
		if exists && time.Since(lastSent) < 2*time.Hour {
			return nil // Email sent recently, skip.
		}

		// Simple size limit: if we're at capacity, remove a random entry.
		if len(server.ghostSessionEmailSent) >= server.config.GhostSessionCacheLimit {
			for cached := range server.ghostSessionEmailSent {
				if cached != user.ID {
					delete(server.ghostSessionEmailSent, cached)
					break
				}
			}
		}

		server.ghostSessionEmailSent[user.ID] = time.Now()
		server.hubspotMailService.SendAsync(ctx, &hubspotmails.SendEmailRequest{
			Kind: hubspotmails.GhostSessionWarning,
			To:   user.Email,
		})
	}

	return nil
}

// runGhostSessionCacheCleanup periodically cleans up old ghost session email timestamps to prevent memory leaks.
func (server *Server) runGhostSessionCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Clean up daily.
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Remove timestamps older than 24 hours.
			cutoff := time.Now().Add(-24 * time.Hour)
			server.ghostSessionEmailMutex.Lock()

			var removed int
			for userID, timestamp := range server.ghostSessionEmailSent {
				if timestamp.Before(cutoff) {
					delete(server.ghostSessionEmailSent, userID)
					removed++
				}
			}

			server.ghostSessionEmailMutex.Unlock()

			server.log.Info("Cleaned up old ghost session email timestamps", zap.Int("removed", removed))
		}
	}
}

// withRequest ensures the http request itself is reachable from the context.
func (server *Server) withRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.Clone(console.WithRequest(r.Context(), r)))
	})
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
			err = server.service.ValidateSecurityToken(csrfHeaderToken)
			if err != nil {
				web.ServeJSONError(ctx, server.log, w, http.StatusForbidden, err)
				return
			}
		}

		handler.ServeHTTP(w, r)
	})
}

// frontendConfigHandler handles sending the frontend config to the client.
func (server *Server) frontendConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	csrfToken := ""
	if server.config.CSRFProtectionEnabled {
		existing := server.csrfService.GetCookie(r)
		if existing != "" {
			// If the CSRF cookie already exists, use it.
			// This is to prevent setting a new CSRF token on every request and resolve multi-tab issue.
			csrfToken = existing
		} else {
			token, err := server.csrfService.SetCookie(w)
			if err != nil {
				server.log.Error("Failed to set CSRF cookie", zap.Error(err))
			} else {
				csrfToken = token
			}
		}
	}

	minimumChargeDate, err := server.minimumChargeConfig.GetEffectiveDate()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		server.log.Error("failed to get minimum charge date", zap.Error(err))
		return
	}

	var newPricingStartDate *time.Time
	if server.config.NewPricingStartDate != "" {
		date, err := time.Parse("2006-01-02", server.config.NewPricingStartDate)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			server.log.Error("failed to get new pricing date", zap.Error(err))
			return
		}

		newPricingStartDate = &date
	}

	apiBase := server.getExternalAddress(ctx)
	cfg := FrontendConfig{
		ExternalAddress:                   apiBase,
		ApiBaseURL:                        apiBase,
		SatelliteName:                     server.config.SatelliteName,
		SatelliteNodeURL:                  server.nodeURL.String(),
		StripePublicKey:                   server.stripePublicKey,
		PartneredSatellites:               server.config.PartneredSatellites,
		DefaultProjectLimit:               server.config.DefaultProjectLimit,
		GeneralRequestURL:                 server.config.GeneralRequestURL,
		ProjectLimitsIncreaseRequestURL:   server.config.ProjectLimitsIncreaseRequestURL,
		GatewayCredentialsRequestURL:      server.config.GatewayCredentialsRequestURL,
		IsBetaSatellite:                   server.config.IsBetaSatellite,
		BetaSatelliteFeedbackURL:          server.config.BetaSatelliteFeedbackURL,
		BetaSatelliteSupportURL:           server.config.BetaSatelliteSupportURL,
		DocumentationURL:                  server.config.DocumentationURL,
		CouponCodeBillingUIEnabled:        server.config.CouponCodeBillingUIEnabled,
		CouponCodeSignupUIEnabled:         server.config.CouponCodeSignupUIEnabled,
		FileBrowserFlowDisabled:           server.config.FileBrowserFlowDisabled,
		LinksharingURL:                    server.config.LinksharingURL,
		PublicLinksharingURL:              server.config.PublicLinksharingURL,
		PathwayOverviewEnabled:            server.config.PathwayOverviewEnabled,
		DefaultPaidStorageLimit:           server.config.UsageLimits.Storage.Paid,
		DefaultPaidBandwidthLimit:         server.config.UsageLimits.Bandwidth.Paid,
		Captcha:                           server.config.Captcha,
		LimitsAreaEnabled:                 server.config.LimitsAreaEnabled,
		InactivityTimerEnabled:            server.config.Session.InactivityTimerEnabled,
		InactivityTimerDuration:           server.config.Session.InactivityTimerDuration,
		InactivityTimerViewerEnabled:      server.config.Session.InactivityTimerViewerEnabled,
		OptionalSignupSuccessURL:          server.config.OptionalSignupSuccessURL,
		HomepageURL:                       server.config.HomepageURL,
		NativeTokenPaymentsEnabled:        server.config.NativeTokenPaymentsEnabled,
		PasswordMinimumLength:             console.PasswordMinimumLength,
		PasswordMaximumLength:             console.PasswordMaximumLength,
		ABTestingEnabled:                  server.config.ABTesting.Enabled,
		PricingPackagesEnabled:            server.config.PricingPackagesEnabled,
		GalleryViewEnabled:                server.config.GalleryViewEnabled,
		NeededTransactionConfirmations:    server.neededTokenPaymentConfirmations,
		BillingFeaturesEnabled:            server.config.BillingFeaturesEnabled,
		UnregisteredInviteEmailsEnabled:   server.config.UnregisteredInviteEmailsEnabled,
		UserBalanceForUpgrade:             server.config.UserBalanceForUpgrade,
		LimitIncreaseRequestEnabled:       server.config.LimitIncreaseRequestEnabled,
		SignupActivationCodeEnabled:       server.config.SignupActivationCodeEnabled,
		AllowedUsageReportDateRange:       server.config.AllowedUsageReportDateRange,
		EnableRegionTag:                   server.config.EnableRegionTag,
		EmissionImpactViewEnabled:         server.config.EmissionImpactViewEnabled,
		SegmentsUIEnabled:                 server.config.SegmentsUIEnabled,
		AnalyticsEnabled:                  server.AnalyticsConfig.Enabled,
		DaysBeforeTrialEndNotification:    server.config.DaysBeforeTrialEndNotification,
		ObjectBrowserKeyNamePrefix:        server.config.ObjectBrowserKeyNamePrefix,
		ObjectBrowserKeyLifetime:          server.config.ObjectBrowserKeyLifetime,
		MaxNameCharacters:                 server.config.MaxNameCharacters,
		BillingInformationTabEnabled:      server.config.BillingInformationTabEnabled,
		SatelliteManagedEncryptionEnabled: server.config.SatelliteManagedEncryptionEnabled,
		HideProjectEncryptionOptions:      server.config.HideProjectEncryptionOptions && server.config.SatelliteManagedEncryptionEnabled,
		EmailChangeFlowEnabled:            server.config.EmailChangeFlowEnabled,
		SelfServeAccountDeleteEnabled:     server.config.SelfServeAccountDeleteEnabled,
		DeleteProjectEnabled:              server.config.DeleteProjectEnabled,
		NoLimitsUiEnabled:                 server.config.NoLimitsUiEnabled,
		AltObjBrowserPagingEnabled:        server.config.AltObjBrowserPagingEnabled,
		AltObjBrowserPagingThreshold:      server.config.AltObjBrowserPagingThreshold,
		DomainsPageEnabled:                server.config.DomainsPageEnabled,
		ActiveSessionsViewEnabled:         server.config.ActiveSessionsViewEnabled,
		VersioningUIEnabled:               true,
		ObjectLockUIEnabled:               server.config.ObjectLockUIEnabled,
		ValdiSignUpURL:                    server.config.ValdiSignUpURL,
		SsoEnabled:                        server.ssoEnabled,
		SelfServePlacementSelectEnabled:   server.config.Placement.SelfServeEnabled,
		CunoFSBetaEnabled:                 server.config.CunoFSBetaEnabled,
		ObjectMountConsultationEnabled:    server.config.ObjectMountConsultationEnabled,
		CSRFToken:                         csrfToken,
		BillingStripeCheckoutEnabled:      server.config.BillingStripeCheckoutEnabled,
		MaxAddFundsAmount:                 server.config.MaxAddFundsAmount,
		MinAddFundsAmount:                 server.config.MinAddFundsAmount,
		DownloadPrefixEnabled:             server.config.DownloadPrefixEnabled,
		ZipDownloadLimit:                  server.config.ZipDownloadLimit,
		LiveCheckBadPasswords:             server.config.LiveCheckBadPasswords,
		RestAPIKeysUIEnabled:              server.config.RestAPIKeysUIEnabled && server.config.UseNewRestKeysTable,
		ZkSyncContractAddress:             server.config.ZkSyncContractAddress,
		NewDetailedUsageReportEnabled:     server.config.NewDetailedUsageReportEnabled,
		UpgradePayUpfrontAmount:           server.config.UpgradePayUpfrontAmount,
		UserFeedbackEnabled:               server.config.UserFeedbackEnabled,
		UseGeneratedPrivateAPI:            server.config.UseGeneratedPrivateAPI,
		Announcement:                      server.config.Announcement,
		ComputeUIEnabled:                  server.config.ComputeUiEnabled && server.entitlementsEnabled,
		EntitlementsEnabled:               server.entitlementsEnabled,
		ShowNewPricingTiers:               server.config.ShowNewPricingTiers,
		ComputeGatewayURL:                 server.config.ComputeGatewayURL,
		NewPricingStartDate:               newPricingStartDate,
		ProductPriceSummaries:             server.productPriceSummaries,
		CollectBillingInfoOnOnboarding:    server.config.CollectBillingInfoOnOnboarding,
		RequireBillingAddress:             server.config.RequireBillingAddress,
		ScheduleMeetingURL:                server.config.ScheduleMeetingURL,
		HideUplinkBehavior:                server.config.HideUplinkBehavior,
		BucketLimitsUIEnabled:             server.config.BucketLimitsUIEnabled,
		MinimumCharge: console.MinimumChargeConfig{
			Enabled:   server.minimumChargeConfig.Amount > 0,
			Amount:    server.minimumChargeConfig.Amount,
			StartDate: minimumChargeDate,
		},
		StorageMBMonthCents: server.usagePrices.StorageMBMonthCents.String(),
		EgressMBCents:       server.usagePrices.EgressMBCents.String(),
		SegmentMonthCents:   server.usagePrices.SegmentMonthCents.String(),
	}

	w.Header().Set(contentType, applicationJSON)

	err = json.NewEncoder(w).Encode(&cfg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		server.log.Error("failed to write frontend config", zap.Error(err))
	}
}

// getBranding returns branding configuration based on tenant context.
func (server *Server) getBranding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	tenantCtx := tenancy.GetContext(ctx)

	// Default Storj branding.
	branding := BrandingConfig{
		Name: "Storj",
		LogoURLs: map[string]string{
			"full-light":  "/static/static/images/logo.svg",
			"full-dark":   "/static/static/images/logo-dark.svg",
			"small-light": "/static/static/images/logo-small.svg",
			"small-dark":  "/static/static/images/logo-small.svg",
		},
		FaviconURLs: map[string]string{
			"16x16":       "/static/static/images/favicons/favicon-16x16.png",
			"32x32":       "/static/static/images/favicons/favicon-32x32.png",
			"apple-touch": "/static/static/images/favicons/apple-touch-icon.png",
		},
		Colors: map[string]string{
			"primary-light":      "#0052FF",
			"primary-dark":       "#0052FF",
			"on-primary-light":   "#FFFFFF",
			"on-primary-dark":    "#FFFFFF",
			"secondary-light":    "#091C45",
			"secondary-dark":     "#537CFF",
			"on-secondary-light": "#FFFFFF",
			"on-secondary-dark":  "#FFFFFF",
			"background-light":   "#FCFCFD",
			"background-dark":    "#000A20",
			"surface-light":      "#FFFFFF",
			"surface-dark":       "#000B21",
			"on-surface-light":   "#000000",
			"on-surface-dark":    "#FFFFFF",
			"success-light":      "#00B661",
			"success-dark":       "#00E366",
			"info-light":         "#0059D0",
			"info-dark":          "#2196f3",
			"warning-light":      "#FF7F00",
			"warning-dark":       "#FF8A00",
		},
		SupportURL:        server.config.GeneralRequestURL,
		DocsURL:           server.config.DocumentationURL,
		HomepageURL:       server.config.HomepageURL,
		GetInTouchURL:     server.config.ScheduleMeetingURL,
		PrivacyPolicyURL:  server.config.HomepageURL + "/privacy-policy/",
		TermsOfServiceURL: server.config.TermsAndConditionsURL,
	}

	// Check single-brand white label first (takes precedence for dedicated deployments).
	if server.config.SingleWhiteLabel.Enabled() {
		wlConfig := server.config.SingleWhiteLabel.ToWhiteLabelConfig()
		branding = brandingFromWhiteLabelConfig(wlConfig, server.config.HomepageURL, server.config.TermsAndConditionsURL)
	} else if tenantCtx.TenantID != "" {
		// Fall back to multi-tenant white label lookup.
		if wlConfig, ok := server.config.WhiteLabel.Value[tenantCtx.TenantID]; ok {
			branding = brandingFromWhiteLabelConfig(wlConfig, server.config.HomepageURL, server.config.TermsAndConditionsURL)
		} else {
			server.log.Warn("tenant white label config not found, falling back to default branding", zap.String("tenant_id", tenantCtx.TenantID))
		}
	}

	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set(contentType, applicationJSON)

	if err := json.NewEncoder(w).Encode(&branding); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		server.log.Error("failed to write branding config", zap.Error(err))
	}
}

// brandingFromWhiteLabelConfig converts a WhiteLabelConfig to BrandingConfig.
func brandingFromWhiteLabelConfig(wlConfig console.WhiteLabelConfig, defaultHomepageURL, defaultTermsURL string) BrandingConfig {
	privacyPolicyURL := wlConfig.PrivacyPolicyURL
	if privacyPolicyURL == "" {
		privacyPolicyURL = defaultHomepageURL + "/privacy-policy/"
	}
	termsOfServiceURL := wlConfig.TermsOfServiceURL
	if termsOfServiceURL == "" {
		termsOfServiceURL = defaultTermsURL
	}

	return BrandingConfig{
		Name:              wlConfig.Name,
		LogoURLs:          wlConfig.LogoURLs,
		FaviconURLs:       wlConfig.FaviconURLs,
		Colors:            wlConfig.Colors,
		SupportURL:        wlConfig.SupportURL,
		DocsURL:           wlConfig.DocsURL,
		HomepageURL:       wlConfig.HomepageURL,
		GetInTouchURL:     wlConfig.GetInTouchURL,
		GatewayURL:        wlConfig.GatewayURL,
		PrivacyPolicyURL:  privacyPolicyURL,
		TermsOfServiceURL: termsOfServiceURL,
	}
}

func (server *Server) partnerUIConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	var partner string
	var ok bool
	if partner, ok = mux.Vars(r)["partner"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		server.log.Error("missing partner in request URL")
		return
	}

	var kind string
	if kind, ok = mux.Vars(r)["kind"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		server.log.Error("missing config kind in request URL")
		return
	}

	var partnerCfg console.UIConfig
	if partnerCfg, ok = server.config.PartnerUI.Value[partner]; !ok {
		w.WriteHeader(http.StatusNotFound)
		server.log.Error("missing config for partner in request URL", zap.String("partner", partner))
		return
	}
	var cfg map[string]any
	switch kind {
	case "signup":
		cfg = partnerCfg.Signup
	case "onboarding":
		cfg = partnerCfg.Onboarding
	case "pricing-plan":
		cfg = partnerCfg.PricingPlan
	case "billing":
		cfg = partnerCfg.Billing
	case "upgrade":
		cfg = partnerCfg.Upgrade
	default:
		w.WriteHeader(http.StatusBadRequest)
		server.log.Error("invalid config kind in request URL", zap.String("kind", kind))
		return
	}

	w.Header().Set(contentType, applicationJSON)

	err := json.NewEncoder(w).Encode(&cfg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		server.log.Error("failed to write partner UI config", zap.Error(err))
	}
}

// createRegistrationTokenHandler is web app http handler function.
func (server *Server) createRegistrationTokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	w.Header().Set(contentType, applicationJSON)

	var response struct {
		Secret string `json:"secret"`
		Error  string `json:"error,omitempty"`
	}

	defer func() {
		err := json.NewEncoder(w).Encode(&response)
		if err != nil {
			server.log.Error(err.Error())
		}
	}()

	equality := subtle.ConstantTimeCompare(
		[]byte(r.Header.Get("Authorization")),
		[]byte(server.config.AuthToken),
	)
	if equality != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		response.Error = "unauthorized"
		return
	}

	projectsLimitInput := r.URL.Query().Get("projectsLimit")

	projectsLimit, err := strconv.Atoi(projectsLimitInput)
	if err != nil {
		response.Error = err.Error()
		return
	}

	token, err := server.service.CreateRegToken(ctx, projectsLimit)
	if err != nil {
		response.Error = err.Error()
		return
	}

	response.Secret = token.Secret.String()
}

// accountActivationHandler is web app http handler function.
func (server *Server) accountActivationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	activationToken := r.URL.Query().Get("token")

	externalAddr := server.getExternalAddress(ctx)

	user, err := server.service.ActivateAccount(ctx, activationToken)
	if err != nil {
		if console.ErrTokenInvalid.Has(err) {
			server.serveError(w, http.StatusBadRequest)
			return
		}

		if console.ErrTokenExpiration.Has(err) {
			http.Redirect(w, r, server.config.ExternalAddress+"activate?expired=true", http.StatusTemporaryRedirect)
			return
		}

		if console.ErrEmailUsed.Has(err) {
			http.Redirect(w, r, server.config.ExternalAddress+"login?activated=false", http.StatusTemporaryRedirect)
			return
		}

		if console.Error.Has(err) {
			server.log.Error("activation: failed to activate account with a valid token",
				zap.Error(err))
			server.serveError(w, http.StatusInternalServerError)
			return
		}

		server.log.Error(
			"activation: failed to activate account with a valid token and unknown error type. BUG: missed error type check",
			zap.Error(err))
		server.serveError(w, http.StatusInternalServerError)
		return
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		server.serveError(w, http.StatusInternalServerError)
		return
	}

	tokenInfo, err := server.service.GenerateSessionToken(ctx, user.ID, user.Email, ip, r.UserAgent(), consoleapi.LoadAjsAnonymousID(r), nil, nil, nil)
	if err != nil {
		server.serveError(w, http.StatusInternalServerError)
		return
	}

	server.cookieAuth.SetTokenCookie(w, *tokenInfo)

	http.Redirect(w, r, externalAddr, http.StatusTemporaryRedirect)
}

func (server *Server) cancelPasswordRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)
	recoveryToken := r.URL.Query().Get("token")

	// No need to check error as we anyway redirect user to support page
	_ = server.service.RevokeResetPasswordToken(ctx, recoveryToken)

	// TODO: Should place this link to config
	http.Redirect(w, r, "https://storjlabs.atlassian.net/servicedesk/customer/portals", http.StatusSeeOther)
}

// getExternalAddress returns the external address for the current tenant context.
// If a tenant-specific external address is configured, it returns that; otherwise, it falls back
// to the global external address. The returned address always has a trailing slash.
func (server *Server) getExternalAddress(ctx context.Context) string {
	// Check single-brand mode first
	if server.config.SingleWhiteLabel.Enabled() && server.config.SingleWhiteLabel.ExternalAddress != "" {
		addr := server.config.SingleWhiteLabel.ExternalAddress
		if !strings.HasSuffix(addr, "/") {
			addr += "/"
		}
		return addr
	}

	// Multi-tenant lookup
	tenantID := tenancy.TenantIDFromContext(ctx)
	if tenantID != "" {
		if wlConfig, ok := server.config.WhiteLabel.Value[tenantID]; ok && wlConfig.ExternalAddress != "" {
			addr := wlConfig.ExternalAddress
			if !strings.HasSuffix(addr, "/") {
				addr += "/"
			}
			return addr
		}
	}
	return server.config.ExternalAddress
}

func (server *Server) handleInvited(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	token := r.URL.Query().Get("invite")
	if token == "" {
		server.serveError(w, http.StatusBadRequest)
		return
	}

	externalAddr := server.getExternalAddress(ctx)
	loginLink := externalAddr + "login"

	invite, err := server.service.GetInviteByToken(ctx, token)
	if err != nil {
		server.log.Error("handleInvited: error checking invitation", zap.Error(err))

		if console.ErrProjectInviteInvalid.Has(err) {
			http.Redirect(w, r, loginLink+"?invite_invalid=true", http.StatusTemporaryRedirect)
			return
		}
		server.serveError(w, http.StatusInternalServerError)
		return
	}

	user, _, err := server.service.GetUserByEmailWithUnverified(ctx, invite.Email)
	if err != nil && !console.ErrEmailNotFound.Has(err) {
		server.log.Error("error getting invitation recipient", zap.Error(err))
		server.serveError(w, http.StatusInternalServerError)
		return
	}
	if user != nil {
		http.Redirect(w, r, loginLink+"?email="+url.QueryEscape(user.Email), http.StatusTemporaryRedirect)
		return
	}

	params := url.Values{"email": {strings.ToLower(invite.Email)}}

	if invite.InviterID != nil {
		inviter, err := server.service.GetUser(ctx, *invite.InviterID)
		if err != nil {
			server.log.Error("error getting invitation sender", zap.Error(err))
			server.serveError(w, http.StatusInternalServerError)
			return
		}
		params.Add("inviter_email", inviter.Email)

		server.analytics.TrackInviteLinkClicked(inviter.Email, invite.Email)
	}

	http.Redirect(w, r, externalAddr+"signup?"+params.Encode(), http.StatusTemporaryRedirect)
}

// serveError serves a static error page.
func (server *Server) serveError(w http.ResponseWriter, status int) {
	w.WriteHeader(status)

	template, err := server.loadErrorTemplate()
	if err != nil {
		server.log.Error("unable to load error template", zap.Error(err))
		return
	}

	data := struct{ StatusCode int }{StatusCode: status}
	err = template.Execute(w, data)
	if err != nil {
		server.log.Error("cannot parse error template", zap.Error(err))
	}
}

// seoHandler used to communicate with web crawlers and other web robots.
func (server *Server) seoHandler(w http.ResponseWriter, req *http.Request) {
	header := w.Header()

	header.Set(contentType, typeByExtension(".txt"))
	header.Set("X-Content-Type-Options", "nosniff")

	_, err := w.Write([]byte(server.config.SEO))
	if err != nil {
		server.log.Error(err.Error())
	}
}

// brotliMiddleware is used to compress static content using brotli to minify resources if browser support such decoding.
func (server *Server) brotliMiddleware(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		isBrotliSupported := strings.Contains(r.Header.Get("Accept-Encoding"), "br")
		if !isBrotliSupported {
			fn.ServeHTTP(w, r)
			return
		}

		info, err := os.Stat(server.config.StaticDir + strings.TrimPrefix(r.URL.Path, "/static") + ".br")
		if err != nil {
			fn.ServeHTTP(w, r)
			return
		}

		extension := filepath.Ext(info.Name()[:len(info.Name())-3])
		w.Header().Set(contentType, typeByExtension(extension))
		w.Header().Set("Content-Encoding", "br")

		newRequest := new(http.Request)
		*newRequest = *r
		newRequest.URL = new(url.URL)
		*newRequest.URL = *r.URL
		newRequest.URL.Path += ".br"

		fn.ServeHTTP(w, newRequest)
	})
}

//go:embed error_fallback.html
var errorTemplateFallback string

// loadTemplates is used to initialize the error page template.
func (server *Server) loadErrorTemplate() (_ *template.Template, err error) {
	if server.errorTemplate == nil || server.config.Watch {
		server.errorTemplate, err = template.ParseFiles(filepath.Join(server.config.StaticDir, "static", "errors", "error.html"))
		if err != nil {
			server.log.Error("failed to load error.html template, falling back to error_fallback.html", zap.Error(err))
			server.errorTemplate, err = template.New("").Parse(errorTemplateFallback)
			if err != nil {
				return nil, Error.Wrap(err)
			}
		}
	}

	return server.errorTemplate, nil
}

func (server *Server) handleContactUs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if server.config.SupportEmail == "" {
		web.ServeCustomJSONError(ctx, server.log, w, http.StatusInternalServerError, nil, "support email is not configured")
		return
	}

	var contactUsRequest struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&contactUsRequest); err != nil {
		web.ServeCustomJSONError(ctx, server.log, w, http.StatusBadRequest, nil, "invalid request body")
		return
	}

	if contactUsRequest.Name == "" || contactUsRequest.Email == "" {
		web.ServeCustomJSONError(ctx, server.log, w, http.StatusBadRequest, nil, "name and email are required")
		return
	}

	if !utils.ValidateEmail(contactUsRequest.Email) {
		web.ServeCustomJSONError(ctx, server.log, w, http.StatusBadRequest, nil, "invalid email")
		return
	}

	server.mailService.SendRenderedAsync(
		ctx,
		[]post.Address{{Address: server.config.SupportEmail}},
		&console.ContactUsForm{
			Name:    contactUsRequest.Name,
			Email:   contactUsRequest.Email,
			Message: contactUsRequest.Message,
		},
	)

	// Truncate message preview if too long (max 100 characters)
	messagePreview := contactUsRequest.Message
	if len(messagePreview) > 100 {
		messagePreview = messagePreview[:100] + "..."
	}

	server.mailService.SendRenderedAsync(
		ctx,
		[]post.Address{{Address: contactUsRequest.Email}},
		&console.ContactUsSubmittedEmail{
			Name:    contactUsRequest.Name,
			Email:   contactUsRequest.Email,
			Message: messagePreview,
		},
	)

	w.WriteHeader(http.StatusNoContent)
}

// NewUserIDRateLimiter constructs a RateLimiter that limits based on user ID.
func NewUserIDRateLimiter(config web.RateLimiterConfig, log *zap.Logger) *web.RateLimiter {
	return web.NewRateLimiter(config, log, getUserIDFromContext)
}

func getUserIDFromContext(r *http.Request) (string, error) {
	user, err := console.GetUser(r.Context())
	if err != nil {
		return "", err
	}
	return user.ID.String(), nil
}

// responseWriterStatusCode is a wrapper of an http.ResponseWriter to track the
// response status code for having access to it after calling
// http.ResponseWriter.WriteHeader.
type responseWriterStatusCode struct {
	http.ResponseWriter
	code int
}

func (w *responseWriterStatusCode) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// newTraceRequestMiddleware returns middleware for tracing each request to a
// registered endpoint through Monkit.
//
// It also log in INFO level each request.
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
					zap.String("uri", r.RequestURI),
					zap.String("ip", getClientIP(r)),
					zap.Int("response_code", respWCode.code),
					zap.Duration("elapse", time.Since(begin)),
				)

				span := monkit.SpanFromCtx(ctx)
				if span != nil {
					fields = append(fields, zap.Int64("trace_id", span.Trace().Id()))
				}

				log.Info("client HTTP request", fields...)
			}()

			match := mux.RouteMatch{}
			root.Match(r, &match)

			pathTpl, err := match.Route.GetPathTemplate()
			if err != nil {
				log.Warn("error when getting the route template path",
					zap.Error(err), zap.String("request_uri", r.RequestURI),
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

// newBodyLimiterMiddleware returns a middleware that places a length limit on each request's body.
func newBodyLimiterMiddleware(log *zap.Logger, limit memory.Size) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit.Int64() {
				web.ServeJSONError(r.Context(), log, w, http.StatusRequestEntityTooLarge, errs.New("Request body is too large"))
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, limit.Int64())
			next.ServeHTTP(w, r)
		})
	}
}

// apiAuth exposes methods to control authentication process for each generated API endpoint.
type apiAuth struct {
	server *Server
}

// IsAuthenticated checks if request is performed with all needed authorization credentials.
func (a *apiAuth) IsAuthenticated(ctx context.Context, r *http.Request, isCookieAuth, isKeyAuth bool) (_ context.Context, err error) {
	if isCookieAuth && isKeyAuth {
		ctx, err = a.cookieAuth(ctx, r)
		if err != nil {
			ctx, err = a.keyAuth(ctx, r)
			if err != nil {
				return nil, err
			}
		}
	} else if isCookieAuth {
		ctx, err = a.cookieAuth(ctx, r)
		if err != nil {
			return nil, err
		}
	} else if isKeyAuth {
		ctx, err = a.keyAuth(ctx, r)
		if err != nil {
			return nil, err
		}
	}

	return ctx, nil
}

// cookieAuth returns an authenticated context by session cookie.
func (a *apiAuth) cookieAuth(ctx context.Context, r *http.Request) (context.Context, error) {
	tokenInfo, err := a.server.cookieAuth.GetToken(r)
	if err != nil {
		return nil, err
	}

	newCtx, _, err := a.server.service.TokenAuth(ctx, tokenInfo.Token, time.Now())
	return newCtx, err
}

// cookieAuth returns an authenticated context by api key.
func (a *apiAuth) keyAuth(ctx context.Context, r *http.Request) (context.Context, error) {
	authToken := r.Header.Get("Authorization")
	split := strings.Split(authToken, "Bearer ")
	if len(split) != 2 {
		return ctx, errs.New("authorization key format is incorrect. Should be 'Bearer <key>'")
	}

	return a.server.service.KeyAuth(ctx, split[1], time.Now())
}

// RemoveAuthCookie indicates to the client that the authentication cookie should be removed.
func (a *apiAuth) RemoveAuthCookie(w http.ResponseWriter) {
	a.server.cookieAuth.RemoveTokenCookie(w)
}

// apiCORS exposes methods to control CORS process for each generated API endpoint.
type apiCORS struct {
	server *Server
}

// Handle sets the necessary CORS headers for the request and checks if the request is an OPTIONS preflight request.
func (c *apiCORS) Handle(w http.ResponseWriter, r *http.Request) (isPreflight bool) {
	w.Header().Set("Access-Control-Allow-Origin", strings.Trim(c.server.config.ExternalAddress, "/"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "*, Authorization")

	if r.Method == http.MethodOptions {
		match := &mux.RouteMatch{}
		if c.server.router.Match(r, match) {
			methods, err := match.Route.GetMethods()
			if err == nil && len(methods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
			}
		}
		return true
	}

	return false
}

// ProductPriceSummaries represents a list of product price summaries.
type ProductPriceSummaries []string

// CreateProductPriceSummaries creates ProductPriceSummaries from config.
func CreateProductPriceSummaries(overrides paymentsconfig.ProductPriceOverrides) (ProductPriceSummaries, error) {
	var res ProductPriceSummaries
	productModels, err := overrides.ToModels()
	if err != nil {
		return nil, err
	}

	for _, model := range productModels {
		if model.PriceSummary != "" {
			res = append(res, model.PriceSummary)
		}
	}
	return res, nil
}
