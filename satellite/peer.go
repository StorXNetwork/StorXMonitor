// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellite

import (
	"context"

	hw "github.com/jtolds/monkit-hw/v2"
	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/healthcheck"
	"github.com/StorXNetwork/StorXMonitor/private/migrate"
	"github.com/StorXNetwork/StorXMonitor/private/server"
	version_checker "github.com/StorXNetwork/StorXMonitor/private/version/checker"
	"github.com/StorXNetwork/StorXMonitor/satellite/accountfreeze"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/live"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/nodetally"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/projectbwcleanup"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/rollup"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/rolluparchive"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/tally"
	"github.com/StorXNetwork/StorXMonitor/satellite/admin"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/attribution"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/backup"
	"github.com/StorXNetwork/StorXMonitor/satellite/bucketmigrations"
	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/StorXMonitor/satellite/compensation"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/sso"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/dbcleanup"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/dbcleanup/pendingdelete"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/emailreminders"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/restkeys"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/userinfo"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/valdi"
	"github.com/StorXNetwork/StorXMonitor/satellite/contact"
	"github.com/StorXNetwork/StorXMonitor/satellite/developer"
	"github.com/StorXNetwork/StorXMonitor/satellite/durability"
	"github.com/StorXNetwork/StorXMonitor/satellite/emission"
	"github.com/StorXNetwork/StorXMonitor/satellite/entitlements"
	"github.com/StorXNetwork/StorXMonitor/satellite/eventing/eventingconfig"
	"github.com/StorXNetwork/StorXMonitor/satellite/gc/bloomfilter"
	"github.com/StorXNetwork/StorXMonitor/satellite/gc/piecetracker"
	"github.com/StorXNetwork/StorXMonitor/satellite/gc/sender"
	"github.com/StorXNetwork/StorXMonitor/satellite/gracefulexit"
	"github.com/StorXNetwork/StorXMonitor/satellite/jobq"
	"github.com/StorXNetwork/StorXMonitor/satellite/kms"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice/hubspotmails"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice/simulate"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/rangedloop"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/zombiedeletion"
	"github.com/StorXNetwork/StorXMonitor/satellite/metainfo"
	"github.com/StorXNetwork/StorXMonitor/satellite/metainfo/expireddeletion"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeapiversion"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeevents"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection/tracker"
	"github.com/StorXNetwork/StorXMonitor/satellite/oidc"
	"github.com/StorXNetwork/StorXMonitor/satellite/orders"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay/offlinenodes"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay/straynodes"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/billing"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/paymentsconfig"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/storjscan"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/stripe"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/checker"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/queue"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/repairer"
	"github.com/StorXNetwork/StorXMonitor/satellite/reputation"
	"github.com/StorXNetwork/StorXMonitor/satellite/revocation"
	"github.com/StorXNetwork/StorXMonitor/satellite/snopayouts"
	"github.com/StorXNetwork/StorXMonitor/satellite/userworker"
	"github.com/StorXNetwork/StorXMonitor/shared/dbutil"
	"github.com/StorXNetwork/StorXMonitor/shared/flightrecorder"
	"github.com/StorXNetwork/StorXMonitor/shared/tagsql"
	"github.com/StorXNetwork/common/debug"
	"github.com/StorXNetwork/common/identity"
)

var mon = monkit.Package()

func init() {
	hw.Register(monkit.Default)
}

// DB is the master database for the satellite.
//
// architecture: Master Database
type DB interface {
	// MigrateToLatest initializes the database
	MigrateToLatest(ctx context.Context) error
	// CheckVersion checks the database is the correct version
	CheckVersion(ctx context.Context) error
	// Close closes the database
	Close() error

	// PeerIdentities returns a storage for peer identities
	PeerIdentities() overlay.PeerIdentities
	// OverlayCache returns database for caching overlay information
	OverlayCache() overlay.DB
	// NodeEvents returns a database for node event information
	NodeEvents() nodeevents.DB
	// Reputation returns database for audit reputation information
	Reputation() reputation.DB
	// Attribution returns database for partner keys information
	Attribution() attribution.DB
	// StoragenodeAccounting returns database for storing information about storagenode use
	StoragenodeAccounting() accounting.StoragenodeAccounting
	// ProjectAccounting returns database for storing information about project data use
	ProjectAccounting() accounting.ProjectAccounting
	// RetentionRemainderCharges returns database for retention remainder charges
	RetentionRemainderCharges() accounting.RetentionRemainderDB
	// RepairQueue returns queue for segments that need repairing
	RepairQueue() queue.RepairQueue
	// VerifyQueue returns queue for segments chosen for verification
	VerifyQueue() audit.VerifyQueue
	// ReverifyQueue returns queue for pieces that need audit reverification
	ReverifyQueue() audit.ReverifyQueue
	// Console returns database for satellite console
	Console() console.DB
	// AdminUsers returns database for admin users.
	AdminUsers() admin.Users
	// // AdminChangeHistory returns the database for storing admin change history.
	// AdminChangeHistory() changehistory.DB
	// OIDC returns the database for OIDC resources.
	OIDC() oidc.DB
	// Orders returns database for orders
	Orders() orders.DB
	// Containment returns database for containment
	Containment() audit.Containment
	// Buckets returns the database to interact with buckets
	Buckets() buckets.DB
	// DeleteUserQueue returns the database for delete user queue
	DeleteUserQueue() userworker.DeleteUserQueue
	// BucketMigrations returns the database to interact with bucket migrations
	BucketMigrations() bucketmigrations.DB
	// StripeCoinPayments returns stripecoinpayments database.
	StripeCoinPayments() stripe.DB
	// Billing returns storjscan transactions database.
	Billing() billing.TransactionsDB
	// NodeReputation returns database for node reputation.
	NodeReputation() audit.NodeReputation
	// Wallets returns storjscan wallets database.
	Wallets() storjscan.WalletsDB
	// SNOPayouts returns database for payouts.
	SNOPayouts() snopayouts.DB
	// Compensation tracks storage node compensation
	Compensation() compensation.DB
	// Revocation tracks revoked macaroons
	Revocation() revocation.DB
	// NodeAPIVersion tracks nodes observed api usage
	NodeAPIVersion() nodeapiversion.DB
	// StorjscanPayments stores payments retrieved from storjscan.
	StorjscanPayments() storjscan.PaymentsDB

	// Web3Auth returns database for web3 auth.
	Web3Auth() backup.DB
	// LiveAccounting returns database for caching project usage data
	LiveAccounting() accounting.Cache

	// Testing provides access to testing facilities. These should not be used in production code.
	Testing() TestingDB
}

// TestingDB defines access to database testing facilities.
type TestingDB interface {
	// Implementation returns the implementations of the databases.
	Implementation() []dbutil.Implementation
	// Rebind adapts a query's syntax for a database dialect.
	Rebind(query string) string
	// RawDB returns the underlying database connection to the primary database.
	RawDB() tagsql.DB
	// Schema returns the full schema for the database.
	Schema() []string
	// TestMigrateToLatest initializes the database for testplanet.
	TestMigrateToLatest(ctx context.Context) error
	// ProductionMigration returns the primary migration.
	ProductionMigration() *migrate.Migration
	// TestMigration returns the migration used for tests.
	TestMigration() *migrate.Migration
}

// Config is the global config satellite.
type Config struct {
	Identity identity.Config
	Server   server.Config
	Debug    debug.Config

	Placement nodeselection.ConfigurablePlacementRule `help:"detailed placement rules in the form 'id:definition;id:definition;...' where id is a 16 bytes integer (use >10 for backward compatibility), definition is a combination of the following functions:country(2 letter country codes,...), tag(nodeId, key, bytes(value)) all(...,...)."`

	Admin     admin.Config
	Developer developer.Config

	Contact      contact.Config
	Overlay      overlay.Config
	OfflineNodes offlinenodes.Config
	NodeEvents   nodeevents.Config
	StrayNodes   straynodes.Config

	BucketEventing eventingconfig.Config
	Metainfo       metainfo.Config
	Orders         orders.Config

	Userinfo userinfo.Config

	Reputation reputation.Config

	Checker  checker.Config
	Repairer repairer.Config
	Audit    audit.Config

	GarbageCollection   sender.Config
	GarbageCollectionBF bloomfilter.Config

	RepairQueueCheck repairer.QueueStatConfig
	JobQueue         jobq.Config

	RangedLoop rangedloop.Config
	Durability durability.Config

	ExpiredDeletion expireddeletion.Config
	ZombieDeletion  zombiedeletion.Config

	Tally            tally.Config
	NodeTally        nodetally.Config
	Rollup           rollup.Config
	RollupArchive    rolluparchive.Config
	LiveAccounting   live.Config
	ProjectBWCleanup projectbwcleanup.Config

	Mail         mailservice.Config
	HubspotMails hubspotmails.Config

	Payments paymentsconfig.Config

	Console          consoleweb.Config
	Entitlements     entitlements.Config
	Valdi            valdi.Config
	ConsoleAuth      consoleauth.Config
	EmailReminders   emailreminders.Config
	ConsoleDBCleanup dbcleanup.Config

	PendingDeleteCleanup pendingdelete.Config

	Emission emission.Config

	AccountFreeze accountfreeze.Config

	Version version_checker.Config

	GracefulExit gracefulexit.Config

	Compensation compensation.Config

	Analytics analytics.Config

	PieceTracker piecetracker.Config

	DurabilityReport durability.ReportConfig

	KeyManagement kms.Config

	SSO sso.Config

	HealthCheck healthcheck.Config

	Backup backup.Config

	FlightRecorder flightrecorder.Config

	RESTKeys restkeys.Config

	TagAuthorities string `help:"comma-separated paths of additional cert files, used to validate signed node tags"`

	PrometheusTracker tracker.PrometheusTrackerConfig

	DisableConsoleFromSatelliteAPI bool `help:"indicates whether the console API should not be served along with satellite API" default:"false"`

	StandaloneConsoleAPIEnabled bool `help:"indicates whether the console API should be served as a standalone service" default:"false"`
}

func setupMailService(log *zap.Logger, mailConfig mailservice.Config, consoleConfig consoleweb.Config) (*mailservice.Service, error) {
	var defaultSender mailservice.Sender
	var err error

	switch mailConfig.AuthType {
	case "nomail":
		defaultSender = simulate.NoMail{}
	case "simulate", "":
		defaultSender = simulate.NewDefaultLinkClicker(log.Named("mail:linkclicker"))
	default:
		defaultSender, err = mailservice.CreateSender(mailConfig)
		if err != nil {
			return nil, err
		}
	}

	// Extract tenant configurations from console config
	tenantConfigs := make(map[string]mailservice.TenantSMTPConfig)
	for tenantID, config := range consoleConfig.WhiteLabel.Value {
		tenantConfigs[tenantID] = mailservice.TenantSMTPConfig{
			Branding: mailservice.WhiteLabelConfig{
				BrandName:         config.Name,
				LogoURL:           config.LogoURLs["mail"],
				HomepageURL:       config.HomepageURL,
				SupportURL:        config.SupportURL,
				DocsURL:           config.DocsURL,
				SourceCodeURL:     config.SourceCodeURL,
				SocialURL:         config.SocialURL,
				PrivacyPolicyURL:  config.PrivacyPolicyURL,
				TermsOfServiceURL: config.TermsOfServiceURL,
				TermsOfUseURL:     config.TermsOfUseURL,
				BlogURL:           config.BlogURL,
				CompanyName:       config.CompanyName,
				AddressLine1:      config.AddressLine1,
				AddressLine2:      config.AddressLine2,
				PrimaryColor:      config.Colors["primary"],
			},
			SMTP: mailservice.Config{
				From:              config.SMTP.From,
				SMTPServerAddress: config.SMTP.ServerAddress,
				AuthType:          config.SMTP.AuthType,
				Login:             config.SMTP.Login,
				Password:          config.SMTP.Password,
			},
		}
	}

	defaultBranding := mailservice.WhiteLabelConfig{
		BrandName:         "Storj",
		LogoURL:           "https://link.storjshare.io/raw/jvu2d4ymgfizmfo4n7ljvc7augra/public-assets/Storj%20-%20Branding/Storj-logo-web-hq.png",
		HomepageURL:       consoleConfig.HomepageURL,
		SupportURL:        consoleConfig.GeneralRequestURL,
		DocsURL:           consoleConfig.DocumentationURL,
		PrivacyPolicyURL:  "https://www.storxnetwork.io/legal/privacy-policy",
		TermsOfServiceURL: consoleConfig.TermsAndConditionsURL,
		TermsOfUseURL:     "https://www.storxnetwork.io/legal/terms-of-use",
		SourceCodeURL:     "https://github.com/storxnetwork",
		SocialURL:         "https://twitter.com/storxnetwork",
		BlogURL:           "https://storxnetwork.io/blog",
		PrimaryColor:      "#0052FF",
		CompanyName:       "Storj Labs",
		AddressLine1:      "1870 The Exchange SE Ste 220, PMB 75268",
		AddressLine2:      "Atlanta, GA 30339-2171, United States",
	}

	return mailservice.SetupWithTenants(log, mailservice.SetupConfig{
		DefaultSender:   defaultSender,
		TemplatePath:    mailConfig.TemplatePath,
		TenantConfigs:   tenantConfigs,
		DefaultBranding: defaultBranding,
	})
}
