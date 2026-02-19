// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellite

import (
	"net"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/private/healthcheck"
	"github.com/StorXNetwork/StorXMonitor/private/revocation"
	"github.com/StorXNetwork/StorXMonitor/private/server"
	"github.com/StorXNetwork/StorXMonitor/satellite/abtesting"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/live"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/attribution"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/buckets"
	"github.com/StorXNetwork/StorXMonitor/satellite/compensation"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/csrf"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/sso"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/pushnotifications"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/restapikeys"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/restkeys"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/userinfo"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/valdi"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/valdi/valdiclient"
	"github.com/StorXNetwork/StorXMonitor/satellite/contact"
	"github.com/StorXNetwork/StorXMonitor/satellite/developer"
	"github.com/StorXNetwork/StorXMonitor/satellite/emission"
	"github.com/StorXNetwork/StorXMonitor/satellite/entitlements"
	"github.com/StorXNetwork/StorXMonitor/satellite/eventing"
	"github.com/StorXNetwork/StorXMonitor/satellite/eventing/eventingconfig"
	"github.com/StorXNetwork/StorXMonitor/satellite/gc/bloomfilter"
	"github.com/StorXNetwork/StorXMonitor/satellite/gracefulexit"
	"github.com/StorXNetwork/StorXMonitor/satellite/jobq"
	"github.com/StorXNetwork/StorXMonitor/satellite/kms"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice/hubspotmails"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/changestream"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/rangedloop"
	"github.com/StorXNetwork/StorXMonitor/satellite/metainfo"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeapiversion"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeevents"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeselection"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodestats"
	"github.com/StorXNetwork/StorXMonitor/satellite/oidc"
	"github.com/StorXNetwork/StorXMonitor/satellite/orders"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/billing"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/paymentsconfig"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/storjscan"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/stripe"
	"github.com/StorXNetwork/StorXMonitor/satellite/piecelist"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/checker"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/queue"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/repaircsv"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/repairer"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/repairer/manual"
	"github.com/StorXNetwork/StorXMonitor/satellite/reputation"
	srevocation "github.com/StorXNetwork/StorXMonitor/satellite/revocation"
	"github.com/StorXNetwork/StorXMonitor/satellite/snopayouts"
	sndebug "github.com/StorXNetwork/StorXMonitor/shared/debug"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/config"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/eventkit"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/profiler"
	"github.com/StorXNetwork/StorXMonitor/shared/modular/tracing"
	"github.com/StorXNetwork/StorXMonitor/shared/mud"
	"github.com/StorXNetwork/StorXMonitor/shared/nodetag"
	"github.com/StorXNetwork/common/debug"
	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/pb"
	"github.com/StorXNetwork/common/peertls/extensions"
	"github.com/StorXNetwork/common/peertls/tlsopts"
	"github.com/StorXNetwork/common/rpc"
	"github.com/StorXNetwork/common/signing"
	"github.com/StorXNetwork/common/storxnetwork"
)

// Module is a mud module.
func Module(ball *mud.Ball) {
	{
		config.RegisterConfig[debug.Config](ball, "debug")
		sndebug.Module(ball)
	}

	profiler.Module(ball)
	tracing.Module(ball)
	eventkit.Module(ball)

	mud.Provide[signing.Signer](ball, signing.SignerFromFullIdentity)
	mud.Provide[storxnetwork.NodeURL](ball, func(id storxnetwork.NodeID, cfg contact.Config) storxnetwork.NodeURL {
		return storxnetwork.NodeURL{
			ID:      id,
			Address: cfg.ExternalAddress,
		}
	})

	contact.Module(ball)
	nodetag.Module(ball)
	gracefulexit.Module(ball)

	// Push notifications and developer services for console web server
	mud.Provide[*pushnotifications.Service](ball, func(log *zap.Logger, db console.DB, cfg console.Config) (*pushnotifications.Service, error) {
		return pushnotifications.NewService(log.Named("pushnotifications"), db.FCMTokens(), db.PushNotifications(), cfg.PushNotifications)
	})
	mud.Provide[*developer.Service](ball, func(log *zap.Logger, store console.DB, analytics *analytics.Service, tokens *consoleauth.Service, cfg console.Config) (*developer.Service, error) {
		regTokenChecker := developer.NewConsoleServiceAdapter(store, cfg)
		return developer.NewService(log, store, analytics, tokens, cfg, regTokenChecker)
	})

	// initialize here due to circular dependencies
	mud.Provide[*consoleweb.Server](ball, CreateServer)
	consoleweb.Module(ball)
	{
		mud.Provide[extensions.RevocationDB](ball, revocation.OpenDBFromCfg)
		mud.Provide[rpc.Dialer](ball, rpc.NewDefaultDialer)
		mud.Provide[*tlsopts.Options](ball, tlsopts.NewOptions)
		config.RegisterConfig[tlsopts.Config](ball, "server")
	}

	{
		overlay.Module(ball)
		mud.View[DB, overlay.DB](ball, DB.OverlayCache)

		// TODO: we must keep it here as it uses consoleweb.Config from overlay package.
		mud.Provide[*overlay.Service](ball, func(log *zap.Logger, db overlay.DB, nodeEvents nodeevents.DB, placements nodeselection.PlacementDefinitions, consoleConfig consoleweb.Config, config overlay.Config) (*overlay.Service, error) {
			return overlay.NewService(log, db, nodeEvents, placements, consoleConfig.ExternalAddress, consoleConfig.SatelliteName, config)
		})
	}

	{
		// TODO: fix reversed dependency (nodeselection -> overlay).
		mud.Provide[nodeselection.PlacementDefinitions](ball, func(config nodeselection.PlacementConfig, selectionConfig overlay.NodeSelectionConfig, env nodeselection.PlacementConfigEnvironment) (nodeselection.PlacementDefinitions, error) {
			return config.Placement.Parse(selectionConfig.CreateDefaultPlacement, env)
		})
		nodeselection.Module(ball)
	}
	rangedloop.Module(ball)
	bloomfilter.Module(ball)
	metainfo.Module(ball)
	metabase.Module(ball)
	eventingconfig.Module(ball)

	{
		orders.Module(ball)
		mud.View[DB, orders.DB](ball, DB.Orders)
		mud.View[DB, nodeapiversion.DB](ball, DB.NodeAPIVersion)
	}
	audit.Module(ball)

	mud.View[DB, nodeevents.DB](ball, DB.NodeEvents)

	piecelist.Module(ball)

	buckets.Module(ball)

	mud.View[DB, buckets.DB](ball, DB.Buckets)
	mud.View[DB, attribution.DB](ball, DB.Attribution)
	mud.View[DB, accounting.RetentionRemainderDB](ball, DB.RetentionRemainderCharges)
	mud.View[DB, overlay.PeerIdentities](ball, DB.PeerIdentities)
	mud.View[DB, srevocation.DB](ball, DB.Revocation)
	mud.View[DB, console.DB](ball, DB.Console)
	mud.View[overlay.DB, bloomfilter.Overlay](ball, func(db overlay.DB) bloomfilter.Overlay {
		return db
	})

	mud.Provide[*console.Service](ball, CreateService)
	console.Module(ball)
	// TODO: need to define here due to circular dependencies
	mud.Provide[restapikeys.Service](ball, func(log *zap.Logger, db restapikeys.DB, tokens oidc.OAuthTokens, config console.Config) restapikeys.Service {
		return console.NewRestKeysService(log, db, restkeys.NewService(tokens, config.RestAPIKeys.DefaultExpiration), time.Now, config)
	})
	consoleservice.Module(ball)
	consoleauth.Module(ball)
	// need to define here due to circular dependencies
	mud.Provide[consoleauth.Signer](ball, func(configw consoleweb.Config) consoleauth.Signer {
		return &consoleauth.Hmac{Secret: []byte(configw.AuthTokenSecret)}
	})
	sso.Module(ball)
	// TODO: we must keep it here as it uses consoleweb.Config from sso package.
	mud.Provide[*sso.Service](ball, func(consoleConfig consoleweb.Config, tokens *consoleauth.Service, config sso.Config) *sso.Service {
		return sso.NewService(consoleConfig.ExternalAddress, tokens, config)
	})
	csrf.Module(ball)
	valdi.Module(ball)
	valdiclient.Module(ball)
	restkeys.Module(ball)
	mailservice.Module(ball)
	analytics.Module(ball)
	// TODO: we must keep it here as it uses consoleweb.Config from analytics package.
	mud.Provide[*analytics.Service](ball, func(log *zap.Logger, config analytics.Config, consoleConfig consoleweb.Config) *analytics.Service {
		return analytics.NewService(log, config, consoleConfig.SatelliteName, consoleConfig.ExternalAddress)
	})
	abtesting.Module(ball)
	hubspotmails.Module(ball)
	mud.RegisterInterfaceImplementation[metainfo.APIKeys, console.APIKeys](ball)

	// TODO: should be defined here due to circular dependencies (accounting vs live/console config)
	mud.Provide[*accounting.Service](ball, func(log *zap.Logger, projectAccountingDB accounting.ProjectAccounting, liveAccounting accounting.Cache, metabaseDB metabase.DB, cc console.Config, config, lc live.Config) *accounting.Service {
		return accounting.NewService(log, projectAccountingDB, liveAccounting, metabaseDB, lc.BandwidthCacheTTL, cc.UsageLimits.Storage.Free, cc.UsageLimits.Bandwidth.Free, cc.UsageLimits.Segment.Free, lc.AsOfSystemInterval)
	})
	accounting.Module(ball)
	mud.View[DB, accounting.ProjectAccounting](ball, DB.ProjectAccounting)

	live.Module(ball)

	{
		mud.Provide[*server.Server](ball, server.New)
		config.RegisterConfig[server.Config](ball, "server2")
	}

	{
		mud.View[DB, entitlements.DB](ball, func(db DB) entitlements.DB {
			return db.Console().Entitlements()
		})
		mud.Provide[*entitlements.Service](ball, entitlements.NewService)
		config.RegisterConfig[entitlements.Config](ball, "entitlements")
	}

	compensation.Module(ball)
	mud.View[DB, accounting.StoragenodeAccounting](ball, DB.StoragenodeAccounting)
	nodestats.Module(ball)
	userinfo.Module(ball)
	snopayouts.Module(ball)
	mud.View[DB, snopayouts.DB](ball, DB.SNOPayouts)

	mud.Provide[*metainfo.MigrationModeFlagExtension](ball, metainfo.NewMigrationModeFlagExtension)
	mud.Provide[eventingconfig.BucketLocationTopicIDMap](ball, func(config eventingconfig.Config) eventingconfig.BucketLocationTopicIDMap {
		return config.Buckets
	})
	mud.Provide[*EndpointRegistration](ball, func(srv *server.Server,
		metainfoEndpoint *metainfo.Endpoint,
		endpoint *contact.Endpoint,
		ne *nodestats.Endpoint,
		ue *userinfo.Endpoint,
		ucfg userinfo.Config,
		se *snopayouts.Endpoint,
		ge *gracefulexit.Endpoint,
		gc gracefulexit.Config,
		oe *orders.Endpoint,
	) (*EndpointRegistration, error) {
		err := pb.DRPCRegisterMetainfo(srv.DRPC(), metainfoEndpoint)
		if err != nil {
			return nil, err
		}

		err = pb.DRPCRegisterOrders(srv.DRPC(), oe)
		if err != nil {
			return nil, err
		}

		err = pb.DRPCRegisterHeldAmount(srv.DRPC(), se)
		if err != nil {
			return nil, err
		}

		if ucfg.Enabled {
			err = pb.DRPCRegisterUserInfo(srv.DRPC(), ue)
			if err != nil {
				return nil, err
			}
		}

		if gc.Enabled {
			err = pb.DRPCRegisterSatelliteGracefulExit(srv.DRPC(), ge)
			if err != nil {
				return nil, err
			}
		}

		err = pb.DRPCRegisterNodeStats(srv.DRPC(), ne)
		if err != nil {
			return nil, err
		}

		err = pb.DRPCRegisterNode(srv.DRPC(), endpoint)
		if err != nil {
			return nil, err
		}
		return &EndpointRegistration{}, nil
	})

	mud.View[DB, audit.ReverifyQueue](ball, DB.ReverifyQueue)
	mud.View[DB, audit.VerifyQueue](ball, DB.VerifyQueue)
	mud.View[DB, audit.WrappedContainment](ball, func(db DB) audit.WrappedContainment {
		return audit.WrappedContainment{
			Containment: db.Containment(),
		}
	})
	mud.View[DB, reputation.DirectDB](ball, func(db DB) reputation.DirectDB {
		return db.Reputation()
	})
	mud.View[*identity.FullIdentity, signing.Signee](ball, func(fullIdentity *identity.FullIdentity) signing.Signee {
		return signing.SigneeFromPeerIdentity(fullIdentity.PeerIdentity())
	})
	checker.Module(ball)
	repairer.Module(ball)
	manual.Module(ball)
	repaircsv.Module(ball)
	reputation.Module(ball)
	jobq.Module(ball)
	healthcheck.Module(ball)
	mud.RegisterInterfaceImplementation[queue.RepairQueue, *jobq.RepairJobQueue](ball)
	eventing.Module(ball)
	mud.View[DB, oidc.DB](ball, DB.OIDC)
	oidc.Module(ball)
	mud.View[metabase.Adapter, changestream.Adapter](ball, func(adapter metabase.Adapter) changestream.Adapter {
		csAdapter, ok := adapter.(changestream.Adapter)
		if !ok {
			panic("changestream service requires spanner adapter")
		}
		return csAdapter
	})
	mud.Provide[*mailservice.Service](ball, setupMailService)
	mud.View[DB, stripe.DB](ball, DB.StripeCoinPayments)
	mud.View[DB, storjscan.WalletsDB](ball, DB.Wallets)
	mud.View[DB, billing.TransactionsDB](ball, DB.Billing)
	paymentsconfig.Module(ball)
	mud.Provide[stripe.ServiceConfig](ball, func(cfg console.Config, pc paymentsconfig.Config, ec entitlements.Config) stripe.ServiceConfig {
		return stripe.ServiceConfig{
			DeleteAccountEnabled:       cfg.SelfServeAccountDeleteEnabled,
			DeleteProjectCostThreshold: pc.DeleteProjectCostThreshold,
			EntitlementsEnabled:        ec.Enabled,
		}
	})

	// TODO: due to circular dependencies, we couldn't put these to stripe.Module
	mud.Provide[stripe.PricingConfig](ball, func(pc paymentsconfig.Config, placements nodeselection.PlacementDefinitions) (stripe.PricingConfig, error) {
		minimumChargeDate, err := pc.MinimumCharge.GetEffectiveDate()
		if err != nil {
			return stripe.PricingConfig{}, err
		}
		productPrices, err := pc.Products.ToModels()
		if err != nil {
			return stripe.PricingConfig{}, err
		}
		placementOverrideMap := pc.PlacementPriceOverrides.ToMap()
		err = paymentsconfig.ValidatePlacementOverrideMap(placementOverrideMap, productPrices, placements)
		if err != nil {
			return stripe.PricingConfig{}, err
		}
		priceOverrides, err := pc.UsagePriceOverrides.ToModels()
		if err != nil {
			return stripe.PricingConfig{}, err
		}
		prices, err := pc.UsagePrice.ToModel()
		if err != nil {
			return stripe.PricingConfig{}, err
		}
		return stripe.PricingConfig{
			UsagePrices:         prices,
			UsagePriceOverrides: priceOverrides,
			ProductPriceMap:     productPrices,
			PlacementProductMap: placementOverrideMap,
			PackagePlans:        pc.PackagePlans.Packages,
			BonusRate:           pc.BonusRate,
			MinimumChargeAmount: pc.MinimumCharge.Amount,
			MinimumChargeDate:   minimumChargeDate,
		}, nil
	})
	stripe.Module(ball)
	emission.Module(ball)
	kms.Module(ball)

	// TODO: remove circular dependency and move it to storjscan.Module
	mud.View[paymentsconfig.Config, storjscan.Config](ball, func(pc paymentsconfig.Config) storjscan.Config {
		return pc.Storjscan
	})
	mud.View[DB, storjscan.PaymentsDB](ball, DB.StorjscanPayments)
	mud.Provide[*storjscan.Service](ball, func(log *zap.Logger, walletsDB storjscan.WalletsDB, paymentsDB storjscan.PaymentsDB, client *storjscan.Client, pc paymentsconfig.Config, cfg storjscan.Config) *storjscan.Service {
		return storjscan.NewService(log, walletsDB, paymentsDB, client, cfg.Confirmations, pc.BonusRate)
	})
	storjscan.Module(ball)

}

// EndpointRegistration is a pseudo component to wire server and DRPC endpoints together.
type EndpointRegistration struct{}

// CreateServer creates and configures a console web server with all required dependencies.
func CreateServer(logger *zap.Logger,
	service *console.Service,
	consoleService *consoleservice.Service,
	oidcService *oidc.Service,
	mailService *mailservice.Service,
	hubspotMailService *hubspotmails.Service,
	analytics *analytics.Service,
	abTesting *abtesting.Service,
	accountFreezeService *console.AccountFreezeService,
	ssoService *sso.Service,
	csrfService *csrf.Service,

	nodeURL storxnetwork.NodeURL,

	cwconfig *consoleweb.Config,
	analyticsConfig analytics.Config,
	notificationService *pushnotifications.Service,
	stripeService *stripe.Service,
	developerService *developer.Service,
	ecfg entitlements.Config,
	ssoCfg sso.Config,
	stripeCfg stripe.Config,
	storjscanCfg storjscan.Config,
	pc paymentsconfig.Config) (*consoleweb.Server, error) {

	listener, err := net.Listen("tcp", cwconfig.Address)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	if cwconfig.AuthTokenSecret == "" {
		return nil, errs.New("Auth token secret required")
	}

	prices, err := pc.UsagePrice.ToModel()
	if err != nil {
		return nil, errs.Wrap(err)
	}

	stripePublicKey := stripeCfg.StripePublicKey

	summaries, err := consoleweb.CreateProductPriceSummaries(pc.Products)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return consoleweb.NewServer(logger, *cwconfig, service, consoleService, oidcService, mailService, hubspotMailService, analytics, abTesting,
		accountFreezeService, ssoService, csrfService, listener, stripePublicKey, storjscanCfg.Confirmations, nodeURL,
		analyticsConfig, notificationService, pc.PackagePlans, stripeService, developerService, pc.MinimumCharge, prices, summaries, ecfg.Enabled, ssoCfg.Enabled), nil
}

// CreateService creates console service.
// TODO: due to circular dependencies, we couldn't put this to console.Module (consoleweb.Config)
func CreateService(log *zap.Logger, store console.DB, restKeys restapikeys.DB, oauthRestKeys restapikeys.Service, projectAccounting accounting.ProjectAccounting,
	projectUsage *accounting.Service, buckets buckets.DB, attributions attribution.DB, accounts payments.Accounts, depositWallets payments.DepositWallets,
	billingDb billing.TransactionsDB, analytics *analytics.Service, tokens *consoleauth.Service, mailService *mailservice.Service, hubspotMailService *hubspotmails.Service,
	accountFreezeService *console.AccountFreezeService, emission *emission.Service, kmsService *kms.Service, ssoService *sso.Service,
	placements nodeselection.PlacementDefinitions, valdiService *valdi.Service,
	entitlementsService *entitlements.Service, entitlementsConfig entitlements.Config, cw consoleweb.Config, cfg console.Config, mcfg metainfo.Config, ssoCfg sso.Config, pc paymentsconfig.Config, bucketEventing eventingconfig.Config) (*console.Service, error) {

	productModels, err := pc.Products.ToModels()
	if err != nil {
		return nil, err
	}

	minimumChargeDate, err := pc.MinimumCharge.GetEffectiveDate()
	if err != nil {
		return nil, err
	}

	loginURL, err := cw.LoginURL()
	if err != nil {
		return nil, err
	}
	return console.NewService(log, store, restKeys, oauthRestKeys, projectAccounting, projectUsage, buckets, attributions, accounts, depositWallets,
		billingDb, analytics, tokens, mailService, hubspotMailService, accountFreezeService, emission, kmsService, valdiService, ssoService,
		cw.ExternalAddress, cw.ExternalAddress, cw.SatelliteName, cfg.WhiteLabel, mcfg.ProjectLimits.MaxBuckets, ssoCfg.Enabled, placements,
		console.VersioningConfig{
			UseBucketLevelObjectVersioning: mcfg.UseBucketLevelObjectVersioning,
		},
		cfg, pc.StripeCoinPayments.SkuEnabled, loginURL, cw.SupportURL(), bucketEventing,
		entitlementsService, entitlementsConfig, pc.PlacementPriceOverrides.ToMap(), productModels,
		pc.MinimumCharge.Amount, minimumChargeDate, pc.PackagePlans.Packages, cw.BackupToolsURL, nil)
}
