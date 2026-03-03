// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellite

import (
	"context"
	"net"
	"runtime/pprof"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/StorXNetwork/StorXMonitor/private/lifecycle"
	version_checker "github.com/StorXNetwork/StorXMonitor/private/version/checker"
	"github.com/StorXNetwork/StorXMonitor/satellite/accountfreeze"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/projectbwcleanup"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/rollup"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/rolluparchive"
	"github.com/StorXNetwork/StorXMonitor/satellite/accounting/tally"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/audit"
	"github.com/StorXNetwork/StorXMonitor/satellite/backup"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/dbcleanup"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/dbcleanup/pendingdelete"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/emailreminders"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/secretconstants"
	"github.com/StorXNetwork/StorXMonitor/satellite/emission"
	"github.com/StorXNetwork/StorXMonitor/satellite/entitlements"
	"github.com/StorXNetwork/StorXMonitor/satellite/gc/sender"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice/hubspotmails"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase/zombiedeletion"
	"github.com/StorXNetwork/StorXMonitor/satellite/metainfo/expireddeletion"
	"github.com/StorXNetwork/StorXMonitor/satellite/nodeevents"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay/offlinenodes"
	"github.com/StorXNetwork/StorXMonitor/satellite/overlay/straynodes"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/billing"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/storjscan"
	"github.com/StorXNetwork/StorXMonitor/satellite/payments/stripe"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/queue"
	"github.com/StorXNetwork/StorXMonitor/satellite/repair/repairer"
	"github.com/StorXNetwork/StorXMonitor/satellite/reputation"
	"github.com/StorXNetwork/StorXMonitor/satellite/smartcontract"
	"github.com/StorXNetwork/common/debug"
	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/peertls/extensions"
	"github.com/StorXNetwork/common/peertls/tlsopts"
	"github.com/StorXNetwork/common/rpc"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/version"
)

// Core is the satellite core process that runs chores.
//
// architecture: Peer
type Core struct {
	// core dependencies
	Log      *zap.Logger
	Identity *identity.FullIdentity
	DB       DB

	Servers  *lifecycle.Group
	Services *lifecycle.Group

	Dialer rpc.Dialer

	Version struct {
		Chore   *version_checker.Chore
		Service *version_checker.Service
	}

	Analytics struct {
		Service *analytics.Service
	}

	Entitlements struct {
		Service *entitlements.Service
	}

	Mail struct {
		Service        *mailservice.Service
		HubspotService *hubspotmails.Service
		EmailReminders *emailreminders.Chore
	}

	Debug struct {
		Listener net.Listener
		Server   *debug.Server
	}

	// services and endpoints
	Overlay struct {
		DB                overlay.DB
		Service           *overlay.Service
		OfflineNodeEmails *offlinenodes.Chore
		DQStrayNodes      *straynodes.Chore
	}

	NodeEvents struct {
		DB       nodeevents.DB
		Notifier nodeevents.Notifier
		Chore    *nodeevents.Chore
	}

	Metainfo struct {
		Metabase *metabase.DB
	}

	Reputation struct {
		Service *reputation.Service
	}

	Audit struct {
		ReverifyQueue        audit.ReverifyQueue
		ContainmentSyncChore *audit.ContainmentSyncChore
	}

	ExpiredDeletion struct {
		Chore *expireddeletion.Chore
	}

	ZombieDeletion struct {
		Chore *zombiedeletion.Chore
	}

	Accounting struct {
		Tally                 *tally.Service
		Rollup                *rollup.Service
		RollupArchiveChore    *rolluparchive.Chore
		ProjectBWCleanupChore *projectbwcleanup.Chore
		ProjectUsage          *accounting.Service
	}

	LiveAccounting struct {
		Cache accounting.Cache
	}

	AccountFreeze struct {
		BillingFreezeChore *accountfreeze.Chore
		BotFreezeChore     *accountfreeze.BotFreezeChore
		TrialFreezeChore   *accountfreeze.TrialFreezeChore
	}

	Payments struct {
		Accounts         payments.Accounts
		BillingChore     *billing.Chore
		StorjscanClient  *storjscan.Client
		StorjscanService *storjscan.Service
		StorjscanChore   *storjscan.Chore
	}

	ConsoleDBCleanup struct {
		Chore              *dbcleanup.Chore
		PendingDeleteChore *pendingdelete.Chore
	}

	GarbageCollection struct {
		Sender *sender.Service
	}

	RepairQueueStat struct {
		Queue queue.RepairQueue
		Chore *repairer.QueueStat
	}

	Backup struct {
		Service *backup.Service
	}
}

// New creates a new satellite.
func New(log *zap.Logger, full *identity.FullIdentity, db DB, metabaseDB *metabase.DB,
	revocationDB extensions.RevocationDB, repairQueue queue.RepairQueue,
	liveAccounting accounting.Cache, versionInfo version.Info, config *Config,
	atomicLogLevel *zap.AtomicLevel) (*Core, error) {
	peer := &Core{
		Log:      log,
		Identity: full,
		DB:       db,

		Servers:  lifecycle.NewGroup(log.Named("servers")),
		Services: lifecycle.NewGroup(log.Named("services")),
	}

	{ // setup debug
		if config.Debug.Addr != "" {
			peer.Debug.Listener, _ = net.Listen("tcp", config.Debug.Addr)
		}
		debugConfig := config.Debug
		debugConfig.ControlTitle = "Core"
		peer.Debug.Server = debug.NewServerWithAtomicLevel(log.Named("debug"), peer.Debug.Listener, monkit.Default, debugConfig, atomicLogLevel)
		peer.Servers.Add(lifecycle.Item{
			Name:  "debug",
			Run:   peer.Debug.Server.Run,
			Close: peer.Debug.Server.Close,
		})
	}

	var err error

	{ // setup version control
		peer.Log.Info("Version info",
			zap.Stringer("version", versionInfo.Version.Version),
			zap.String("commit_hash", versionInfo.CommitHash),
			zap.Stringer("build_timestamp", versionInfo.Timestamp),
			zap.Bool("release_build", versionInfo.Release),
		)
		peer.Version.Service = version_checker.NewService(log.Named("version"), config.Version, versionInfo, "Satellite")
		peer.Version.Chore = version_checker.NewChore(peer.Version.Service, config.Version.CheckInterval)

		peer.Services.Add(lifecycle.Item{
			Name: "version",
			Run:  peer.Version.Chore.Run,
		})
	}

	{ // setup listener and server
		sc := config.Server

		tlsOptions, err := tlsopts.NewOptions(peer.Identity, sc.Config, revocationDB)
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		peer.Dialer = rpc.NewDefaultDialer(tlsOptions)
	}

	{ // setup analytics service
		peer.Analytics.Service = analytics.NewService(peer.Log.Named("analytics:service"), config.Analytics, config.Console.SatelliteName, config.Console.ExternalAddress)

		peer.Services.Add(lifecycle.Item{
			Name:  "analytics:service",
			Run:   peer.Analytics.Service.Run,
			Close: peer.Analytics.Service.Close,
		})
	}

	{ // setup legacy and hubspot mail services
		peer.Mail.Service, err = setupMailService(peer.Log, config.Mail, config.Console)
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		peer.Services.Add(lifecycle.Item{
			Name:  "mail:service",
			Close: peer.Mail.Service.Close,
		})

		peer.Mail.HubspotService = hubspotmails.NewService(peer.Log.Named("mail:hubspotservice"), peer.Analytics.Service, config.HubspotMails)

		peer.Services.Add(lifecycle.Item{
			Name:  "hubspotmails:service",
			Close: peer.Mail.HubspotService.Close,
		})
	}

	{ // setup email reminders
		if config.EmailReminders.Enable {
			authTokens := consoleauth.NewService(config.ConsoleAuth, &consoleauth.Hmac{Secret: []byte(config.Console.AuthTokenSecret)})

			peer.Mail.EmailReminders = emailreminders.NewChore(
				peer.Log.Named("console:chore"),
				authTokens,
				peer.DB.Console().Users(),
				peer.DB.Console().Projects(),
				liveAccounting,
				peer.Mail.Service,
				config.EmailReminders,
				config.Console.ExternalAddress,
				config.Console.GeneralRequestURL,
				config.Console.ScheduleMeetingURL,
				nil,
				peer.Accounting.ProjectUsage,
			)

			peer.Services.Add(lifecycle.Item{
				Name:  "mail:email-reminders",
				Run:   peer.Mail.EmailReminders.Run,
				Close: peer.Mail.EmailReminders.Close,
			})
		}
	}

	placement, err := config.Placement.Parse(config.Overlay.Node.CreateDefaultPlacement, nil)
	if err != nil {
		return nil, err
	}

	{ // setup overlay

		peer.Overlay.DB = peer.DB.OverlayCache()
		peer.Overlay.Service, err = overlay.NewService(peer.Log.Named("overlay"), peer.Overlay.DB, peer.DB.NodeEvents(), placement, config.Console.ExternalAddress, config.Console.SatelliteName, config.Overlay)
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}
		peer.Services.Add(lifecycle.Item{
			Name:  "overlay",
			Run:   peer.Overlay.Service.Run,
			Close: peer.Overlay.Service.Close,
		})

		if config.Overlay.SendNodeEmails {
			peer.Overlay.OfflineNodeEmails = offlinenodes.NewChore(log.Named("overlay:offline-node-emails"), peer.Mail.Service, peer.Overlay.Service, config.OfflineNodes)
			peer.Services.Add(lifecycle.Item{
				Name:  "overlay:offline-node-emails",
				Run:   peer.Overlay.OfflineNodeEmails.Run,
				Close: peer.Overlay.OfflineNodeEmails.Close,
			})
			peer.Debug.Server.Panel.Add(
				debug.Cycle("Overlay Offline Node Emails", peer.Overlay.OfflineNodeEmails.Loop))
		}

		if config.StrayNodes.EnableDQ {
			peer.Overlay.DQStrayNodes = straynodes.NewChore(peer.Log.Named("overlay:dq-stray-nodes"), peer.Overlay.Service, config.StrayNodes)
			peer.Services.Add(lifecycle.Item{
				Name:  "overlay:dq-stray-nodes",
				Run:   peer.Overlay.DQStrayNodes.Run,
				Close: peer.Overlay.DQStrayNodes.Close,
			})
			peer.Debug.Server.Panel.Add(
				debug.Cycle("Overlay DQ Stray Nodes", peer.Overlay.DQStrayNodes.Loop))
		}
	}

	{ // setup node events
		if config.Overlay.SendNodeEmails {
			var notifier nodeevents.Notifier
			switch config.NodeEvents.Notifier {
			case "customer.io":
				notifier = nodeevents.NewCustomerioNotifier(
					log.Named("node-events:customer.io-notifier"),
					config.NodeEvents.Customerio,
				)
			default:
				notifier = nodeevents.NewMockNotifier(log.Named("node-events:mock-notifier"))
			}
			peer.NodeEvents.Notifier = notifier
			peer.NodeEvents.DB = peer.DB.NodeEvents()
			peer.NodeEvents.Chore = nodeevents.NewChore(peer.Log.Named("node-events:chore"), peer.NodeEvents.DB, config.Console.SatelliteName, peer.NodeEvents.Notifier, config.NodeEvents)
			peer.Services.Add(lifecycle.Item{
				Name:  "node-events:chore",
				Run:   peer.NodeEvents.Chore.Run,
				Close: peer.NodeEvents.Chore.Close,
			})
		}
	}

	{ // setup live accounting
		peer.LiveAccounting.Cache = liveAccounting
	}

	{ // setup metainfo
		peer.Metainfo.Metabase = metabaseDB
	}

	{ // setup reputation
		reputationDB := peer.DB.Reputation()
		if config.Reputation.FlushInterval > 0 {
			cachingDB := reputation.NewCachingDB(log.Named("reputation:writecache"), reputationDB, config.Reputation)
			peer.Services.Add(lifecycle.Item{
				Name: "reputation:writecache",
				Run:  cachingDB.Manage,
			})
			reputationDB = cachingDB
		}
		peer.Reputation.Service = reputation.NewService(log.Named("reputation:service"),
			peer.Overlay.Service,
			reputationDB,
			config.Reputation,
		)
		peer.Services.Add(lifecycle.Item{
			Name:  "reputation",
			Close: peer.Reputation.Service.Close,
		})
	}

	{ // setup audit
		config := config.Audit

		peer.Audit.ReverifyQueue = db.ReverifyQueue()

		peer.Audit.ContainmentSyncChore = audit.NewContainmentSyncChore(peer.Log.Named("audit:containment-sync-chore"),
			peer.Audit.ReverifyQueue,
			peer.Overlay.DB,
			config.ContainmentSyncChoreInterval,
		)
		peer.Services.Add(lifecycle.Item{
			Name: "audit:containment-sync-chore",
			Run:  peer.Audit.ContainmentSyncChore.Run,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Audit Containment Sync Chore", peer.Audit.ContainmentSyncChore.Loop))
	}

	{ // setup expired segment cleanup
		peer.ExpiredDeletion.Chore = expireddeletion.NewChore(
			peer.Log.Named("core-expired-deletion"),
			config.ExpiredDeletion,
			peer.Metainfo.Metabase,
		)
		peer.Services.Add(lifecycle.Item{
			Name:  "expireddeletion:chore",
			Run:   peer.ExpiredDeletion.Chore.Run,
			Close: peer.ExpiredDeletion.Chore.Close,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Expired Segments Chore", peer.ExpiredDeletion.Chore.Loop))
	}

	{ // setup zombie objects cleanup
		peer.ZombieDeletion.Chore = zombiedeletion.NewChore(
			peer.Log.Named("core-zombie-deletion"),
			config.ZombieDeletion,
			peer.Metainfo.Metabase,
		)
		peer.Services.Add(lifecycle.Item{
			Name:  "zombiedeletion:chore",
			Run:   peer.ZombieDeletion.Chore.Run,
			Close: peer.ZombieDeletion.Chore.Close,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Zombie Objects Chore", peer.ZombieDeletion.Chore.Loop))
	}

	// Parse product prices early for use in tally service
	productPrices, err := config.Payments.Products.ToModels()
	if err != nil {
		return nil, errs.Combine(err, peer.Close())
	}

	{ // setup accounting
		// Convert product prices to tally-compatible format.
		tallyProductPrices := make(map[int32]tally.ProductUsagePriceModel)
		for id, price := range productPrices {
			tallyProductPrices[id] = tally.ProductUsagePriceModel{
				ProductID:             price.ProductID,
				StorageRemainderBytes: price.StorageRemainderBytes,
			}
		}

		// Convert global placement map.
		globalPlacementMap := make(tally.PlacementProductMap)
		for placement, productID := range config.Payments.PlacementPriceOverrides.ToMap() {
			globalPlacementMap[placement] = productID
		}

		peer.Accounting.Tally = tally.New(
			peer.Log.Named("accounting:tally"),
			peer.DB.StoragenodeAccounting(),
			peer.DB.ProjectAccounting(),
			peer.LiveAccounting.Cache,
			peer.Metainfo.Metabase,
			peer.DB.Buckets(),
			config.Tally,
			tallyProductPrices,
			globalPlacementMap,
		)
		peer.Services.Add(lifecycle.Item{
			Name:  "accounting:tally",
			Run:   peer.Accounting.Tally.Run,
			Close: peer.Accounting.Tally.Close,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Accounting Tally", peer.Accounting.Tally.Loop))

		// Lets add 1 more day so we catch any off by one errors when deleting tallies
		orderExpirationPlusDay := config.Orders.Expiration + config.Rollup.Interval
		peer.Accounting.Rollup = rollup.New(peer.Log.Named("accounting:rollup"), peer.DB.StoragenodeAccounting(), config.Rollup, orderExpirationPlusDay)
		peer.Services.Add(lifecycle.Item{
			Name:  "accounting:rollup",
			Run:   peer.Accounting.Rollup.Run,
			Close: peer.Accounting.Rollup.Close,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Accounting Rollup", peer.Accounting.Rollup.Loop))

		peer.Accounting.ProjectBWCleanupChore = projectbwcleanup.NewChore(peer.Log.Named("accounting:chore"), peer.DB.ProjectAccounting(), config.ProjectBWCleanup)
		peer.Services.Add(lifecycle.Item{
			Name:  "accounting:project-bw-rollup",
			Run:   peer.Accounting.ProjectBWCleanupChore.Run,
			Close: peer.Accounting.ProjectBWCleanupChore.Close,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Accounting Project Bandwidth Rollup", peer.Accounting.ProjectBWCleanupChore.Loop))

		// Setup accounting project usage
		peer.Accounting.ProjectUsage = accounting.NewService(
			peer.Log.Named("accounting:projectusage-service"),
			peer.DB.ProjectAccounting(),
			peer.LiveAccounting.Cache,
			*metabaseDB,
			config.LiveAccounting.BandwidthCacheTTL,
			config.Console.Config.UsageLimits.Storage.Free,
			config.Console.Config.UsageLimits.Bandwidth.Free,
			config.Console.Config.UsageLimits.Segment.Free,
			config.LiveAccounting.AsOfSystemInterval,
		)

		if config.RollupArchive.Enabled {
			peer.Accounting.RollupArchiveChore = rolluparchive.New(peer.Log.Named("accounting:rollup-archive"), peer.DB.StoragenodeAccounting(), peer.DB.ProjectAccounting(), config.RollupArchive)
			peer.Services.Add(lifecycle.Item{
				Name:  "accounting:rollup-archive",
				Run:   peer.Accounting.RollupArchiveChore.Run,
				Close: peer.Accounting.RollupArchiveChore.Close,
			})
			peer.Debug.Server.Panel.Add(
				debug.Cycle("Accounting Rollup Archive", peer.Accounting.RollupArchiveChore.Loop))
		} else {
			peer.Log.Named("rolluparchive").Info("disabled")
		}
	}

	{ // setup entitlements
		peer.Entitlements.Service = entitlements.NewService(
			peer.Log.Named("entitlements:service"),
			db.Console().Entitlements(),
		)
	}

	{ // setup email reminders (after accounting to have access to ProjectUsage)
		if config.EmailReminders.Enable {
			authTokens := consoleauth.NewService(config.ConsoleAuth, &consoleauth.Hmac{Secret: []byte(config.Console.AuthTokenSecret)})

			peer.Mail.EmailReminders = emailreminders.NewChore(
				peer.Log.Named("console:chore"),
				authTokens,
				peer.DB.Console().Users(),
				peer.DB.Console().Projects(),
				liveAccounting,
				peer.Mail.Service,
				config.EmailReminders,
				config.Console.ExternalAddress,
				config.Console.GeneralRequestURL,
				config.Console.ScheduleMeetingURL,
				nil,                          // consoleService not available in core.go, pass nil
				peer.Accounting.ProjectUsage, // Pass projectUsage service
			)

			peer.Services.Add(lifecycle.Item{
				Name:  "mail:email-reminders",
				Run:   peer.Mail.EmailReminders.Run,
				Close: peer.Mail.EmailReminders.Close,
			})
		}
	}

	// TODO: remove in future, should be in API
	{ // setup payments
		pc := config.Payments

		var stripeClient stripe.Client
		switch pc.Provider {
		case "": // just new mock, only used in testing binaries
			stripeClient = stripe.NewStripeMock(
				peer.DB.StripeCoinPayments().Customers(),
				peer.DB.Console().Users(),
			)
		case "mock":
			stripeClient = pc.MockProvider
		case "stripecoinpayments":
			stripeClient = stripe.NewStripeClient(log, pc.StripeCoinPayments)
		default:
			return nil, errs.New("invalid stripe coin payments provider %q", pc.Provider)
		}

		prices, err := pc.UsagePrice.ToModel()
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		priceOverrides, err := pc.UsagePriceOverrides.ToModels()
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		// productPrices already parsed earlier for tally service

		minimumChargeDate, err := pc.MinimumCharge.GetEffectiveDate()
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		service, err := stripe.NewService(
			peer.Log.Named("payments.stripe:service"),
			stripeClient,
			stripe.ServiceDependencies{
				DB:           peer.DB.StripeCoinPayments(),
				WalletsDB:    peer.DB.Wallets(),
				BillingDB:    peer.DB.Billing(),
				ProjectsDB:   peer.DB.Console().Projects(),
				UsersDB:      peer.DB.Console().Users(),
				UsageDB:      peer.DB.ProjectAccounting(),
				Analytics:    peer.Analytics.Service,
				Emission:     emission.NewService(config.Emission),
				Entitlements: peer.Entitlements.Service,
			},
			stripe.ServiceConfig{
				DeleteAccountEnabled:       config.Console.SelfServeAccountDeleteEnabled,
				DeleteProjectCostThreshold: pc.DeleteProjectCostThreshold,
				EntitlementsEnabled:        config.Entitlements.Enabled,
			},
			pc.StripeCoinPayments,
			stripe.PricingConfig{
				UsagePrices:         prices,
				UsagePriceOverrides: priceOverrides,
				ProductPriceMap:     productPrices,
				PlacementProductMap: pc.PlacementPriceOverrides.ToMap(),
				PackagePlans:        pc.PackagePlans.Packages,
				BonusRate:           pc.BonusRate,
				MinimumChargeAmount: pc.MinimumCharge.Amount,
				MinimumChargeDate:   minimumChargeDate,
			},
		)
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		peer.Payments.Accounts = service.Accounts()

		peer.Payments.StorjscanClient = storjscan.NewClient(
			pc.Storjscan.Endpoint,
			pc.Storjscan.Auth.Identifier,
			pc.Storjscan.Auth.Secret)

		peer.Payments.StorjscanService = storjscan.NewService(log.Named("storjscan-service"),
			peer.DB.Wallets(),
			peer.DB.StorjscanPayments(),
			peer.Payments.StorjscanClient,
			pc.Storjscan.Confirmations,
			pc.BonusRate)

		peer.Payments.StorjscanChore = storjscan.NewChore(
			peer.Log.Named("payments.storjscan:chore"),
			peer.Payments.StorjscanClient,
			peer.DB.StorjscanPayments(),
			config.Payments.Storjscan.Confirmations,
			config.Payments.Storjscan.Interval,
			config.Payments.Storjscan.DisableLoop,
		)
		peer.Services.Add(lifecycle.Item{
			Name: "payments.storjscan:chore",
			Run:  peer.Payments.StorjscanChore.Run,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Payments Storjscan", peer.Payments.StorjscanChore.TransactionCycle),
		)

		freezeService := console.NewAccountFreezeService(peer.DB.Console(), peer.Analytics.Service, config.Console.AccountFreeze)
		choreObservers := billing.ChoreObservers{
			UpgradeUser: console.NewUpgradeUserObserver(peer.DB.Console(), peer.DB.Billing(), config.Console.UsageLimits, config.Console.UserBalanceForUpgrade, config.Console.ExternalAddress, freezeService, peer.Analytics.Service, peer.Mail.Service),
			PayInvoices: console.NewInvoiceTokenPaymentObserver(
				peer.DB.Console(), peer.Payments.Accounts.Invoices(),
				freezeService,
			),
		}

		peer.Payments.BillingChore = billing.NewChore(
			peer.Log.Named("payments.billing:chore"),
			[]billing.PaymentType{peer.Payments.StorjscanService},
			peer.DB.Billing(),
			config.Payments.BillingConfig.Interval,
			config.Payments.BillingConfig.DisableLoop,
			config.Payments.BonusRate,
			choreObservers,
		)
		peer.Services.Add(lifecycle.Item{
			Name:  "billing:chore",
			Run:   peer.Payments.BillingChore.Run,
			Close: peer.Payments.BillingChore.Close,
		})
	}

	{ // setup account freeze
		if config.AccountFreeze.Enabled {
			peer.AccountFreeze.BillingFreezeChore = accountfreeze.NewChore(peer.Log.Named("payments.accountfreeze:chore"), peer.DB.StripeCoinPayments(), peer.Payments.Accounts, peer.DB.Console().Users(), peer.DB.Wallets(), peer.DB.StorjscanPayments(), console.NewAccountFreezeService(db.Console(), peer.Analytics.Service, config.Console.AccountFreeze), peer.Analytics.Service, peer.Mail.Service, config.Console.AccountFreeze, config.AccountFreeze, config.Console.ExternalAddress, config.Console.GeneralRequestURL)
			peer.AccountFreeze.BotFreezeChore = accountfreeze.NewBotFreezeChore(peer.Log.Named("payments.accountfreeze:chore"), peer.DB.Console().Users(), console.NewAccountFreezeService(db.Console(), peer.Analytics.Service, config.Console.AccountFreeze), config.AccountFreeze, config.Console.Captcha.FlagBotsEnabled)
			peer.AccountFreeze.TrialFreezeChore = accountfreeze.NewTrialFreezeChore(peer.Log.Named("payments.accountfreeze:chore"), peer.DB.Console().Users(), console.NewAccountFreezeService(db.Console(), peer.Analytics.Service, config.Console.AccountFreeze), peer.Mail.Service, config.Console.AccountFreeze, config.AccountFreeze, config.Console.ExternalAddress, config.Console.GeneralRequestURL)

			peer.Services.Add(lifecycle.Item{
				Name:  "accountfreeze:billingfreezechore",
				Run:   peer.AccountFreeze.BillingFreezeChore.Run,
				Close: peer.AccountFreeze.BillingFreezeChore.Close,
			})

			peer.Services.Add(lifecycle.Item{
				Name:  "accountfreeze:botfreezechore",
				Run:   peer.AccountFreeze.BotFreezeChore.Run,
				Close: peer.AccountFreeze.BotFreezeChore.Close,
			})

			peer.Services.Add(lifecycle.Item{
				Name:  "accountfreeze:trialfreezechore",
				Run:   peer.AccountFreeze.TrialFreezeChore.Run,
				Close: peer.AccountFreeze.TrialFreezeChore.Close,
			})
		}
	}

	// setup console DB cleanup service
	if config.ConsoleDBCleanup.Enabled {
		peer.ConsoleDBCleanup.Chore = dbcleanup.NewChore(
			peer.Log.Named("console.dbcleanup:chore"),
			peer.DB.Console(),
			config.ConsoleDBCleanup,
			config.Console.Config,
		)

		peer.Services.Add(lifecycle.Item{
			Name:  "dbcleanup:chore",
			Run:   peer.ConsoleDBCleanup.Chore.Run,
			Close: peer.ConsoleDBCleanup.Chore.Close,
		})
	}

	{ // setup pending delete escalator
		if config.PendingDeleteCleanup.Enabled {
			peer.ConsoleDBCleanup.PendingDeleteChore = pendingdelete.NewChore(
				peer.Log.Named("console.dbcleanup.pendingdelete:chore"),
				config.PendingDeleteCleanup,
				peer.Payments.Accounts,
				console.NewAccountFreezeService(db.Console(), peer.Analytics.Service, config.Console.AccountFreeze),
				peer.DB.Buckets(),
				peer.DB.Console(),
				peer.Metainfo.Metabase,
			)

			peer.Services.Add(lifecycle.Item{
				Name:  "dbcleanup.pendingdelete:chore",
				Run:   peer.ConsoleDBCleanup.PendingDeleteChore.Run,
				Close: peer.ConsoleDBCleanup.PendingDeleteChore.Close,
			})
		}
	}

	{
		peer.RepairQueueStat.Queue = repairQueue

		if config.RepairQueueCheck.Interval.Seconds() > 0 {
			peer.RepairQueueStat.Chore = repairer.NewQueueStat(log, monkit.Default, placement.SupportedPlacements(), repairQueue, config.RepairQueueCheck.Interval)

			peer.Services.Add(lifecycle.Item{
				Name: "queue-stat",
				Run:  peer.RepairQueueStat.Chore.Run,
			})
		}
	}

	{ // setup garbage collection
		peer.GarbageCollection.Sender = sender.NewService(
			peer.Log.Named("gc-sender"),
			config.GarbageCollection,
			peer.Dialer,
			peer.Overlay.DB,
		)

		peer.Services.Add(lifecycle.Item{
			Name: "gc-sender",
			Run:  peer.GarbageCollection.Sender.Run,
		})
		peer.Debug.Server.Panel.Add(
			debug.Cycle("Garbage Collection", peer.GarbageCollection.Sender.Loop))
	}

	{ // setup backup service
		// Create smart contract helper using console Web3Auth configuration
		smartContractConnector, err := smartcontract.NewKeyValueWeb3Helper(smartcontract.Web3Config{
			NetworkRPC:   config.Console.Web3AuthNetworkRPC,
			ContractAddr: config.Console.Web3AuthContractAddress,
			Address:      config.Console.Web3AuthAddress,
		}, secretconstants.Web3AuthPrivateKey)
		if err != nil {
			peer.Log.Warn("Failed to create smart contract connector for backup", zap.Error(err))
		} else {
			peer.Backup.Service, err = backup.NewService(
				peer.Log.Named("backup"),
				peer.DB.Web3Auth(),
				smartContractConnector,
				&config.Backup,
			)
			if err != nil {
				peer.Log.Warn("Failed to create backup service", zap.Error(err))
			} else {
				peer.Services.Add(lifecycle.Item{
					Name:  "backup",
					Run:   peer.Backup.Service.Run,
					Close: peer.Backup.Service.Close,
				})
				peer.Debug.Server.Panel.Add(
					debug.Cycle("Backup Service", peer.Backup.Service.Backup.Worker.Loop))
			}
		}
	}

	return peer, nil
}

// Run runs satellite until it's either closed or it errors.
func (peer *Core) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	group, ctx := errgroup.WithContext(ctx)

	pprof.Do(ctx, pprof.Labels("subsystem", "core"), func(ctx context.Context) {
		peer.Servers.Run(ctx, group)
		peer.Services.Run(ctx, group)

		pprof.Do(ctx, pprof.Labels("name", "subsystem-wait"), func(ctx context.Context) {
			err = group.Wait()
		})
	})
	return err
}

// Close closes all the resources.
func (peer *Core) Close() error {
	return errs.Combine(
		peer.Servers.Close(),
		peer.Services.Close(),
	)
}

// ID returns the peer ID.
func (peer *Core) ID() storxnetwork.NodeID { return peer.Identity.ID }
