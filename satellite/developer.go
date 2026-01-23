// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellite

import (
	"context"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/identity"
	"storj.io/common/storj"
	"github.com/StorXNetwork/StorXMonitor/private/lifecycle"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/developer"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
)

// Developer is the satellite core process that runs developer console.
//
// architecture: Peer
type Developer struct {
	// core dependencies
	Log        *zap.Logger
	Identity   *identity.FullIdentity
	DB         DB
	MetabaseDB *metabase.DB

	Servers  *lifecycle.Group
	Services *lifecycle.Group

	Analytics struct {
		Service *analytics.Service
	}

	Developer struct {
		Listener net.Listener
		Server   *developer.Server
	}

	FreezeAccounts struct {
		Service *console.AccountFreezeService
	}
}

// NewDeveloper creates a new satellite developer peer.
func NewDeveloper(log *zap.Logger, full *identity.FullIdentity, db DB, metabaseDB *metabase.DB,
	config *Config) (*Developer, error) {
	peer := &Developer{
		Log:        log,
		Identity:   full,
		DB:         db,
		MetabaseDB: metabaseDB,

		Servers:  lifecycle.NewGroup(log.Named("servers")),
		Services: lifecycle.NewGroup(log.Named("services")),
	}

	{ // setup analytics
		peer.Analytics.Service = analytics.NewService(peer.Log.Named("analytics:service"), config.Analytics, config.Console.SatelliteName)

		peer.Services.Add(lifecycle.Item{
			Name:  "analytics:service",
			Run:   peer.Analytics.Service.Run,
			Close: peer.Analytics.Service.Close,
		})
	}

	{ // setup account freeze service
		peer.FreezeAccounts.Service = console.NewAccountFreezeService(
			db.Console(),
			peer.Analytics.Service,
			config.Console.AccountFreeze,
		)
	}

	{ // setup developer server
		var err error
		peer.Developer.Listener, err = net.Listen("tcp", config.Developer.Address)
		if err != nil {
			return nil, err
		}

		// Setup developer service
		consoleAuthConfig := consoleauth.Config{
			TokenExpirationTime: 24 * time.Hour,
		}
		authTokens := consoleauth.NewService(consoleAuthConfig, &consoleauth.Hmac{Secret: []byte(config.Console.AuthTokenSecret)})

		regTokenChecker := developer.NewConsoleServiceAdapter(peer.DB.Console(), config.Console.Config)

		// Setup mail service for developer emails
		mailService, err := setupMailService(log, Config{
			Mail: config.Mail,
		})
		if err != nil {
			log.Warn("Failed to setup mail service for developer", zap.Error(err))
			// Continue without mail service - emails won't be sent
			mailService = nil
		}

		// External address is required for developer service (used in activation emails)
		if config.Console.DeveloperExternalAddress == "" {
			return nil, errs.New("console.developer-external-address must be set for developer service")
		}

		developerService, err := developer.NewServiceWithMail(
			log.Named("developerservice"),
			peer.DB.Console(),
			peer.Analytics.Service,
			authTokens,
			config.Console.Config,
			regTokenChecker,
			mailService,
			config.Console.DeveloperExternalAddress,
		)
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		developerConfig := config.Developer
		// Use Console's AuthTokenSecret for JWT signing (same secret used for console auth tokens)
		developerConfig.JWTSecretKey = config.Console.AuthTokenSecret
		// Set RateLimit from console config
		developerConfig.RateLimit = config.Console.RateLimit

		// Load bad passwords
		badPasswords := make(map[string]struct{})
		if config.Console.BadPasswordsFile != "" {
			bytes, err := os.ReadFile(config.Console.BadPasswordsFile)
			if err != nil {
				log.Warn("Failed to load bad passwords file", zap.Error(err))
			} else {
				parsedPasswords := strings.Split(string(bytes), "\n")
				for _, p := range parsedPasswords {
					if p != "" {
						badPasswords[p] = struct{}{}
					}
				}
			}
		}

		// Create DB adapter to match developer.DB interface (Console() returns interface{})
		developerDB := &developerDBAdapter{db: peer.DB}

		// Note: console.Service is not available in developer peer, pass nil
		// The developer server will handle this gracefully
		var consoleService *console.Service = nil

		// Prepare server config
		serverConfig := developer.DeveloperServerConfig{
			ExternalAddress:             config.Console.DeveloperExternalAddress,
			SatelliteName:               config.Console.SatelliteName,
			LetUsKnowURL:                config.Console.LetUsKnowURL,
			TermsAndConditionsURL:       config.Console.TermsAndConditionsURL,
			ContactInfoURL:              config.Console.ContactInfoURL,
			GeneralRequestURL:           config.Console.GeneralRequestURL,
			DeveloperRegisterAPIKey:     config.Console.DeveloperRegisterAPIKey,
			SignupActivationCodeEnabled: config.Console.SignupActivationCodeEnabled,
		}

		developerServer, err := developer.NewServer(
			log.Named("developer"),
			peer.Developer.Listener,
			developerDB,
			peer.FreezeAccounts.Service,
			peer.Analytics.Service,
			developerConfig,
			developerService,
			consoleService,
			mailService,
			serverConfig,
			badPasswords,
		)
		if err != nil {
			return nil, err
		}
		peer.Developer.Server = developerServer

		peer.Servers.Add(lifecycle.Item{
			Name:  "developer",
			Run:   peer.Developer.Server.Run,
			Close: peer.Developer.Server.Close,
		})
	}

	return peer, nil
}

// Run runs satellite until it's either closed or it errors.
func (peer *Developer) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	group, ctx := errgroup.WithContext(ctx)

	pprof.Do(ctx, pprof.Labels("subsystem", "developer"), func(ctx context.Context) {
		peer.Servers.Run(ctx, group)
		peer.Services.Run(ctx, group)

		pprof.Do(ctx, pprof.Labels("name", "subsystem-wait"), func(ctx context.Context) {
			err = group.Wait()
		})
	})
	return err
}

// Close closes all the resources.
func (peer *Developer) Close() error {
	return errs.Combine(
		peer.Servers.Close(),
		peer.Services.Close(),
	)
}

// ID returns the peer ID.
func (peer *Developer) ID() storj.NodeID { return peer.Identity.ID }

// developerDBAdapter adapts satellite.DB to developer.DB interface.
type developerDBAdapter struct {
	db DB
}

func (a *developerDBAdapter) Console() interface{} {
	return a.db.Console()
}
