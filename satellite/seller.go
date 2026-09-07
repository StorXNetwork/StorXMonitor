// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellite

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/StorXNetwork/StorXMonitor/private/lifecycle"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth/csrf"
	"github.com/StorXNetwork/StorXMonitor/satellite/metabase"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/identity"
	"github.com/StorXNetwork/common/storxnetwork"
)

// Seller is the satellite peer process that runs the seller console.
//
// architecture: Peer
type Seller struct {
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

	Seller struct {
		Listener net.Listener
		Server   *seller.Server
	}

	FreezeAccounts struct {
		Service *console.AccountFreezeService
	}
}

// NewSeller creates a new satellite seller peer.
func NewSeller(log *zap.Logger, full *identity.FullIdentity, db DB, metabaseDB *metabase.DB,
	config *Config) (*Seller, error) {
	peer := &Seller{
		Log:        log,
		Identity:   full,
		DB:         db,
		MetabaseDB: metabaseDB,

		Servers:  lifecycle.NewGroup(log.Named("servers")),
		Services: lifecycle.NewGroup(log.Named("services")),
	}

	{ // setup analytics
		peer.Analytics.Service = analytics.NewService(peer.Log.Named("analytics:service"), config.Analytics, config.Console.SatelliteName, config.Console.ExternalAddress)

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

	{ // setup seller server
		var err error
		peer.Seller.Listener, err = net.Listen("tcp", config.Seller.Address)
		if err != nil {
			return nil, err
		}

		consoleAuthConfig := consoleauth.Config{
			TokenExpirationTime: 24 * time.Hour,
		}
		authTokens := consoleauth.NewService(consoleAuthConfig, &consoleauth.Hmac{Secret: []byte(config.Console.AuthTokenSecret)})

		if config.Console.SellerExternalAddress == "" {
			return nil, errs.New("console.seller-external-address must be set for seller service")
		}

		badPasswords := make(map[string]struct{})
		badPasswordsEncoded := ""
		badPasswordsFile := config.Seller.Auth.BadPasswordsFile
		if badPasswordsFile != "" {
			bytes, readErr := os.ReadFile(badPasswordsFile)
			if readErr != nil {
				log.Warn("Failed to load seller bad passwords file", zap.Error(readErr))
			} else {
				badPasswordsEncoded = base64.StdEncoding.EncodeToString(bytes)
				for _, p := range strings.Split(string(bytes), "\n") {
					if p != "" {
						badPasswords[p] = struct{}{}
					}
				}
			}
		}

		sellerService, err := seller.NewService(
			log.Named("sellerservice"),
			peer.DB.Seller(),
			peer.Analytics.Service,
			authTokens,
			config.Seller.Auth,
			config.Console.SellerExternalAddress,
			len(badPasswords) > 0,
		)
		if err != nil {
			return nil, errs.Combine(err, peer.Close())
		}

		mailService, err := setupMailService(log, config.Mail, config.Console)
		if err != nil {
			log.Warn("Failed to setup mail service for seller", zap.Error(err))
			mailService = nil
		}

		csrfService := csrf.NewService(authTokens)

		serverConfig := seller.SellerServerConfig{
			ExternalAddress:        config.Console.SellerExternalAddress,
			SatelliteName:          config.Console.SatelliteName,
			LetUsKnowURL:           config.Console.LetUsKnowURL,
			TermsAndConditionsURL:  config.Console.TermsAndConditionsURL,
			ContactInfoURL:         config.Console.ContactInfoURL,
			GeneralRequestURL:      config.Console.GeneralRequestURL,
			GoogleClientID:         config.Console.GoogleClientID,
			GoogleClientSecret:     config.Console.GoogleClientSecret,
			GoogleOAuthRedirectURL: config.Console.GoogleSellerRedirectURLstring,
			ClientOrigin:           config.Console.ClientOrigin,
		}

		sellerService.ExtendService(mailService, seller.SellerServerRuntimeConfig{
			SatelliteName:       serverConfig.SatelliteName,
			ExternalAddress:     serverConfig.ExternalAddress,
			LetUsKnowURL:        serverConfig.LetUsKnowURL,
			TermsAndConditionsURL: serverConfig.TermsAndConditionsURL,
			ContactInfoURL:      serverConfig.ContactInfoURL,
			GeneralRequestURL:   serverConfig.GeneralRequestURL,
		})

		sellerConfig := config.Seller
		sellerConfig.JWTSecretKey = config.Console.AuthTokenSecret

		sellerServer, err := seller.NewServer(
			log.Named("seller"),
			peer.Seller.Listener,
			peer.DB.Seller(),
			peer.Analytics.Service,
			sellerConfig,
			sellerService,
			serverConfig,
			badPasswords,
			badPasswordsEncoded,
			csrfService,
		)
		if err != nil {
			return nil, err
		}
		peer.Seller.Server = sellerServer

		peer.Servers.Add(lifecycle.Item{
			Name:  "seller",
			Run:   peer.Seller.Server.Run,
			Close: peer.Seller.Server.Close,
		})
	}

	return peer, nil
}

// Run runs satellite until it's either closed or it errors.
func (peer *Seller) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	group, ctx := errgroup.WithContext(ctx)

	pprof.Do(ctx, pprof.Labels("subsystem", "seller"), func(ctx context.Context) {
		peer.Servers.Run(ctx, group)
		peer.Services.Run(ctx, group)

		pprof.Do(ctx, pprof.Labels("name", "subsystem-wait"), func(ctx context.Context) {
			err = group.Wait()
		})
	})
	return err
}

// Close closes all the resources.
func (peer *Seller) Close() error {
	return errs.Combine(
		peer.Servers.Close(),
		peer.Services.Close(),
	)
}

// ID returns the peer ID.
func (peer *Seller) ID() storxnetwork.NodeID { return peer.Identity.ID }
