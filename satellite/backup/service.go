// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package backup

import (
	"context"
	"errors"
	"net"
	"runtime/pprof"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/debug"
	"storj.io/common/version"
	"github.com/StorXNetwork/StorXMonitor/private/lifecycle"
	version_checker "github.com/StorXNetwork/StorXMonitor/private/version/checker"
	"github.com/StorXNetwork/StorXMonitor/satellite/smartcontract"
)

// Service is the backup service process.
//
// architecture: Peer
type Service struct {
	Log *zap.Logger

	Servers  *lifecycle.Group
	Services *lifecycle.Group

	Version struct {
		Chore   *version_checker.Chore
		Service *version_checker.Service
	}

	Debug struct {
		Listener net.Listener
		Server   *debug.Server
	}

	Backup struct {
		Worker *Worker
	}

	db       DB
	contract smartcontract.SocialShareHelper
	config   *Config
}

// NewService creates a new backup service peer.
func NewService(log *zap.Logger, db DB, contract smartcontract.SocialShareHelper, config *Config) (*Service, error) {
	peer := &Service{
		Log: log,

		Servers:  lifecycle.NewGroup(log.Named("servers")),
		Services: lifecycle.NewGroup(log.Named("services")),

		db:       db,
		contract: contract,
		config:   config,
	}

	{ // setup debug
		var err error
		if config.Debug.Addr != "" {
			peer.Debug.Listener, err = net.Listen("tcp", config.Debug.Addr)
			if err != nil {
				withoutStack := errors.New(err.Error())
				peer.Log.Warn("failed to start debug endpoints", zap.Error(withoutStack))
			}
		}
		debugConfig := config.Debug
		debugConfig.ControlTitle = "Backup"
		peer.Debug.Server = debug.NewServerWithAtomicLevel(log.Named("debug"), peer.Debug.Listener, monkit.Default, debugConfig, nil)
		peer.Servers.Add(lifecycle.Item{
			Name:  "debug",
			Run:   peer.Debug.Server.Run,
			Close: peer.Debug.Server.Close,
		})
	}

	{ // setup version control
		peer.Log.Info("Version info",
			zap.Stringer("Version", version.Build.Version.Version),
			zap.String("Commit Hash", version.Build.CommitHash),
			zap.Stringer("Build Timestamp", version.Build.Timestamp),
			zap.Bool("Release Build", version.Build.Release),
		)
		peer.Version.Service = version_checker.NewService(log.Named("version"), config.Version, version.Build, "Satellite")
		peer.Version.Chore = version_checker.NewChore(peer.Version.Service, config.Version.CheckInterval)

		peer.Services.Add(lifecycle.Item{
			Name: "version",
			Run:  peer.Version.Chore.Run,
		})
	}

	{ // setup backup worker
		peer.Backup.Worker = NewWorker(log.Named("backup"), db, contract, *config)

		peer.Services.Add(lifecycle.Item{
			Name:  "backup",
			Run:   peer.Backup.Worker.Run,
			Close: peer.Backup.Worker.Close,
		})
	}

	return peer, nil
}

// Run runs the backup service.
func (peer *Service) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	group, ctx := errgroup.WithContext(ctx)

	pprof.Do(ctx, pprof.Labels("subsystem", "backup"), func(ctx context.Context) {
		peer.Servers.Run(ctx, group)
		peer.Services.Run(ctx, group)

		pprof.Do(ctx, pprof.Labels("name", "subsystem-wait"), func(ctx context.Context) {
			err = group.Wait()
		})
	})

	if err != nil {
		mon.Counter("backup_service_run_failures").Inc(1)
		return err
	}

	return err
}

// Close closes the backup service.
func (peer *Service) Close() error {
	err := errs.Combine(
		peer.Servers.Close(),
		peer.Services.Close(),
	)

	if err != nil {
		mon.Counter("backup_service_close_failures").Inc(1)
		return err
	}

	return nil
}
