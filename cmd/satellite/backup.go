// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/errs2"
	"storj.io/common/process"
	"storj.io/common/process/eventkitbq"
	"storj.io/storj/satellite/backup"
	"storj.io/storj/satellite/console/secretconstants"
	"storj.io/storj/satellite/satellitedb"
	"storj.io/storj/satellite/smartcontract"
)

var mon = monkit.Package()

func cmdBackupRun(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)
	log := zap.L()

	// Load identity
	identity, err := runCfg.Identity.Load()
	if err != nil {
		log.Error("Failed to load identity.", zap.Error(err))
		return errs.New("Failed to load identity: %+v", err)
	}

	// Open database connections
	db, err := satellitedb.Open(ctx, log.Named("db"), runCfg.Database, satellitedb.Options{ApplicationName: "satellite-backup"})
	if err != nil {
		return errs.New("Error starting master database: %+v", err)
	}
	defer func() {
		err = errs.Combine(err, db.Close())
	}()

	// Create smart contract helper
	smartContractConnector, err := smartcontract.NewKeyValueWeb3Helper(smartcontract.Web3Config{
		NetworkRPC:   runCfg.Audit.SmartContractNetworkRPC,
		ContractAddr: runCfg.Audit.SmartContractReputationContractAddr,
		Address:      runCfg.Audit.SmartContractNounceAddr,
	}, secretconstants.Web3AuthPrivateKey)
	if err != nil {
		return errs.New("Failed to create smart contract connector: %+v", err)
	}

	// Create backup service with database adapter
	backupService, err := backup.NewService(
		log,
		identity,
		db.Web3Auth(),
		smartContractConnector,
		&runCfg.Backup,
	)
	if err != nil {
		return err
	}

	// Initialize metrics
	if err := process.InitMetrics(ctx, log, monkit.Default, process.MetricsIDFromHostname(log), eventkitbq.BQDestination); err != nil {
		log.Warn("Failed to initialize telemetry batcher on backup service", zap.Error(err))
	}

	// Check database versions
	err = db.CheckVersion(ctx)
	if err != nil {
		log.Error("Failed satellite database version check.", zap.Error(err))
		return errs.New("Error checking version for satellitedb: %+v", err)
	}

	// Run backup service
	runError := backupService.Run(ctx)
	closeError := backupService.Close()
	return errs2.IgnoreCanceled(errs.Combine(runError, closeError))
}
