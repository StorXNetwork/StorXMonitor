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
	defer mon.Task()(&ctx)(&err)
	// Check if database connection string is properly configured
	if runCfg.Database == "" || runCfg.Database == "postgres://" {
		log.Error("Database connection string is not properly configured")
		return errs.New("Database connection string is not properly configured. Please set the --database flag or configure it in your config file.")
	}

	// Open database connections
	db, err := satellitedb.Open(ctx, log.Named("db"), runCfg.Database, satellitedb.Options{ApplicationName: "satellite-backup"})
	if err != nil {
		log.Error("Failed to connect to database", zap.Error(err), zap.String("database", runCfg.Database))
		mon.Counter("backup_cmd_database_connection_failed").Inc(1)
		return errs.New("Error starting master database: %+v", err)
	}
	defer func() {
		err = errs.Combine(err, db.Close())
	}()

	// Validate Web3Auth configuration
	if runCfg.Console.Web3AuthNetworkRPC == "" {
		log.Error("Web3AuthNetworkRPC is not configured")
		return errs.New("Web3AuthNetworkRPC is not configured. Please set the --console.web3auth-network-rpc flag or configure it in your config file.")
	}
	if runCfg.Console.Web3AuthContractAddress == "" {
		log.Error("Web3AuthContractAddress is not configured")
		return errs.New("Web3AuthContractAddress is not configured. Please set the --console.web3auth-contract-address flag or configure it in your config file.")
	}
	if runCfg.Console.Web3AuthAddress == "" {
		log.Error("Web3AuthAddress is not configured")
		return errs.New("Web3AuthAddress is not configured. Please set the --console.web3auth-address flag or configure it in your config file.")
	}
	if secretconstants.Web3AuthPrivateKey == "" {
		log.Error("Web3AuthPrivateKey is not set")
		return errs.New("Web3AuthPrivateKey is not set. This should be injected at build time.")
	}

	// Log Web3Auth configuration for debugging
	log.Info("Web3Auth configuration",
		zap.String("networkRPC", runCfg.Console.Web3AuthNetworkRPC),
		zap.String("contractAddress", runCfg.Console.Web3AuthContractAddress),
		zap.String("address", runCfg.Console.Web3AuthAddress),
		zap.Bool("privateKeySet", secretconstants.Web3AuthPrivateKey != ""),
	)

	// Create smart contract helper using console Web3Auth configuration
	smartContractConnector, err := smartcontract.NewKeyValueWeb3Helper(smartcontract.Web3Config{
		NetworkRPC:   runCfg.Console.Web3AuthNetworkRPC,
		ContractAddr: runCfg.Console.Web3AuthContractAddress,
		Address:      runCfg.Console.Web3AuthAddress,
	}, secretconstants.Web3AuthPrivateKey)
	if err != nil {
		log.Error("Failed to create smart contract connector", zap.Error(err))
		mon.Counter("backup_cmd_smart_contract_connector_failed").Inc(1)
		return errs.New("Failed to create smart contract connector: %+v", err)
	}

	// Create backup service with database adapter
	backupService, err := backup.NewService(
		log,
		db.Web3Auth(),
		smartContractConnector,
		&runCfg.Backup,
	)
	if err != nil {
		log.Error("Failed to create backup service", zap.Error(err))
		mon.Counter("backup_cmd_service_creation_failed").Inc(1)
		return err
	}

	// Record successful service creation
	mon.Counter("backup_cmd_service_created_successfully").Inc(1)

	// Initialize metrics
	if err := process.InitMetrics(ctx, log, monkit.Default, process.MetricsIDFromHostname(log), eventkitbq.BQDestination); err != nil {
		log.Warn("Failed to initialize telemetry batcher on backup service", zap.Error(err))
	}

	// Check database versions
	err = db.CheckVersion(ctx)
	if err != nil {
		log.Error("Failed satellite database version check.", zap.Error(err))
		mon.Counter("backup_cmd_database_version_check_failed").Inc(1)
		return errs.New("Error checking version for satellitedb: %+v", err)
	}

	// Run backup service
	runError := backupService.Run(ctx)
	closeError := backupService.Close()
	return errs2.IgnoreCanceled(errs.Combine(runError, closeError))
}
