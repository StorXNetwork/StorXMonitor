// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"storj.io/common/cfgstruct"
	"storj.io/common/errs2"
	"storj.io/common/fpath"
	"storj.io/common/process"
	_ "storj.io/storj/private/version"
	"storj.io/storj/replication"
)

var (
	rootCmd = &cobra.Command{
		Use:   "replication",
		Short: "Replication service to sync database changes to Backuptools",
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the replication service",
		RunE:  cmdRun,
	}
	setupCmd = &cobra.Command{
		Use:         "setup",
		Short:       "Create config files",
		RunE:        cmdSetup,
		Annotations: map[string]string{"type": "setup"},
	}

	runCfg struct {
		Database    string `help:"satellite database connection string" releaseDefault:"postgres://" devDefault:"postgres://"`
		Replication replication.Config
	}
	setupCfg struct {
		Database    string `help:"satellite database connection string" releaseDefault:"postgres://" devDefault:"postgres://"`
		Replication replication.Config
	}

	confDir string
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "local-network", "replication")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for replication configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)
	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(setupCmd, &setupCfg, defaults, cfgstruct.ConfDir(confDir), cfgstruct.SetupMode())
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	ctx, _ := process.Ctx(cmd)
	log := zap.L()

	// Validate database connection
	if runCfg.Database == "" || runCfg.Database == "postgres://" {
		log.Error("Database connection string is not properly configured")
		return errs.New("Database connection string is not properly configured. Please set the --database flag or configure it in your config file.")
	}

	// Build replication config from binding config
	replicationConfig := runCfg.Replication

	// Load tables from YAML config file (for YAML config support, cfgstruct handles JSON flags)
	tables, err := loadTablesFromConfig(confDir)
	if err != nil {
		log.Warn("Failed to load tables from config, continuing without table-specific config", zap.Error(err))
	} else if len(tables) > 0 {
		// Only override if YAML has tables configured (don't override empty JSON flag)
		replicationConfig.Tables = replication.TableConfigs(tables)
	}

	// Use main database connection string for replication
	// Add replication=database parameter if not present
	if replicationConfig.SourceDB == "" {
		replicationConfig.SourceDB = runCfg.Database
		// Ensure replication parameter is set
		if !strings.Contains(replicationConfig.SourceDB, "replication=") {
			if strings.Contains(replicationConfig.SourceDB, "?") {
				replicationConfig.SourceDB += "&replication=database"
			} else {
				replicationConfig.SourceDB += "?replication=database"
			}
		}
	}

	// Validate public key path
	if replicationConfig.WebhookPublicKey == "" {
		log.Error("WebhookPublicKey is not configured")
		return errs.New("WebhookPublicKey is not configured. Please set the --replication.webhook-public-key flag or configure it in your config file.")
	}

	// Validate configuration (this will check webhook URLs)
	if err := replicationConfig.Validate(); err != nil {
		log.Error("Invalid replication configuration", zap.Error(err))
		return errs.New("Invalid replication configuration: %+v", err)
	}

	// Create replication service
	replicationService, err := replication.NewService(log.Named("replication"), replicationConfig)
	if err != nil {
		log.Error("Failed to create replication service", zap.Error(err))
		return errs.New("Failed to create replication service: %+v", err)
	}
	defer func() {
		err = errs.Combine(err, replicationService.Close())
	}()

	// Log configuration
	tableNames := replicationConfig.GetTableNames()
	log.Info("Starting replication service",
		zap.String("slot", replicationConfig.SlotName),
		zap.String("publication", replicationConfig.PublicationName),
		zap.String("default_webhook_url", replicationConfig.WebhookURL),
		zap.Strings("tables", tableNames),
		zap.Int("table_count", len(replicationConfig.Tables)),
	)

	// Run replication service
	runError := replicationService.Run(ctx)
	return errs2.IgnoreCanceled(runError)
}

func cmdSetup(cmd *cobra.Command, args []string) (err error) {
	setupDir, err := filepath.Abs(confDir)
	if err != nil {
		return err
	}

	valid, _ := fpath.IsValidSetupDir(setupDir)
	if !valid {
		return errs.New("replication configuration already exists (%v)", setupDir)
	}

	return process.SaveConfig(cmd, filepath.Join(setupDir, "config.yaml"))
}

// loadTablesFromConfig loads table configurations from the YAML config file.
func loadTablesFromConfig(confDir string) ([]replication.TableConfig, error) {
	configPath := filepath.Join(confDir, "config.yaml")

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil // No config file, return empty slice
	}

	// Read YAML file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	// Parse YAML
	var yamlConfig struct {
		Replication struct {
			Tables []replication.TableConfig `yaml:"tables"`
		} `yaml:"replication"`
	}

	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil, errs.Wrap(err)
	}

	return yamlConfig.Replication.Tables, nil
}

func main() {
	logger, _, _ := process.NewLogger("replication")
	zap.ReplaceGlobals(logger)

	process.ExecCustomDebug(rootCmd)
}
