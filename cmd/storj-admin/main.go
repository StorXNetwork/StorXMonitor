// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	_ "github.com/StorXNetwork/StorXMonitor/private/version" // This attaches version information during release builds.
	"github.com/StorXNetwork/common/cfgstruct"
	"github.com/StorXNetwork/common/fpath"
	"github.com/StorXNetwork/common/process"
)

var (
	rootCmd = &cobra.Command{
		Use:   "storxnetwork-admin",
		Short: "A tool for managing operations against a satellite",
	}
	setupCmd = &cobra.Command{
		Use:         "setup",
		Short:       "Create config files",
		RunE:        cmdSetup,
		Annotations: map[string]string{"type": "setup"},
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the storxnetwork-admin",
	}
	confDir string

	runCfg   AdminConf
	setupCfg AdminConf
)

// AdminConf defines necessary configuration to run the storxnetwork-admin UI.
type AdminConf struct {
	AuthKey     string `help:"API authorization key" default:""`
	Address     string `help:"address to start the web server on" default:":8080" testDefault:"$HOST:0"`
	EndpointURL string `help:"satellite admin endpoint" default:"localhost:7778" testDefault:"$HOST:0"`
}

func cmdSetup(cmd *cobra.Command, args []string) (err error) {
	setupDir, err := filepath.Abs(confDir)
	if err != nil {
		return err
	}

	valid, _ := fpath.IsValidSetupDir(setupDir)
	if !valid {
		return fmt.Errorf("satellite configuration already exists (%v)", setupDir)
	}

	err = os.MkdirAll(setupDir, 0700)
	if err != nil {
		return err
	}

	return process.SaveConfig(cmd, filepath.Join(setupDir, "config.yaml"))
}

func init() {
	defaultConfDir := fpath.ApplicationDir("storxnetwork", "storxnetwork-admin")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for satellite configuration")
	defaults := cfgstruct.DefaultsFlag(rootCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)
	process.Bind(runCmd, &runCfg, defaults, cfgstruct.ConfDir(confDir))
	process.Bind(setupCmd, &setupCfg, defaults, cfgstruct.ConfDir(confDir), cfgstruct.SetupMode())
}

func main() {
	logger, _, _ := process.NewLogger("storxnetwork-admin")
	zap.ReplaceGlobals(logger)

	process.Exec(rootCmd)
}
