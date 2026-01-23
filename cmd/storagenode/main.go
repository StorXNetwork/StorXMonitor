// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"os"

	"go.uber.org/zap"

	"storj.io/common/process"
	_ "github.com/StorXNetwork/StorXMonitor/private/version" // This attaches version information during release builds.
	"github.com/StorXNetwork/StorXMonitor/storagenode/pieces/lazyfilewalker"
)

func main() {
	logger, _, _ := process.NewLogger("storagenode")
	zap.ReplaceGlobals(logger.With(zap.String("Process", "storagenode")))

	process.SetHardcodedApplicationName("storagenode")

	allowDefaults := !isFilewalkerCommand()
	rootCmd, _ := newRootCmd(allowDefaults)

	if startAsService(rootCmd) {
		return
	}

	loggerFunc := func(logger *zap.Logger) *zap.Logger {
		return logger.With(zap.String("Process", rootCmd.Use))
	}

	process.ExecWithCustomOptions(rootCmd, process.ExecOptions{
		InitDefaultDebugServer: allowDefaults,
		InitTracing:            allowDefaults,
		InitProfiler:           allowDefaults,
		LoggerFactory:          loggerFunc,
		LoadConfig:             process.LoadConfig,
	})
}

func isFilewalkerCommand() bool {
	return len(os.Args) > 1 && (os.Args[1] == lazyfilewalker.UsedSpaceFilewalkerCmdName || os.Args[1] == lazyfilewalker.GCFilewalkerCmdName || os.Args[1] == lazyfilewalker.TrashCleanupFilewalkerCmdName)
}
