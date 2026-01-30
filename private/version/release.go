// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package version

import _ "unsafe" // needed for go:linkname

//go:linkname buildTimestamp github.com/StorXNetwork/common/version.buildTimestamp
var buildTimestamp string

//go:linkname buildCommitHash github.com/StorXNetwork/common/version.buildCommitHash
var buildCommitHash string

//go:linkname buildVersion github.com/StorXNetwork/common/version.buildVersion
var buildVersion string

//go:linkname buildRelease github.com/StorXNetwork/common/version.buildRelease
var buildRelease string

// ensure that linter understands that the variables are being used.
func init() { use(buildTimestamp, buildCommitHash, buildVersion, buildRelease) }

func use(...interface{}) {}
