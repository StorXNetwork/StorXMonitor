// Copyright (C) 2026 StorX Labs, Inc.
// See LICENSE for copying information.

// Package mailtemplates holds embedded console email HTML templates.
// On disk the same files live in this directory under emails/.
package mailtemplates

import "embed"

// RootDir is the fixed on-disk directory name at the repository root.
const RootDir = "mail-templates"

// EmailsDir is the fixed subdirectory containing *.html templates.
const EmailsDir = "emails"

// FS contains all embedded email templates (Forgot.html, Welcome.html, etc.).
//
//go:embed emails/*.html
var FS embed.FS
