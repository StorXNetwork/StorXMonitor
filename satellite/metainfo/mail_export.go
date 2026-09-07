// Copyright (C) 2026 StorXNetwork Labs, Inc.
// See LICENSE for copying information.

package metainfo

import (
	"strings"

	"github.com/StorXNetwork/common/useragent"
)

const defaultMailExportInternalUserAgent = "StorX-MailExport"

// useInternalGetDownload reports whether this download should use GET_INTERNAL
// (skip live + settled user bandwidth). Satellite alone decides after verifying:
// flag on, trusted uplink identity, and mail-export worker user-agent product.
// Clients never choose the piece action.
func (endpoint *Endpoint) useInternalGetDownload(trustedUplink bool, rawUserAgent []byte) bool {
	cfg := endpoint.config.MailExport
	if !cfg.NonBillableBuildDownloads {
		return false
	}
	if !trustedUplink {
		return false
	}
	product := cfg.InternalDownloadUserAgent
	if product == "" {
		product = defaultMailExportInternalUserAgent
	}
	return userAgentHasProduct(rawUserAgent, product)
}

func userAgentHasProduct(rawUserAgent []byte, product string) bool {
	if len(rawUserAgent) == 0 || product == "" {
		return false
	}
	entries, err := useragent.ParseEntries(rawUserAgent)
	if err != nil {
		// Fall back to substring match for slightly malformed agents that still
		// carry the product token (e.g. appended uplink version quirks).
		return strings.Contains(string(rawUserAgent), product)
	}
	for _, entry := range entries {
		if entry.Product == product {
			return true
		}
	}
	return false
}
