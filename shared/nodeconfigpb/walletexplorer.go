// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package nodeconfigpb

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/zeebo/errs"
)

// WalletAddressPlaceholder is replaced with the operator wallet address in a wallet explorer URL template.
const WalletAddressPlaceholder = "{{WALLET_ADDRESS}}"

// Error is the error class for node configuration templates.
var Error = errs.Class("nodeconfig")

var walletAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// ValidateWalletExplorerURLTemplate checks that a non-empty template is an https URL containing
// WalletAddressPlaceholder. An empty template is valid and means no template is configured.
func ValidateWalletExplorerURLTemplate(template string) error {
	if template == "" {
		return nil
	}
	if !strings.Contains(template, WalletAddressPlaceholder) {
		return Error.New("wallet explorer URL template %q must contain %s", template, WalletAddressPlaceholder)
	}
	u, err := url.Parse(strings.ReplaceAll(template, WalletAddressPlaceholder, "0x0000000000000000000000000000000000000000"))
	if err != nil {
		return Error.New("wallet explorer URL template %q is not a valid URL: %v", template, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return Error.New("wallet explorer URL template %q must be an absolute https URL", template)
	}
	return nil
}

// NormalizeWalletAddress converts an XDC-prefixed wallet address to the 0x form and returns
// an empty string when the result is not a 20-byte hex address.
func NormalizeWalletAddress(wallet string) string {
	wallet = strings.TrimSpace(wallet)
	if len(wallet) > 3 && strings.EqualFold(wallet[:3], "xdc") {
		wallet = "0x" + wallet[3:]
	}
	if !walletAddressPattern.MatchString(wallet) {
		return ""
	}
	return wallet
}

// RenderWalletExplorerURL fills the template with the wallet address. It returns an empty string
// when the template is empty or invalid, or the wallet is not a valid address.
func RenderWalletExplorerURL(template, wallet string) string {
	if template == "" || ValidateWalletExplorerURLTemplate(template) != nil {
		return ""
	}
	wallet = NormalizeWalletAddress(wallet)
	if wallet == "" {
		return ""
	}
	return strings.ReplaceAll(template, WalletAddressPlaceholder, wallet)
}
