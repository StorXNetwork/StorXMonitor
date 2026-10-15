// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package nodeconfigpb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/shared/nodeconfigpb"
)

func TestValidateWalletExplorerURLTemplate(t *testing.T) {
	for _, tt := range []struct {
		template string
		valid    bool
	}{
		{"", true},
		{"https://xdcscan.com/address/{{WALLET_ADDRESS}}", true},
		{"https://xdcscan.com/address/{{WALLET_ADDRESS}}#tokentxns", true},
		{"https://xdcscan.com/address/", false},
		{"http://xdcscan.com/address/{{WALLET_ADDRESS}}", false},
		{"javascript:alert(1)//{{WALLET_ADDRESS}}", false},
		{"/address/{{WALLET_ADDRESS}}", false},
	} {
		err := nodeconfigpb.ValidateWalletExplorerURLTemplate(tt.template)
		if tt.valid {
			require.NoError(t, err, tt.template)
		} else {
			require.Error(t, err, tt.template)
		}
	}
}

func TestRenderWalletExplorerURL(t *testing.T) {
	const template = "https://xdcscan.com/address/{{WALLET_ADDRESS}}"
	const wallet = "0x0b9a3572E8aE2a166967B5830AC6c84E33390C91"

	require.Equal(t, "https://xdcscan.com/address/"+wallet, nodeconfigpb.RenderWalletExplorerURL(template, wallet))
	require.Equal(t, "https://xdcscan.com/address/"+wallet, nodeconfigpb.RenderWalletExplorerURL(template, "xdc0b9a3572E8aE2a166967B5830AC6c84E33390C91"))
	require.Equal(t, "https://xdcscan.com/address/"+wallet, nodeconfigpb.RenderWalletExplorerURL(template, " "+wallet+" "))

	require.Empty(t, nodeconfigpb.RenderWalletExplorerURL("", wallet))
	require.Empty(t, nodeconfigpb.RenderWalletExplorerURL("http://xdcscan.com/{{WALLET_ADDRESS}}", wallet))
	require.Empty(t, nodeconfigpb.RenderWalletExplorerURL(template, ""))
	require.Empty(t, nodeconfigpb.RenderWalletExplorerURL(template, "0x123"))
	require.Empty(t, nodeconfigpb.RenderWalletExplorerURL(template, "0x0b9a3572E8aE2a166967B5830AC6c84E33390C91/../evil"))
}
