package smartcontract

import (
	"context"
	"embed"
	"os"
	"testing"
)

// go:embed *.abi
var abiFile embed.FS

func Test_Web3API(t *testing.T) {
	var (
		testNodeAddress        = "0x0bda050d6d856a3134478de5cd75dc8ec24ab082"
		networkRPC             = "https://erpc.xinfin.network" // Updated with proper URL
		reputationContractAddr = "0x5DB64839828174D2D29B419E5581C16C67D62046"
		nounceAddr             = "0xe50d5fc9bcbce037a19c860ba4105548d42517a0"                       // Replace this with the address of the account that will be used to send the transaction
		privateKey             = "1637a3827950e2b50b45a427d826cf4a36f099a42b825afeefb83ee99e0ee0e6" // Replace this with the private key
	)

	h, err := NewWeb3Helper(Web3Config{
		NetworkRPC:             networkRPC,
		ReputationContractAddr: reputationContractAddr,
		NounceAddr:             nounceAddr,
		PrivateKey:             privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open("contract.abi")
	if err != nil {
		t.Fatal(err)
	}
	h.SetABI(f)

	v, err := h.IsStaker(context.Background(), testNodeAddress)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("expected true")
	}

	v, err = h.IsStaker(context.Background(), "0x0bda050d6d856a3134478de5cd75dc8ec24ab081")
	if err != nil {
		t.Fatal(err)
	}
	if v {
		t.Fatal("expected true")
	}

	// err = h.AddStaker(testNodeAddress, 100)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// err = h.SetReputation(testNodeAddress, 50)
	// if err != nil {
	// 	t.Fatal(err)
	// }
}
