package main

import (
	"context"
	"fmt"
	"log"

	"storj.io/storj/satellite/smartcontract"
)

func main() {
	ctx := context.Background()

	// Use the same configuration as the backup service
	config := smartcontract.Web3Config{
		NetworkRPC:   "https://erpc.xinfin.network",
		ContractAddr: "",
		Address:      "",
	}
	privateKey := ""

	fmt.Println("Testing smart contract connection...")
	fmt.Printf("Network RPC: %s\n", config.NetworkRPC)
	fmt.Printf("Contract Address: %s\n", config.ContractAddr)
	fmt.Printf("Caller Address: %s\n", config.Address)

	// Test basic web3 helper connection
	fmt.Println("\n1. Testing basic web3 helper connection...")
	web3Helper, err := smartcontract.NewWeb3Helper(config, privateKey)
	if err != nil {
		log.Fatalf("Failed to create web3 helper: %v", err)
	}
	fmt.Println("✓ Web3 helper created successfully")

	// Test key-value web3 helper
	fmt.Println("\n2. Testing key-value web3 helper...")
	keyValueHelper, err := smartcontract.NewKeyValueWeb3Helper(config, privateKey)
	if err != nil {
		log.Fatalf("Failed to create key-value web3 helper: %v", err)
	}
	fmt.Println("✓ Key-value web3 helper created successfully")

	// Test GetTotalKeys method
	fmt.Println("\n3. Testing GetTotalKeys method...")
	totalKeys, err := keyValueHelper.GetTotalKeys(ctx)
	if err != nil {
		fmt.Printf("✗ GetTotalKeys failed: %v\n", err)

		// Try to get more details about the error
		fmt.Println("\n4. Testing contract method directly...")
		var total uint64
		err2 := web3Helper.GetMethodCallData(ctx, "getTotalKeys", &total)
		if err2 != nil {
			fmt.Printf("✗ Direct method call failed: %v\n", err2)
		} else {
			fmt.Printf("✓ Direct method call succeeded: total = %d\n", total)
		}
	} else {
		fmt.Printf("✓ GetTotalKeys succeeded: total = %d\n", totalKeys)
	}

	// Test GetPaginatedKeyValues method
	fmt.Println("\n5. Testing GetPaginatedKeyValues method...")
	keys, values, versions, err := keyValueHelper.GetPaginatedKeyValues(ctx, 1, 30)
	if err != nil {
		fmt.Printf("✗ GetPaginatedKeyValues failed: %v\n", err)
	} else {
		fmt.Printf("✓ GetPaginatedKeyValues succeeded: %d keys\n", len(keys))
		for i := 0; i < len(keys); i++ {
			fmt.Printf("  Key %d: %s = %s (version: %s)\n", i, keys[i], values[i], versions[i])
		}
	}

	fmt.Println("\nTest completed.")
}
