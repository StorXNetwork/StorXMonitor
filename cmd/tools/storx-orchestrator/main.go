package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// =============================================================================
// COMMANDS - All necessary commands for StorX services
// =============================================================================
var (
	// Core Commands
	storjSimCmd    = []string{"storj-sim", "network", "run", "--no-gateways"}
	storjSimEnvCmd = []string{"storj-sim", "network", "env", "SATELLITE_0_URL"}
	authServiceCmd = "authservice"
	gatewayMTCmd   = "gateway-mt"
	linkShareCmd   = "linksharing"

	// Service Configurations
	authToken    = "my-test-auth-token"
	authEndpoint = "http://localhost:8002"
	listenAddr   = ":8000"
	kvBackend    = "badger://"

	domainName = "localhost"
	serverAddr = "localhost:8002"

	linkShareURL  = "http://localhost:8001"
	linkShareAddr = ":8001"
)

func main() {
	// =============================================================================
	// STORX ORCHESTRATOR - Service Management Tool
	// =============================================================================
	// To stop all services: Press Ctrl+C
	// =============================================================================

	// Parse CLI input (authservice,gateway,link-share)
	var services []string
	if len(os.Args) >= 2 {
		arg := strings.ToLower(os.Args[1])
		if arg == "all" {
			services = []string{"authservice", "gateway", "link-share"}
		} else {
			services = strings.Split(arg, ",")
		}
	}

	// Always run storj-sim
	fmt.Printf("▶ Running: %s\n", strings.Join(storjSimCmd, " "))
	simCmd := exec.Command(storjSimCmd[0], storjSimCmd[1:]...)
	if err := simCmd.Start(); err != nil {
		log.Fatalf("❌ Failed to start storj-sim network: %v", err)
	}
	log.Println("✅ storj-sim network started successfully")

	// Fetch SATELLITE_0_URL only if authservice is requested
	var satelliteURL string
	if contains(services, "authservice") {
		fmt.Printf("▶ Running: %s\n", strings.Join(storjSimEnvCmd, " "))
		out, err := exec.Command(storjSimEnvCmd[0], storjSimEnvCmd[1:]...).Output()
		if err != nil {
			log.Fatalf("❌ Failed to get SATELLITE_0_URL: %v", err)
		}
		satelliteURL = strings.TrimSpace(string(out))
		log.Printf("✅ Got SATELLITE_0_URL: %s\n", satelliteURL)
	}

	// Start services as requested
	var authCmd, gatewayCmd, linkshareCmd *exec.Cmd

	if contains(services, "authservice") {
		authArgs := []string{
			"run",
			"--allowed-satellites", satelliteURL,
			"--auth-token", authToken,
			"--endpoint", authEndpoint,
			"--listen-addr", listenAddr,
			"--kv-backend", kvBackend,
		}
		fmt.Printf("▶ Running: %s %s\n", authServiceCmd, strings.Join(authArgs, " "))
		authCmd = exec.Command(authServiceCmd, authArgs...)
		if err := authCmd.Start(); err != nil {
			log.Fatalf("❌ Failed to start authservice: %v", err)
		}
		log.Printf("✅ authservice started successfully with --allowed-satellites %s", satelliteURL)
	}

	if contains(services, "gateway") {
		gatewayArgs := []string{
			"run",
			"--auth.token", authToken,
			"--auth.base-url", "http://localhost:8000",
			"--domain-name", domainName,
			"--server.address", serverAddr,
			"--insecure-disable-tls",
		}
		fmt.Printf("▶ Running: %s %s\n", gatewayMTCmd, strings.Join(gatewayArgs, " "))
		gatewayCmd = exec.Command(gatewayMTCmd, gatewayArgs...)
		if err := gatewayCmd.Start(); err != nil {
			log.Fatalf("❌ Failed to start gateway-mt: %v", err)
		}
		log.Println("✅ gateway-mt started successfully")
	}

	if contains(services, "link-share") {
		setupArgs := []string{
			"setup",
			"--defaults", "dev",
			"--public-url", linkShareURL,
			"--address", linkShareAddr,
			"--auth-service.base-url", "http://localhost:8000",
			"--auth-service.token", authToken,
		}
		fmt.Printf("▶ Running: %s %s\n", linkShareCmd, strings.Join(setupArgs, " "))

		setupCmd := exec.Command(linkShareCmd, setupArgs...)
		setupCmd.Stdout = os.Stdout

		// Capture stderr to inspect error messages
		var stderr strings.Builder
		setupCmd.Stderr = &stderr

		err := setupCmd.Run()
		if err != nil {
			errOutput := stderr.String()
			if strings.Contains(errOutput, "link sharing configuration already exists") {
				log.Println("ℹ️ linksharing setup skipped: configuration already exists")
			} else {
				log.Fatalf("❌ Failed to setup linksharing: %v\nStderr: %s", err, errOutput)
			}
		} else {
			log.Println("✅ linksharing setup completed successfully")
		}

		// Step 2: Run
		runArgs := []string{"run"}
		fmt.Printf("▶ Running: %s %s\n", linkShareCmd, strings.Join(runArgs, " "))
		linkshareCmd = exec.Command(linkShareCmd, runArgs...)
		if err := linkshareCmd.Start(); err != nil {
			log.Fatalf("❌ Failed to start linksharing: %v", err)
		}
		log.Println("✅ linksharing service started")
	}

	// Wait for Ctrl+C
	log.Println("🚀 All components started. Press Ctrl+C to stop and clean up.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Println("🛑 Interrupt received. Cleaning up...")

	cleanupProcess(simCmd, "storj-sim")
	cleanupProcess(authCmd, "authservice")
	cleanupProcess(gatewayCmd, "gateway-mt")
	cleanupProcess(linkshareCmd, "linksharing")

	log.Println("✅ All processes terminated.")
}

func cleanupProcess(cmd *exec.Cmd, name string) {
	if cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("⚠️  Failed to kill %s: %v", name, err)
		} else {
			log.Printf("✅ %s terminated", name)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == item {
			return true
		}
	}
	return false
}
