# StorX Orchestrator

A comprehensive service orchestration tool for managing StorX (Storj) network components in development environments. This tool automates the startup, configuration, and management of multiple StorX services including the satellite network, authentication service, gateway, and link sharing service.

> **⚠️ IMPORTANT**: To stop all services, simply press **Ctrl+C** in the terminal where the orchestrator is running.

## Quick Start

```bash
# Run all services
go run main.go all

# Run specific services (comma-separated)
go run main.go authservice,gateway

# Run only authentication service
go run main.go authservice

# Run only gateway and link sharing
go run main.go gateway,link-share

# Stop all services: Press Ctrl+C
```

## Features

- **Automated Service Management**: Start and stop multiple StorX services with a single command
- **Dynamic Configuration**: Automatically fetches satellite URLs and configures services
- **Graceful Shutdown**: Properly terminates all services on interruption
- **Error Handling**: Comprehensive error handling with detailed logging
- **Flexible Service Selection**: Choose which services to run via command line arguments

## Services Managed

### Core Services
- **storj-sim**: Storj simulation network (always started)
- **authservice**: Authentication and authorization service
- **gateway-mt**: Multi-tenant gateway service
- **linksharing**: Link sharing service for public access

### Service Ports
- **storj-sim**: Various ports (managed by storj-sim)
- **authservice**: `:8000`
- **gateway-mt**: `localhost:8002`
- **linksharing**: `:8001`

## Usage

> **🛑 STOP SERVICES**: Press **Ctrl+C** to stop all running services and clean up processes.

### Prerequisites

Ensure you have the following StorX tools installed and available in your PATH:
- `storj-sim`
- `authservice`
- `gateway-mt`
- `linksharing`


### Available Service Options

- `authservice` - Authentication and authorization service
- `gateway` - Multi-tenant gateway service
- `link-share` - Link sharing service
- `all` - All services (equivalent to `authservice,gateway,link-share`)

## Configuration

The tool uses the following default configuration:

```go
// Authentication
authToken    = "my-test-auth-token"
authEndpoint = "http://localhost:8002"
listenAddr   = ":8000"
kvBackend    = "badger://"

// Gateway
domainName = "localhost"
serverAddr = "localhost:8002"

// Link Sharing
linkShareURL  = "http://localhost:8001"
linkShareAddr = ":8001"
```

## How It Works

1. **Network Setup**: Always starts the `storj-sim` network first
2. **Satellite Discovery**: If authservice is requested, fetches the `SATELLITE_0_URL` from storj-sim
3. **Service Startup**: Starts requested services in sequence with proper configuration
4. **Link Sharing Setup**: For link sharing, runs setup command first, then starts the service
5. **Signal Handling**: Listens for interrupt signals (Ctrl+C) to gracefully shutdown all services

## Error Handling

- **Service Startup Failures**: Logs detailed error messages and exits
- **Configuration Errors**: Handles missing satellite URLs and configuration issues
- **Graceful Shutdown**: Properly terminates all running processes on interruption
- **Link Sharing Setup**: Handles existing configuration gracefully

## Development

### Building

```bash
# Build the binary
go build -o storx-orchestrator main.go

# Run the binary
./storx-orchestrator all
```

### Logging

The tool provides comprehensive logging with emoji indicators:
- ✅ Success messages
- ❌ Error messages
- ⚠️ Warning messages
- ℹ️ Information messages
- ▶ Action messages

## Troubleshooting

### Common Issues

1. **Service Not Found**: Ensure all required StorX tools are installed and in PATH
2. **Port Conflicts**: Check if ports 8000, 8001, 8002 are available
3. **Permission Issues**: Ensure you have permission to start network services
4. **Configuration Errors**: Verify satellite URL is properly fetched

### Debug Mode

For detailed debugging, you can modify the code to add more verbose logging or run individual services manually to isolate issues.

## License

This tool is part of the StorX Monitor project and follows the same license terms.
