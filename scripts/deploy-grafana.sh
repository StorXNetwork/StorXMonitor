#!/usr/bin/env bash

# StorX Grafana Dashboard Deployment Script
# Usage: ./scripts/deploy-grafana.sh [OPTIONS]

set -euo pipefail

# Configuration
COMPOSE_FILE="docker-compose.grafana.yml"

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "ERROR: Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        echo "ERROR: Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
}

# Check if required files exist
check_files() {
    local required_files=(
        "docker-compose.grafana.yml"
        "prometheus.yml"
        "grafana/provisioning/datasources/prometheus.yml"
        "grafana/provisioning/dashboards/dashboards.yml"
        "grafana/dashboards/storx-comprehensive-dashboard.json"
        "storx_exporter/storx_exporter.go"
        "storx_exporter/nodes.txt"
    )
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            echo "ERROR: Required file $file not found"
            exit 1
        fi
    done
}

# Create necessary directories
create_directories() {
    mkdir -p grafana/provisioning/datasources
    mkdir -p grafana/provisioning/dashboards
    mkdir -p grafana/dashboards
}

# Build StorX Exporter
build_exporter() {
    if [ ! -f "storx_exporter/storx_exporter" ]; then
        cd storx_exporter
        go build -o storx_exporter storx_exporter.go
        cd ..
    fi
}

# Test system health
test_system() {
    # Test Grafana
    if ! curl -s http://localhost:3000/api/health >/dev/null 2>&1; then
        echo "ERROR: Grafana is not responding"
        return 1
    fi
    
    # Test Prometheus
    if ! curl -s http://localhost:9090/-/healthy >/dev/null 2>&1; then
        echo "ERROR: Prometheus is not responding"
        return 1
    fi
    
    # Test StorX Exporter
    if ! curl -s http://localhost:9651/health >/dev/null 2>&1; then
        echo "ERROR: StorX Exporter is not responding"
        return 1
    fi
    
    return 0
}

# Deploy Grafana stack
deploy_grafana() {
    echo "Starting StorX monitoring stack..."
    
    docker-compose -f docker-compose.grafana.yml down 2>/dev/null || true
    docker-compose -f docker-compose.grafana.yml up -d --build
    sleep 15
    
    if test_system; then
        echo "StorX monitoring stack started successfully!"
        echo "Grafana: http://localhost:3000 (admin/storx123)"
    else
        echo "ERROR: System health check failed"
        exit 1
    fi
}

# Show usage information
show_usage() {
    echo "StorX Grafana Dashboard Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -d, --deploy   Deploy the StorX monitoring stack"
    echo "  -t, --test     Test system health"
    echo "  -s, --stop     Stop the monitoring stack"
    echo "  -r, --restart  Restart the monitoring stack"
    echo "  -l, --logs     Show logs"
    echo "  -c, --clean    Clean up containers and volumes"
    echo ""
    echo "Examples:"
    echo "  $0 --deploy    # Deploy monitoring stack"
    echo "  $0 --test      # Test system health"
    echo "  $0 --stop      # Stop monitoring stack"
    echo "  $0 --restart   # Restart monitoring stack"
    echo "  $0 --logs      # Show logs"
    echo "  $0 --clean     # Clean up everything"
}

# Stop StorX monitoring stack
stop_grafana() {
    echo "Stopping StorX monitoring stack..."
    docker-compose -f docker-compose.grafana.yml down
}

# Restart StorX monitoring stack
restart_grafana() {
    echo "Restarting StorX monitoring stack..."
    docker-compose -f docker-compose.grafana.yml restart
}

# Show logs
show_logs() {
    docker-compose -f docker-compose.grafana.yml logs -f
}

# Clean up
cleanup() {
    echo "This will remove all containers and volumes. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        docker-compose -f docker-compose.grafana.yml down -v
        docker system prune -f
    fi
}

# Main script logic
main() {
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -d|--deploy)
            check_docker
            check_files
            create_directories
            build_exporter
            deploy_grafana
            ;;
        -t|--test)
            test_system
            ;;
        -s|--stop)
            stop_grafana
            ;;
        -r|--restart)
            restart_grafana
            ;;
        -l|--logs)
            show_logs
            ;;
        -c|--clean)
            cleanup
            ;;
        "")
            # Default action: deploy
            check_docker
            check_files
            create_directories
            build_exporter
            deploy_grafana
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"