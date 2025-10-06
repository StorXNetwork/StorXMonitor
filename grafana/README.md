# StorX Grafana Monitoring Dashboards

This directory contains Grafana dashboard configurations for monitoring the StorX distributed storage network. The dashboards are designed to provide comprehensive visibility into satellite operations and system health.

## 📊 Available Dashboards

### Satellite Monitoring Dashboard
- **File**: `dashboards/satellite-dashboard.json`
- **Purpose**: Detailed satellite-specific metrics and operations
- **Key Metrics**:
  - Function execution rates and performance
  - Function metrics and timing
  - Status code monitoring
  - Time to run functions
  - Database operations
  - API performance

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- StorX satellite running with metrics enabled on port 10009

### Deployment

1. **Deploy the monitoring stack**:
   ```bash
   sudo ./scripts/deploy-grafana.sh
   ```

2. **Access the dashboards**:
   - Grafana: http://localhost:3000
   - Prometheus: http://localhost:9090

3. **Default credentials**:
   - Username: `admin`
   - Password: `storx123`

### Manual Deployment

If you prefer to deploy manually:

```bash
# Start the monitoring stack
sudo docker-compose -f docker-compose.grafana.yml up -d

# Check status
sudo docker-compose -f docker-compose.grafana.yml ps

# View logs
sudo docker-compose -f docker-compose.grafana.yml logs -f
```

## 🔧 Configuration

### Prometheus Configuration

The Prometheus configuration is located in `prometheus.yml` and includes:

- **Scrape targets**: Satellite core metrics (port 10009)
- **Scrape interval**: 30 seconds for satellite metrics
- **Retention**: 200 hours
- **External labels**: Cluster and environment identification
- **Network mode**: Host networking for direct access to localhost

### Grafana Provisioning

The provisioning configuration automatically:

- **Data sources**: Configures Prometheus as the default data source (localhost:9090)
- **Dashboards**: Loads all dashboard JSON files from the dashboards directory
- **Auto-updates**: Refreshes dashboard configurations every 10 seconds
- **Network mode**: Host networking for direct access to Prometheus

### Customizing Dashboards

To modify dashboards:

1. **Edit JSON files**: Modify the dashboard JSON files in `dashboards/`
2. **Restart Grafana**: The changes will be automatically picked up
3. **Export from UI**: Use Grafana's export feature to save changes back to JSON

## 📈 Metrics and Queries

### Key Metric Patterns

The dashboards use the following metric naming conventions:

- `function_times`: Function execution timing metrics
- `function`: Function execution counters and status
- `db_stats`: Database connection statistics
- `memory`: Memory usage metrics
- `cpu`: CPU usage metrics

### Example Queries

```promql
# Function execution rate
sum(rate(function_times[5m])) by (scope, name)

# Function success rate
sum(function{field="successes"}) by (scope, name)

# Function error rate
sum(function{field="errors"}) by (scope, name)

# Database connections
db_stats{field="OpenConnections"}
```

## 🛠️ Management Commands

The deployment script provides several management options:

```bash
# Deploy the stack
sudo ./scripts/deploy-grafana.sh

# Stop the stack
sudo ./scripts/deploy-grafana.sh --stop

# Restart the stack
sudo ./scripts/deploy-grafana.sh --restart

# View logs
sudo ./scripts/deploy-grafana.sh --logs

# Clean up everything
sudo ./scripts/deploy-grafana.sh --clean

# Show help
./scripts/deploy-grafana.sh --help
```

## 🔍 Troubleshooting

### Common Issues

1. **Dashboards not loading**:
   - Check if Prometheus is running and accessible
   - Verify data source configuration
   - Check Grafana logs for errors

2. **No data in dashboards**:
   - Ensure StorX satellite is running with metrics enabled on port 10009
   - Verify Prometheus is scraping the correct endpoints
   - Check if metrics are being exposed: `curl http://127.0.0.1:10009/metrics`

3. **Connection refused errors**:
   - Verify all services are running: `sudo docker-compose -f docker-compose.grafana.yml ps`
   - Check port conflicts (3000, 9090)
   - Review service logs

### Logs and Debugging

```bash
# View all logs
sudo docker-compose -f docker-compose.grafana.yml logs

# View specific service logs
sudo docker-compose -f docker-compose.grafana.yml logs grafana
sudo docker-compose -f docker-compose.grafana.yml logs prometheus

# Follow logs in real-time
sudo docker-compose -f docker-compose.grafana.yml logs -f

# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Test metrics endpoint
curl http://127.0.0.1:10009/metrics | head -10
```

## 📝 Adding New Dashboards

To add a new dashboard:

1. **Create JSON file**: Add your dashboard JSON to `dashboards/`
2. **Follow naming convention**: Use descriptive names like `custom-dashboard.json`
3. **Include metadata**: Ensure the JSON includes proper title, UID, and tags
4. **Restart services**: The new dashboard will be automatically loaded

### Dashboard JSON Structure

```json
{
  "title": "Dashboard Title",
  "uid": "unique-dashboard-id",
  "tags": ["storx", "monitoring"],
  "panels": [...],
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "refresh": "30s"
}
```

## 🔐 Security Considerations

- **Change default passwords**: Update admin credentials in production
- **Network security**: Consider using reverse proxy for external access
- **Data retention**: Configure appropriate retention policies
- **Access control**: Implement proper user roles and permissions

## 📚 Additional Resources

- [Grafana Documentation](https://grafana.com/docs/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [StorX Documentation](https://docs.storj.io/)
- [Docker Compose Reference](https://docs.docker.com/compose/)

## 🤝 Contributing

To contribute to the monitoring dashboards:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This monitoring configuration is part of the StorX project and follows the same licensing terms.
