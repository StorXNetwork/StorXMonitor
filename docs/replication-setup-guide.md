# Replication Service Setup Guide

Complete guide to set up the replication service on a new PC/server.

---

## 📋 Prerequisites

### 1. **Go Language** (v1.21 or higher)
```bash
# Check if Go is installed
go version

# If not installed, download from: https://golang.org/dl/
```

### 2. **PostgreSQL** (v12 or higher)
```bash
# Check PostgreSQL version
psql --version

# PostgreSQL must have:
# - Logical replication enabled (wal_level = logical)
# - Replication privileges for the database user
```

### 3. **RSA Public Key**
- You need the RSA public key file (`.pem`) for webhook encryption
- This should be provided by Backup-Tools team

---

## 🚀 Step-by-Step Setup

### Step 1: Clone/Transfer the Code

```bash
# Option A: If using Git
git clone <repository-url>
cd StorXMonitor

# Option B: If transferring files
# Copy the entire StorXMonitor directory to the new PC
```

### Step 2: Build the Service

```bash
# Navigate to project root
cd /path/to/StorXMonitor

# Build the replication service
go build -o replication-service ./cmd/replication

# Verify build
./replication-service --help
```

### Step 3: Generate RSA Key Pair (if needed)

If you need to generate a new key pair:

```bash
# Generate private key
openssl genrsa -out webhook_private_key.pem 2048

# Generate public key
openssl rsa -in webhook_private_key.pem -pubout -out webhook_public_key.pem

# Keep private key secure (Backup-Tools needs it)
# Use public key for replication service
```

### Step 4: Configure PostgreSQL

#### 4.1 Enable Logical Replication

Edit PostgreSQL config (`postgresql.conf`):

```conf
wal_level = logical
max_replication_slots = 10
max_wal_senders = 10
```

#### 4.2 Restart PostgreSQL

```bash
# Linux (systemd)
sudo systemctl restart postgresql

# Or manually
sudo -u postgres pg_ctl restart -D /var/lib/postgresql/data
```

#### 4.3 Grant Replication Privileges

```sql
-- Connect to PostgreSQL
psql -U postgres -d your_database

-- Grant replication privileges
ALTER USER your_user REPLICATION;

-- Or create a dedicated replication user
CREATE USER replication_user WITH REPLICATION PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE your_database TO replication_user;
```

### Step 5: Create Configuration

#### Option A: Using Setup Command (Recommended)

```bash
# Create config directory and files
./replication-service setup --config-dir /etc/storj/replication

# This creates: /etc/storj/replication/config.yaml
```

#### Option B: Manual Configuration

Create config file: `/etc/storj/replication/config.yaml`

```yaml
database: "postgresql://user:password@localhost:5432/storj_satellite_db?sslmode=disable"

replication:
  source-db: "postgresql://user:password@localhost:5432/storj_satellite_db?sslmode=disable"
  slot-name: "backuptools_slot"
  publication-name: "backuptools_pub"
  
  webhook-url: "https://backup-tools.example.com/api/webhook"
  webhook-public-key: "/etc/storj/replication/webhook_public_key.pem"
  
  max-retries: 3
  retry-delay: 5s
  status-update-interval: 10s
  webhook-timeout: 30s
  
  worker-pool-size: 10
  event-channel-buffer: 1000
  
  tables:
    - table: "objects"
      events: ["INSERT", "UPDATE", "DELETE"]
      webhook-url: ""  # Uses default if empty
    - table: "segments"
      events: ["INSERT", "DELETE"]
      webhook-url: ""  # Uses default if empty
```

### Step 6: Set Permissions

```bash
# Make service executable
chmod +x replication-service

# Set config file permissions (readable by service user)
chmod 600 /etc/storj/replication/config.yaml
chmod 644 /etc/storj/replication/webhook_public_key.pem

# Create service user (optional, recommended)
sudo useradd -r -s /bin/false storj-replication
sudo chown -R storj-replication:storj-replication /etc/storj/replication
```

### Step 7: Test the Service

```bash
# Test with verbose output
./replication-service run \
  --config-dir /etc/storj/replication \
  --database "postgresql://user:password@localhost:5432/storj_satellite_db" \
  --replication.webhook-url "https://backup-tools.example.com/api/webhook" \
  --replication.webhook-public-key "/etc/storj/replication/webhook_public_key.pem"

# Check logs for:
# - "created replication slot" or "replication slot already exists"
# - "created publication" or "publication already exists"
# - "replication started successfully"
```

### Step 8: Create Systemd Service (Linux)

Create `/etc/systemd/system/storj-replication.service`:

```ini
[Unit]
Description=Storj Replication Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=storj-replication
Group=storj-replication
WorkingDirectory=/opt/storj/replication
ExecStart=/opt/storj/replication/replication-service run --config-dir /etc/storj/replication
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable storj-replication

# Start service
sudo systemctl start storj-replication

# Check status
sudo systemctl status storj-replication

# View logs
sudo journalctl -u storj-replication -f
```

---

## 🔧 Configuration Reference

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `database` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `replication.webhook-url` | Backup-Tools webhook endpoint | `https://backup-tools.example.com/api/webhook` |
| `replication.webhook-public-key` | Path to RSA public key | `/etc/storj/replication/webhook_public_key.pem` |

### Optional Parameters (with defaults)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `replication.slot-name` | `backuptools_slot` | Replication slot name |
| `replication.publication-name` | `backuptools_pub` | Publication name |
| `replication.max-retries` | `3` | Max webhook retry attempts |
| `replication.retry-delay` | `5s` | Base retry delay |
| `replication.status-update-interval` | `10s` | Status update frequency |
| `replication.webhook-timeout` | `30s` | HTTP request timeout |
| `replication.worker-pool-size` | `10` | Number of webhook workers |
| `replication.event-channel-buffer` | `1000` | Event channel buffer size |

---

## 🧪 Verification Steps

### 1. Check PostgreSQL Replication Slot

```sql
-- Connect to PostgreSQL
psql -U postgres -d your_database

-- Check replication slots
SELECT * FROM pg_replication_slots WHERE slot_name = 'backuptools_slot';

-- Should show:
-- - slot_name: backuptools_slot
-- - plugin: pgoutput
-- - slot_type: logical
```

### 2. Check Publication

```sql
-- Check publications
SELECT * FROM pg_publication WHERE pubname = 'backuptools_pub';

-- Check publication tables
SELECT * FROM pg_publication_tables WHERE pubname = 'backuptools_pub';
```

### 3. Test Database Changes

```sql
-- Insert a test record (if replicating objects table)
INSERT INTO objects (project_id, bucket_name, object_key, ...) 
VALUES (...);

-- Check if webhook was sent (check Backup-Tools logs)
```

### 4. Monitor Service Logs

```bash
# Real-time logs
sudo journalctl -u storj-replication -f

# Check for errors
sudo journalctl -u storj-replication | grep -i error

# Check webhook sends
sudo journalctl -u storj-replication | grep "webhook sent successfully"
```

---

## 🐛 Troubleshooting

### Issue: "replication slot already exists"

**Solution:**
```sql
-- Drop existing slot (if safe to do so)
SELECT pg_drop_replication_slot('backuptools_slot');
```

### Issue: "publication already exists"

**Solution:**
```sql
-- Drop existing publication
DROP PUBLICATION backuptools_pub;
```

### Issue: "permission denied for replication"

**Solution:**
```sql
-- Grant replication privilege
ALTER USER your_user REPLICATION;
```

### Issue: "wal_level is not logical"

**Solution:**
```conf
# Edit postgresql.conf
wal_level = logical

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### Issue: Webhook connection errors

**Check:**
- Webhook URL is accessible
- Firewall allows outbound HTTPS
- Public key file exists and is readable
- Backup-Tools service is running

---

## 📊 Monitoring

### Key Metrics to Monitor

1. **Replication Lag**
   ```sql
   SELECT 
     slot_name,
     pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)) AS lag
   FROM pg_replication_slots;
   ```

2. **Service Health**
   ```bash
   # Check if service is running
   sudo systemctl status storj-replication
   
   # Check process
   ps aux | grep replication-service
   ```

3. **Webhook Success Rate**
   - Check logs for "webhook sent successfully" vs "webhook send failed"
   - Monitor Backup-Tools for received events

---

## 🔐 Security Best Practices

1. **File Permissions**
   ```bash
   # Config file: readable only by service user
   chmod 600 config.yaml
   
   # Public key: readable by service user
   chmod 644 webhook_public_key.pem
   ```

2. **Database Credentials**
   - Use environment variables or secure config files
   - Don't hardcode passwords in config files
   - Use PostgreSQL connection pooling if possible

3. **Network Security**
   - Use SSL/TLS for PostgreSQL connections (`sslmode=require`)
   - Use HTTPS for webhook URLs
   - Firewall: Allow only necessary ports

4. **Service User**
   - Run service as non-root user
   - Use dedicated user (`storj-replication`)
   - Limit file system access

---

## 📝 Quick Start Commands

```bash
# 1. Build
go build -o replication-service ./cmd/replication

# 2. Setup config
./replication-service setup --config-dir /etc/storj/replication

# 3. Edit config
nano /etc/storj/replication/config.yaml

# 4. Test run
./replication-service run --config-dir /etc/storj/replication

# 5. Install as service
sudo cp replication-service /opt/storj/replication/
sudo cp storj-replication.service /etc/systemd/system/
sudo systemctl enable storj-replication
sudo systemctl start storj-replication
```

---

## ✅ Checklist

- [ ] Go installed (v1.21+)
- [ ] PostgreSQL installed (v12+) with logical replication enabled
- [ ] Code cloned/transferred
- [ ] Service built successfully
- [ ] RSA public key file available
- [ ] Config file created and configured
- [ ] PostgreSQL user has replication privileges
- [ ] Replication slot created (automatic)
- [ ] Publication created (automatic)
- [ ] Service tested manually
- [ ] Systemd service created (optional)
- [ ] Service running and monitored
- [ ] Test database changes trigger webhooks

---

## 📞 Support

If you encounter issues:

1. Check service logs: `sudo journalctl -u storj-replication -f`
2. Check PostgreSQL logs: `/var/log/postgresql/postgresql-*.log`
3. Verify configuration: `./replication-service run --config-dir /path/to/config --help`
4. Test webhook endpoint manually with curl

---

**Last Updated:** 2024

