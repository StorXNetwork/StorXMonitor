# Replication Service - Quick Start Commands

Quick reference for setting up replication service on a new PC.

---

## 🚀 Quick Setup (5 Minutes)

### 1. Prerequisites Check
```bash
# Check Go
go version

# Check PostgreSQL
psql --version

# Check PostgreSQL logical replication
psql -U postgres -c "SHOW wal_level;"
# Should output: logical
```

### 2. Build Service
```bash
cd /path/to/StorXMonitor
go build -o replication-service ./cmd/replication
```

### 3. Create Config
```bash
# Create config directory
sudo mkdir -p /etc/storj/replication

# Generate config template
./replication-service setup --config-dir /etc/storj/replication

# Edit config
sudo nano /etc/storj/replication/config.yaml
```

### 4. Configure PostgreSQL
```bash
# Edit postgresql.conf
sudo nano /etc/postgresql/*/main/postgresql.conf

# Add/verify:
wal_level = logical
max_replication_slots = 10

# Restart PostgreSQL
sudo systemctl restart postgresql

# Grant replication privilege
sudo -u postgres psql -c "ALTER USER your_user REPLICATION;"
```

### 5. Run Service
```bash
# Test run
./replication-service run --config-dir /etc/storj/replication

# Or with command-line flags
./replication-service run \
  --database "postgresql://user:pass@localhost:5432/db" \
  --replication.webhook-url "https://backup-tools.example.com/api/webhook" \
  --replication.webhook-public-key "/path/to/public_key.pem"
```

---

## 📋 Essential Commands

### Build
```bash
go build -o replication-service ./cmd/replication
```

### Setup Config
```bash
./replication-service setup --config-dir /etc/storj/replication
```

### Run (Config File)
```bash
./replication-service run --config-dir /etc/storj/replication
```

### Run (Command Line)
```bash
./replication-service run \
  --database "postgresql://user:pass@host:5432/db" \
  --replication.webhook-url "https://backup-tools.example.com/api/webhook" \
  --replication.webhook-public-key "/path/to/public_key.pem" \
  --replication.slot-name "backuptools_slot" \
  --replication.publication-name "backuptools_pub"
```

### Check Help
```bash
./replication-service --help
./replication-service run --help
```

---

## 🔧 PostgreSQL Setup Commands

### Enable Logical Replication
```sql
-- Connect to PostgreSQL
sudo -u postgres psql

-- Check current wal_level
SHOW wal_level;

-- If not 'logical', edit postgresql.conf:
-- wal_level = logical
-- max_replication_slots = 10
-- Then restart: sudo systemctl restart postgresql
```

### Grant Replication Privilege
```sql
ALTER USER your_user REPLICATION;
-- Or create new user:
CREATE USER replication_user WITH REPLICATION PASSWORD 'password';
```

### Check Replication Slot
```sql
SELECT * FROM pg_replication_slots WHERE slot_name = 'backuptools_slot';
```

### Check Publication
```sql
SELECT * FROM pg_publication WHERE pubname = 'backuptools_pub';
SELECT * FROM pg_publication_tables WHERE pubname = 'backuptools_pub';
```

### Drop Slot (if needed)
```sql
SELECT pg_drop_replication_slot('backuptools_slot');
```

### Drop Publication (if needed)
```sql
DROP PUBLICATION backuptools_pub;
```

---

## 🐧 Systemd Service Setup

### Create Service File
```bash
sudo nano /etc/systemd/system/storj-replication.service
```

### Service File Content
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

[Install]
WantedBy=multi-user.target
```

### Enable & Start
```bash
# Create service user
sudo useradd -r -s /bin/false storj-replication

# Copy binary
sudo mkdir -p /opt/storj/replication
sudo cp replication-service /opt/storj/replication/
sudo chown -R storj-replication:storj-replication /opt/storj/replication

# Set permissions
sudo chmod 600 /etc/storj/replication/config.yaml

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable storj-replication
sudo systemctl start storj-replication
```

### Service Management
```bash
# Start
sudo systemctl start storj-replication

# Stop
sudo systemctl stop storj-replication

# Restart
sudo systemctl restart storj-replication

# Status
sudo systemctl status storj-replication

# Logs
sudo journalctl -u storj-replication -f
```

---

## 📝 Config File Template

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
    - table: "segments"
      events: ["INSERT", "DELETE"]
```

---

## 🧪 Testing Commands

### Test Database Connection
```bash
psql "postgresql://user:password@localhost:5432/db" -c "SELECT 1;"
```

### Test Webhook Endpoint
```bash
curl -X POST https://backup-tools.example.com/api/webhook \
  -H "Content-Type: application/octet-stream" \
  -d "test"
```

### Check Service Logs
```bash
# Real-time
sudo journalctl -u storj-replication -f

# Last 100 lines
sudo journalctl -u storj-replication -n 100

# Errors only
sudo journalctl -u storj-replication | grep -i error
```

### Monitor Replication Slot
```sql
SELECT 
  slot_name,
  pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)) AS lag
FROM pg_replication_slots
WHERE slot_name = 'backuptools_slot';
```

---

## 🔍 Troubleshooting Commands

### Check PostgreSQL Config
```bash
sudo -u postgres psql -c "SHOW wal_level;"
sudo -u postgres psql -c "SHOW max_replication_slots;"
```

### Check Replication Slots
```sql
SELECT * FROM pg_replication_slots;
```

### Check Publications
```sql
SELECT * FROM pg_publication;
SELECT * FROM pg_publication_tables;
```

### Check Service Process
```bash
ps aux | grep replication-service
```

### Check Ports
```bash
netstat -tulpn | grep 5432  # PostgreSQL
```

### Test Config
```bash
./replication-service run --config-dir /etc/storj/replication --help
```

---

## 📦 File Locations

| File | Default Location |
|------|----------------|
| Binary | `/opt/storj/replication/replication-service` |
| Config | `/etc/storj/replication/config.yaml` |
| Public Key | `/etc/storj/replication/webhook_public_key.pem` |
| Logs | `journalctl -u storj-replication` |

---

## ✅ Verification Checklist

```bash
# 1. Service builds
go build -o replication-service ./cmd/replication

# 2. Config exists
ls -la /etc/storj/replication/config.yaml

# 3. Public key exists
ls -la /etc/storj/replication/webhook_public_key.pem

# 4. PostgreSQL logical replication enabled
sudo -u postgres psql -c "SHOW wal_level;"  # Should be "logical"

# 5. User has replication privilege
sudo -u postgres psql -c "\du" | grep REPLICATION

# 6. Service runs
./replication-service run --config-dir /etc/storj/replication

# 7. Replication slot created (after first run)
sudo -u postgres psql -c "SELECT * FROM pg_replication_slots;"

# 8. Publication created (after first run)
sudo -u postgres psql -c "SELECT * FROM pg_publication;"
```

---

**Quick Reference - Save this!**

