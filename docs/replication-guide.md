# PostgreSQL Logical Replication - Complete Guide

## 📋 Overview

This service replicates database changes from **StorXMonitor** to **Backuptools** using PostgreSQL Logical Replication and encrypted webhooks.

**Flow:**
```
PostgreSQL WAL → Replication Service → Encrypted Webhook → Backuptools
```

**Key Points:**
- StorXMonitor: Detects changes via WAL and sends encrypted webhooks
- Backuptools: Receives webhooks, decrypts, and syncs to backup database
- Encryption: RSA public key (StorXMonitor) → RSA private key (Backuptools)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                       │
│  • Application writes to objects/segments tables             │
│  • WAL (Write-Ahead Log) records all changes                │
│  • wal_level = logical (required!)                          │
└──────────────┬──────────────────────────────────────────────┘
               │ Replication Protocol
               ▼
┌─────────────────────────────────────────────────────────────┐
│          StorXMonitor Replication Service                   │
│  • Reads WAL stream (pglogrepl)                             │
│  • Parses INSERT/UPDATE/DELETE operations                   │
│  • Encrypts payload with RSA public key                     │
│  • Sends HTTP POST to Backuptools                           │
└──────────────┬──────────────────────────────────────────────┘
               │ HTTP POST (encrypted)
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Backuptools                              │
│  • Receives encrypted webhook                               │
│  • Decrypts with RSA private key                            │
│  • Processes INSERT/UPDATE/DELETE                          │
│  • Syncs to backup database                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Setup (One-Time)

### Step 1: PostgreSQL Configuration

**Enable logical replication (REQUIRED):**
```sql
ALTER SYSTEM SET wal_level = logical;
ALTER SYSTEM SET max_replication_slots = 10;
ALTER SYSTEM SET max_wal_senders = 10;
```
**Then restart PostgreSQL:**
```bash
sudo systemctl restart postgresql
```

**Verify:**
```sql
SHOW wal_level;  -- Should return: logical
```

### Step 2: PostgreSQL Permissions

**Grant permissions to your database user:**
```sql
-- Grant REPLICATION privilege (required!)
ALTER USER your_user WITH REPLICATION;

-- Grant database and schema access
GRANT CONNECT ON DATABASE storx TO your_user;
GRANT USAGE ON SCHEMA "satellite/0" TO your_user;

-- Grant SELECT on tables to replicate
GRANT SELECT ON ALL TABLES IN SCHEMA "satellite/0" TO your_user;
```

### Step 3: Generate RSA Key Pair

**In Backuptools:**
```bash
# Generate private key (keep secret!)
openssl genrsa -out backuptools_private.pem 2048

# Extract public key (share with StorXMonitor)
openssl rsa -in backuptools_private.pem -pubout -out backuptools_public.pem

# Secure private key
chmod 600 backuptools_private.pem
```

**Copy public key to StorXMonitor:**
```bash
scp backuptools_public.pem storxmonitor:/path/to/keys/
```

### Step 4: Configure Service

**Create config:**
```bash
./bin/replication setup \
  --database "postgres://user:password@localhost:5432/storx?sslmode=disable&options=--search_path%3D%22satellite%2F0%22" \
  --replication.webhook-url "http://localhost:8005/webhook" \
  --replication.webhook-public-key "/path/to/backuptools_public.pem"
```

**Or edit config file:**
```yaml
# ~/.local/share/storj/local-network/replication/config.yaml
database: "postgres://user:password@localhost:5432/storx?sslmode=disable&options=--search_path%3D%22satellite%2F0%22"

replication:
  webhook-url: "http://localhost:8005/webhook"
  webhook-public-key: "/path/to/backuptools_public.pem"
  slot-name: "backuptools_slot"
  publication-name: "backuptools_pub"
  tables:
    - "objects"
    - "segments"
```

---

## 🚀 Running the Service

```bash
./bin/replication run
```

**What happens automatically:**
- ✅ Creates replication slot (if not exists)
- ✅ Creates publication (if not exists)
- ✅ Connects to WAL stream
- ✅ Processes INSERT/UPDATE/DELETE operations
- ✅ Encrypts and sends webhooks to Backuptools

---

## 🔄 How It Works

### Service Startup Flow

1. **Create Replication Slot** - Tracks WAL position (LSN)
2. **Create Publication** - Defines which tables to replicate
3. **Get Current LSN** - Starting point for replication
4. **Start Replication Stream** - Connects to WAL
5. **Main Loop** - Receives and processes changes

### Processing Changes

When database change detected:
1. Parse WAL message (extract table data)
2. Check if table is in replication list
3. Create `ObjectChangeEvent` (INSERT/UPDATE/DELETE)
4. Encrypt payload (RSA + AES hybrid encryption)
5. Send webhook to Backuptools (with retry logic)

---

## 📝 Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `webhook-url` | Backuptools endpoint URL | Required |
| `webhook-public-key` | Path to RSA public key file | Required |
| `slot-name` | Replication slot name | `backuptools_slot` |
| `publication-name` | Publication name | `backuptools_pub` |
| `tables` | Tables to replicate | `["objects", "segments"]` |
| `max-retries` | Webhook retry attempts | `3` |
| `retry-delay` | Initial retry delay | `5s` |
| `webhook-timeout` | HTTP request timeout | `30s` |

---

## 🔐 Security

**Encryption Flow:**
1. StorXMonitor generates random AES-256 key
2. Encrypts AES key with RSA public key
3. Encrypts payload with AES key
4. Sends: `base64(encryptedAESKey):base64(encryptedPayload)`
5. Backuptools decrypts AES key with RSA private key
6. Backuptools decrypts payload with AES key

**Key Management:**
- **Private key**: Stays in Backuptools (NEVER share!)
- **Public key**: Safe to share, goes to StorXMonitor
- **Key size**: Use 2048-bit or higher (4096 recommended)

---

## 🛠️ Backuptools Implementation

### Webhook Endpoint

**Required:**
- `POST /webhook` endpoint
- Decrypt payload using RSA private key
- Parse `ObjectChangeEvent` JSON
- Process INSERT/UPDATE/DELETE operations

### Decryption Example (Go)

```go
// Load private key
privateKey, _ := loadPrivateKey("backuptools_private.pem")

// Decrypt payload
// Format: base64(encryptedAESKey):base64(encryptedPayload)
parts := strings.Split(encryptedData, ":")
encryptedAESKey, _ := base64.Decode(parts[0])
encryptedPayload, _ := base64.Decode(parts[1])

// Decrypt AES key with RSA
aesKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)

// Decrypt payload with AES
plaintext, _ := aesDecrypt(encryptedPayload, aesKey)

// Parse JSON
var event ObjectChangeEvent
json.Unmarshal(plaintext, &event)
```

### Event Structure

```json
{
  "operation": "INSERT|UPDATE|DELETE",
  "table": "objects|segments",
  "timestamp": "2025-12-06T10:20:00Z",
  "data": { /* ObjectData for INSERT/UPDATE */ },
  "old_data": { /* ObjectData for UPDATE/DELETE */ }
}
```

**See:** `docs/backuptools-implementation-guide.md` for complete implementation.

---

## ⚠️ Troubleshooting

### Error: "wal_level is not logical"
```sql
ALTER SYSTEM SET wal_level = logical;
-- Restart PostgreSQL
```

### Error: "permission denied for replication slot"
```sql
ALTER USER your_user WITH REPLICATION;
```

### Error: "relation does not exist"
- Check schema path in connection string
- Verify tables exist in that schema
- Grant SELECT on tables

### Error: "failed to load public key"
- Verify public key file exists
- Check file permissions (should be readable)
- Ensure PEM format (starts with `-----BEGIN PUBLIC KEY-----`)

---

## 📋 Quick Checklist

**PostgreSQL:**
- [ ] `wal_level = logical` (and restarted)
- [ ] User has `REPLICATION` privilege
- [ ] User has `SELECT` on tables
- [ ] User has `USAGE` on schema

**StorXMonitor:**
- [ ] RSA public key file exists
- [ ] Config file created
- [ ] Webhook URL configured
- [ ] Service can connect to database

**Backuptools:**
- [ ] Webhook endpoint implemented
- [ ] RSA private key configured
- [ ] Decryption logic implemented
- [ ] Database schema created

---

## 🔗 Related Files

- `replication/service.go` - Main replication service
- `replication/webhook.go` - Webhook encryption and sending
- `replication/parser.go` - WAL message parsing
- `replication/config.go` - Configuration structure
- `replication/HOW_IT_WORKS.md` - Detailed technical explanation

---

## 📚 Additional Resources

- [PostgreSQL Logical Replication](https://www.postgresql.org/docs/current/logical-replication.html)
- [pglogrepl Library](https://github.com/jackc/pglogrepl)
- [Backuptools Implementation Guide](./backuptools-implementation-guide.md)

