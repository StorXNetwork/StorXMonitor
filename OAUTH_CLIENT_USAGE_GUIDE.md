# OAuth Client Management API - Real-World Usage Guide

## 🌍 What is OAuth2 and Why Do We Need This?

OAuth2 is an authorization framework that allows **third-party applications** to access user data from your StorX platform **without sharing passwords**. Think of it like giving a hotel key card - the app gets limited access without your master key.

### Real-World Analogy:
- **You (User)**: Want to use a mobile app that backs up photos to StorX
- **Mobile App (OAuth Client)**: Needs permission to upload photos to your account
- **StorX Platform (Authorization Server)**: Grants limited access tokens
- **Your Photos (Protected Resource)**: What the app can access

---

## 🎯 Real-World Scenarios

### Scenario 1: Mobile Photo Backup App

**Company**: "PhotoSync Inc." wants to create a mobile app that automatically backs up user photos to StorX.

**Steps**:

1. **Developer Registration** (Already done via admin portal)
   - PhotoSync developer creates account
   - Gets developer credentials

2. **Create OAuth Client** (First time setup)
   ```bash
   POST /api/v0/developer/auth/oauth2/clients
   Authorization: Bearer <developer_token>
   Content-Type: application/json
   
   {
     "name": "PhotoSync Mobile App",
     "description": "Automatic photo backup service for iOS and Android",
     "redirect_uris": [
       "photosync://oauth/callback",
       "https://photosync.app/oauth/callback"
     ],
     "scopes": ["files:read", "files:write"]
   }
   ```
   
   **Response**:
   ```json
   {
     "client_id": "550e8400-e29b-41d4-a716-446655440000",
     "client_secret": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"  // ⚠️ SAVE THIS NOW!
   }
   ```
   
   **What happens**: PhotoSync saves `client_id` and `client_secret` securely in their app backend.

3. **User Authorization Flow** (When user installs app)
   ```
   User opens PhotoSync app
   → App redirects to StorX login page
   → User logs in and grants permission
   → StorX redirects back with authorization code
   → App exchanges code for access token
   → App can now upload photos to user's StorX account
   ```

4. **If Secret is Compromised** (Security incident)
   ```bash
   POST /api/v0/developer/auth/oauth2/clients/{id}/regenerate-secret
   Authorization: Bearer <developer_token>
   ```
   
   **Response**:
   ```json
   {
     "client_id": "550e8400-e29b-41d4-a716-446655440000",
     "client_secret": "NEW_SECRET_xyz123..."  // Old secret invalidated
   }
   ```
   
   **What happens**: Old secret stops working, app must update with new secret.

---

### Scenario 2: Enterprise Integration Tool

**Company**: "DataFlow Corp" wants to integrate StorX with their enterprise data pipeline.

**Steps**:

1. **Create Client for Production**
   ```bash
   POST /api/v0/developer/auth/oauth2/clients
   {
     "name": "DataFlow Production Integration",
     "description": "Enterprise data pipeline integration for production environment",
     "redirect_uris": ["https://dataflow.corp/api/storx/callback"],
     "scopes": ["projects:read", "buckets:read", "buckets:write", "files:read", "files:write"]
   }
   ```

2. **Create Separate Client for Testing**
   ```bash
   POST /api/v0/developer/auth/oauth2/clients
   {
     "name": "DataFlow Staging Integration",
     "description": "Testing environment for development",
     "redirect_uris": ["https://staging.dataflow.corp/api/storx/callback"],
     "scopes": ["projects:read", "buckets:read", "buckets:write"]
   }
   ```

3. **List All Clients** (Management)
   ```bash
   GET /api/v0/developer/auth/oauth2/clients
   Authorization: Bearer <developer_token>
   ```
   
   **Response**:
   ```json
   [
     {
       "id": "550e8400-e29b-41d4-a716-446655440000",
       "client_id": "prod-client-123",
       "name": "DataFlow Production Integration",
       "description": "Enterprise data pipeline...",
       "redirect_uris": ["https://dataflow.corp/api/storx/callback"],
       "scopes": ["projects:read", "buckets:read", "buckets:write", "files:read", "files:write"],
       "status": 1,
       "created_at": "2024-01-15T10:30:00Z",
       "updated_at": "2024-01-15T10:30:00Z"
     },
     {
       "id": "660e8400-e29b-41d4-a716-446655440001",
       "client_id": "staging-client-456",
       "name": "DataFlow Staging Integration",
       "description": "Testing environment...",
       "redirect_uris": ["https://staging.dataflow.corp/api/storx/callback"],
       "scopes": ["projects:read", "buckets:read", "buckets:write"],
       "status": 1,
       "created_at": "2024-01-16T14:20:00Z",
       "updated_at": "2024-01-16T14:20:00Z"
     }
   ]
   ```
   
   **Note**: No `client_secret` in list (security)

4. **Update Client** (Add new redirect URI)
   ```bash
   PUT /api/v0/developer/auth/oauth2/clients/{id}
   Authorization: Bearer <developer_token>
   Content-Type: application/json
   
   {
     "redirect_uris": [
       "https://dataflow.corp/api/storx/callback",
       "https://dataflow.corp/api/storx/callback-v2"  // New URI added
     ]
   }
   ```
   
   **What happens**: App can now accept callbacks from both old and new URLs.

5. **Get Single Client Details**
   ```bash
   GET /api/v0/developer/auth/oauth2/clients/{id}
   Authorization: Bearer <developer_token>
   ```
   
   **Response**:
   ```json
   {
     "id": "550e8400-e29b-41d4-a716-446655440000",
     "client_id": "prod-client-123",
     "name": "DataFlow Production Integration",
     "description": "Enterprise data pipeline integration for production environment",
     "redirect_uris": ["https://dataflow.corp/api/storx/callback"],
     "scopes": ["projects:read", "buckets:read", "buckets:write", "files:read", "files:write"],
     "status": 1,
     "created_at": "2024-01-15T10:30:00Z",
     "updated_at": "2024-01-20T09:15:00Z"
   }
   ```

6. **Temporarily Disable Client** (Maintenance)
   ```bash
   PATCH /api/v0/developer/auth/oauth2/clients/{id}/status
   Authorization: Bearer <developer_token>
   Content-Type: application/json
   
   {
     "status": 0  // 0 = inactive, 1 = active
   }
   ```
   
   **What happens**: All tokens from this client become invalid, app stops working until reactivated.

7. **Delete Client** (No longer needed)
   ```bash
   DELETE /api/v0/developer/auth/oauth2/clients/{id}
   Authorization: Bearer <developer_token>
   ```
   
   **What happens**: Client permanently removed, all associated tokens invalidated.

---

### Scenario 3: Web Application Integration

**Company**: "CloudDocs" wants to add StorX as a storage option in their web-based document editor.

**Steps**:

1. **Initial Setup**
   ```bash
   POST /api/v0/developer/auth/oauth2/clients
   {
     "name": "CloudDocs Web App",
     "description": "Document editor with StorX cloud storage integration",
     "redirect_uris": [
       "https://clouddocs.app/oauth/storx/callback",
       "https://www.clouddocs.app/oauth/storx/callback"  // Both www and non-www
     ],
     "scopes": ["files:read", "files:write", "buckets:read"]
   }
   ```

2. **Update Scopes** (Need more permissions later)
   ```bash
   PUT /api/v0/developer/auth/oauth2/clients/{id}
   {
     "scopes": [
       "files:read",
       "files:write",
       "buckets:read",
       "buckets:write",  // Added
       "projects:read"   // Added
     ]
   }
   ```

3. **Update Description** (Documentation)
   ```bash
   PUT /api/v0/developer/auth/oauth2/clients/{id}
   {
     "description": "Document editor with StorX cloud storage integration. Supports real-time collaboration and automatic sync."
   }
   ```

---

## 🔄 Complete OAuth2 Flow Example

### Step-by-Step: User Grants Access to Third-Party App

1. **User Action**: User clicks "Connect StorX" button in PhotoSync app

2. **App Redirects**:
   ```
   https://storx.com/oauth/authorize?
     client_id=550e8400-e29b-41d4-a716-446655440000
     &redirect_uri=photosync://oauth/callback
     &response_type=code
     &scope=files:read files:write
     &state=random_security_token
   ```

3. **User Sees**: StorX login page asking:
   - "PhotoSync Mobile App wants to access your files"
   - Permissions: Read files, Write files
   - User clicks "Allow"

4. **StorX Redirects Back**:
   ```
   photosync://oauth/callback?
     code=AUTHORIZATION_CODE_12345
     &state=random_security_token
   ```

5. **App Exchanges Code for Token**:
   ```bash
   POST https://storx.com/oauth/token
   Content-Type: application/x-www-form-urlencoded
   
   grant_type=authorization_code
   &code=AUTHORIZATION_CODE_12345
   &redirect_uri=photosync://oauth/callback
   &client_id=550e8400-e29b-41d4-a716-446655440000
   &client_secret=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
   ```
   
   **Response**:
   ```json
   {
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "refresh_token_xyz..."
   }
   ```

6. **App Uses Token**:
   ```bash
   GET https://api.storx.com/v1/files
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```
   
   **Response**: User's files list

---

## 🛡️ Security Best Practices

### 1. **Secret Management**
- ✅ Store `client_secret` in secure environment variables
- ✅ Never commit secrets to Git
- ✅ Use different secrets for dev/staging/production
- ✅ Rotate secrets regularly using regenerate endpoint

### 2. **Redirect URI Validation**
- ✅ Only use HTTPS redirect URIs (except localhost for development)
- ✅ Register exact URIs - no wildcards
- ✅ Update redirect URIs if your app URL changes

### 3. **Scope Management**
- ✅ Request minimum required scopes
- ✅ Update scopes if app needs more permissions
- ✅ Document what each scope allows

### 4. **Client Status Management**
- ✅ Disable clients during maintenance
- ✅ Delete unused clients
- ✅ Monitor active clients regularly

---

## 📊 Common Use Cases Summary

| Use Case | Example | Scopes Needed |
|----------|---------|---------------|
| **File Backup** | PhotoSync, CloudBackup | `files:read`, `files:write` |
| **Data Analytics** | Business Intelligence Tool | `files:read`, `projects:read` |
| **Content Management** | CMS Integration | `buckets:read`, `buckets:write`, `files:read`, `files:write` |
| **Development Tools** | CI/CD Pipeline | `projects:read`, `buckets:write` |
| **Enterprise Sync** | Corporate File Sync | `files:read`, `files:write`, `projects:read` |

---

## 🔧 API Endpoints Quick Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/oauth2/clients` | Create new OAuth client |
| `GET` | `/oauth2/clients` | List all your clients |
| `GET` | `/oauth2/clients/{id}` | Get single client details |
| `PUT` | `/oauth2/clients/{id}` | Update client (name, description, URIs, scopes) |
| `DELETE` | `/oauth2/clients/{id}` | Delete client |
| `PATCH` | `/oauth2/clients/{id}/status` | Enable/disable client |
| `POST` | `/oauth2/clients/{id}/regenerate-secret` | Generate new secret |

---

## 💡 Pro Tips

1. **Multiple Environments**: Create separate clients for dev, staging, and production
2. **Secret Rotation**: Regenerate secrets every 90 days or after security incidents
3. **Monitoring**: Regularly list clients to audit active integrations
4. **Documentation**: Use `description` field to document what each client is for
5. **Cleanup**: Delete unused clients to reduce attack surface

---

## 🚨 Important Notes

- ⚠️ **Client Secret is shown ONLY ONCE** - Save it immediately after creation/regeneration
- ⚠️ **Secrets are NEVER returned** in list/get endpoints (security)
- ⚠️ **Ownership Validation** - You can only manage your own clients
- ⚠️ **Status Changes** - Disabling a client invalidates all its tokens immediately
- ⚠️ **Redirect URIs** - Must match exactly (case-sensitive, no trailing slashes)

---

## 📝 Example: Complete Integration Setup

```bash
# 1. Create client
curl -X POST https://api.storx.com/api/v0/developer/auth/oauth2/clients \
  -H "Authorization: Bearer YOUR_DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Awesome App",
    "description": "Integration for automated backups",
    "redirect_uris": ["https://myapp.com/callback"],
    "scopes": ["files:read", "files:write"]
  }'

# Response: Save client_id and client_secret!

# 2. Later, update redirect URI
curl -X PUT https://api.storx.com/api/v0/developer/auth/oauth2/clients/{id} \
  -H "Authorization: Bearer YOUR_DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": [
      "https://myapp.com/callback",
      "https://myapp.com/callback-v2"
    ]
  }'

# 3. If secret compromised, regenerate
curl -X POST https://api.storx.com/api/v0/developer/auth/oauth2/clients/{id}/regenerate-secret \
  -H "Authorization: Bearer YOUR_DEV_TOKEN"

# Response: New client_secret - update your app immediately!
```

---

This API enables secure, scalable integrations between StorX and third-party applications! 🚀

