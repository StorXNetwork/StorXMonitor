# Task: Implement Backend API for OAuth Client Application Management

## 📋 Current Implementation Status

### ✅ Already Implemented

1. **Database Schema** (`satellite/satellitedb/dbx/developer.dbx`)
   - Table: `developer_oauth_client`
   - Fields: `id`, `developer_id`, `client_id`, `client_secret`, `name`, `redirect_uris`, `status`, `created_at`, `updated_at`
   - ✅ CRUD operations exist

2. **Service Layer** (`satellite/developer/functions.go`)
   - ✅ `CreateDeveloperOAuthClient()` - Creates OAuth client with hashed secret
   - ✅ `ListDeveloperOAuthClients()` - Lists all clients for developer
   - ✅ `DeleteDeveloperOAuthClient()` - Deletes OAuth client
   - ✅ `UpdateDeveloperOAuthClientStatus()` - Updates status (active/inactive)
   - ✅ `isCurrentDeveloperOAuthClientOwner()` - Ownership validation
   - ✅ `generateRandomSecret()` - Generates random secret
   - ✅ `hashSecret()` - Hashes secret using bcrypt

3. **HTTP Controllers** (`satellite/developer/auth_controller.go`)
   - ✅ `CreateOAuthClient()` - POST `/api/v0/developer/auth/oauth2/clients`
   - ✅ `ListOAuthClients()` - GET `/api/v0/developer/auth/oauth2/clients`
   - ✅ `DeleteOAuthClient()` - DELETE `/api/v0/developer/auth/oauth2/clients/{id}`
   - ✅ `UpdateOAuthClientStatus()` - PATCH `/api/v0/developer/auth/oauth2/clients/{id}/status`

4. **Routes** (`satellite/developer/server.go`)
   - ✅ All routes registered with authentication middleware

5. **Data Models** (`satellite/console/developer_oauth_clients.go`)
   - ✅ `DeveloperOAuthClient` struct
   - ✅ `DeveloperOAuthClients` interface

---

## ❌ Missing Implementation

### 1. **Regenerate Client Secret**
   - **Endpoint**: `POST /api/v0/developer/auth/oauth2/clients/{id}/regenerate-secret`
   - **Purpose**: Generate new client secret, invalidate old one
   - **Security**: Must verify ownership, hash new secret, return plaintext only once
   - **Files to modify**:
     - `satellite/developer/functions.go` - Add `RegenerateDeveloperOAuthClientSecret()`
     - `satellite/developer/auth_controller.go` - Add `RegenerateOAuthClientSecret()`
     - `satellite/developer/server.go` - Add route

### 2. **Update OAuth Client** (Name, Description, Redirect URIs, Scopes)
   - **Endpoint**: `PUT /api/v0/developer/auth/oauth2/clients/{id}`
   - **Purpose**: Update client details (name, description, redirect URIs, scopes)
   - **Files to modify**:
     - `satellite/console/developer_oauth_clients.go` - Add `Description` and `Scopes` fields
     - `satellite/developer/functions.go` - Add `UpdateDeveloperOAuthClient()`
     - `satellite/developer/auth_controller.go` - Add `UpdateOAuthClient()`
     - `satellite/developer/server.go` - Add route
     - Database migration - Add `description` and `scopes` columns

### 3. **Get Single OAuth Client**
   - **Endpoint**: `GET /api/v0/developer/auth/oauth2/clients/{id}`
   - **Purpose**: Get details of a specific client (without secret)
   - **Files to modify**:
     - `satellite/developer/functions.go` - Add `GetDeveloperOAuthClient()` (or use existing `GetByID`)
     - `satellite/developer/auth_controller.go` - Add `GetOAuthClient()`
     - `satellite/developer/server.go` - Add route

### 4. **Database Schema Updates**
   - **Add fields**: `description` (text), `scopes` (text/JSON)
   - **Migration**: Create migration to add columns
   - **Files to modify**:
     - `satellite/satellitedb/dbx/developer.dbx` - Add fields to model
     - `satellite/satellitedb/developer_oauth_clients.go` - Update conversion logic
     - `satellite/console/developer_oauth_clients.go` - Update struct

### 5. **Request/Response Types**
   - **Files to modify**:
     - `satellite/console/service.go` - Update `CreateOAuthClientRequest` and `UpdateOAuthClientRequest`
     - Add `RegenerateSecretRequest` and `RegenerateSecretResponse`

### 6. **Error Handling Improvements**
   - Better error messages
   - Proper HTTP status codes
   - Validation errors

### 7. **Security Enhancements**
   - Ensure secrets never returned after creation (except regenerate)
   - Audit logging for all operations
   - Rate limiting considerations

---

## 🎯 Implementation Plan

### Phase 1: Database Schema Updates

1. **Update DBX Schema** (`satellite/satellitedb/dbx/developer.dbx`)
   ```dbx
   model developer_oauth_client (
       // ... existing fields ...
       field description text ( updatable )
       field scopes text ( updatable )
   )
   ```

2. **Create Migration**
   - Add `description` and `scopes` columns
   - Update existing records if needed

3. **Regenerate DBX Code**
   ```bash
   make generate-dbx
   ```

4. **Update Go Structs**
   - `satellite/console/developer_oauth_clients.go` - Add fields
   - `satellite/satellitedb/developer_oauth_clients.go` - Update conversion

### Phase 2: Service Layer Functions

1. **RegenerateSecret Function** (`satellite/developer/functions.go`)
   ```go
   func (s *Service) RegenerateDeveloperOAuthClientSecret(ctx context.Context, id uuid.UUID) (*console.DeveloperOAuthClient, error)
   ```

2. **Update Function** (`satellite/developer/functions.go`)
   ```go
   func (s *Service) UpdateDeveloperOAuthClient(ctx context.Context, id uuid.UUID, req console.UpdateOAuthClientRequest) (*console.DeveloperOAuthClient, error)
   ```

3. **Get Function** (if needed, or use existing)
   ```go
   func (s *Service) GetDeveloperOAuthClient(ctx context.Context, id uuid.UUID) (*console.DeveloperOAuthClient, error)
   ```

### Phase 3: HTTP Controllers

1. **RegenerateSecret Handler** (`satellite/developer/auth_controller.go`)
   ```go
   func (a *DeveloperAuth) RegenerateOAuthClientSecret(w http.ResponseWriter, r *http.Request)
   ```

2. **Update Handler** (`satellite/developer/auth_controller.go`)
   ```go
   func (a *DeveloperAuth) UpdateOAuthClient(w http.ResponseWriter, r *http.Request)
   ```

3. **Get Handler** (`satellite/developer/auth_controller.go`)
   ```go
   func (a *DeveloperAuth) GetOAuthClient(w http.ResponseWriter, r *http.Request)
   ```

### Phase 4: Routes

1. **Add Routes** (`satellite/developer/server.go`)
   ```go
   developerAuthRouter.Handle("/oauth2/clients/{id}", ...).Methods("GET", "PUT")
   developerAuthRouter.Handle("/oauth2/clients/{id}/regenerate-secret", ...).Methods("POST")
   ```

### Phase 5: Request/Response Types

1. **Update Types** (`satellite/console/service.go` or new file)
   ```go
   type CreateOAuthClientRequest struct {
       Name         string   `json:"name"`
       Description  string   `json:"description"`
       RedirectURIs []string `json:"redirect_uris"`
       Scopes       []string `json:"scopes"`
   }
   
   type UpdateOAuthClientRequest struct {
       Name         *string   `json:"name"`
       Description  *string   `json:"description"`
       RedirectURIs *[]string `json:"redirect_uris"`
       Scopes       *[]string `json:"scopes"`
   }
   
   type RegenerateSecretResponse struct {
       ClientID     string `json:"client_id"`
       ClientSecret string `json:"client_secret"`
   }
   ```

---

## 📝 Detailed Implementation Checklist

### Database Layer
- [ ] Add `description` field to `developer_oauth_client` model in DBX
- [ ] Add `scopes` field to `developer_oauth_client` model in DBX
- [ ] Create database migration
- [ ] Run migration
- [ ] Regenerate DBX code
- [ ] Update `toConsoleOAuthClient()` helper function
- [ ] Update `Insert()` to handle new fields

### Service Layer
- [ ] Implement `RegenerateDeveloperOAuthClientSecret()`
  - [ ] Verify ownership
  - [ ] Generate new secret
  - [ ] Hash secret
  - [ ] Update database
  - [ ] Return plaintext secret (one-time)
  - [ ] Audit log
- [ ] Implement `UpdateDeveloperOAuthClient()`
  - [ ] Verify ownership
  - [ ] Validate input
  - [ ] Update only provided fields
  - [ ] Update `updated_at` timestamp
  - [ ] Audit log
- [ ] Update `CreateDeveloperOAuthClient()` to handle description and scopes
- [ ] Ensure secrets are never returned in list/get (except create/regenerate)

### Controller Layer
- [ ] Implement `RegenerateOAuthClientSecret()` handler
  - [ ] Parse ID from URL
  - [ ] Call service
  - [ ] Return response
  - [ ] Error handling
- [ ] Implement `UpdateOAuthClient()` handler
  - [ ] Parse ID from URL
  - [ ] Parse request body
  - [ ] Validate input
  - [ ] Call service
  - [ ] Return response
  - [ ] Error handling
- [ ] Implement `GetOAuthClient()` handler
  - [ ] Parse ID from URL
  - [ ] Verify ownership
  - [ ] Call service
  - [ ] Return response (without secret)
  - [ ] Error handling
- [ ] Improve error handling in existing handlers
- [ ] Add proper HTTP status codes

### Routes
- [ ] Add GET route for single client
- [ ] Add PUT route for update
- [ ] Add POST route for regenerate secret
- [ ] Ensure all routes have authentication middleware

### Request/Response Types
- [ ] Update `CreateOAuthClientRequest` with description and scopes
- [ ] Create/Update `UpdateOAuthClientRequest` with all fields
- [ ] Create `RegenerateSecretResponse` type
- [ ] Update response types to exclude secrets

### Security & Validation
- [ ] Ensure secrets are hashed before storage
- [ ] Ensure secrets are only returned on create/regenerate
- [ ] Add ownership validation for all operations
- [ ] Add input validation (name, redirect URIs, scopes)
- [ ] Add audit logging for all operations
- [ ] Validate redirect URI format
- [ ] Validate scopes (if predefined list exists)

### Testing Considerations
- [ ] Test regenerate secret flow
- [ ] Test update client flow
- [ ] Test get single client
- [ ] Test ownership validation
- [ ] Test secret security (never returned after creation)
- [ ] Test validation errors
- [ ] Test error handling

---

## 🔒 Security Requirements

1. **Secret Management**
   - ✅ Secrets are hashed using bcrypt (already implemented)
   - ✅ Plaintext secret shown only once on creation
   - ⚠️ Need to ensure regenerate also shows only once
   - ⚠️ Need to ensure secrets never returned in list/get

2. **Ownership Validation**
   - ✅ `isCurrentDeveloperOAuthClientOwner()` exists
   - ⚠️ Must be used in all new operations

3. **Audit Logging**
   - ✅ `getDeveloperAndAuditLog()` exists
   - ⚠️ Must be used in all new operations

4. **Input Validation**
   - ⚠️ Validate name (not empty, length limits)
   - ⚠️ Validate redirect URIs (valid URLs, format)
   - ⚠️ Validate scopes (if predefined list)

---

## 📁 Files to Create/Modify

### Files to Modify:
1. `satellite/satellitedb/dbx/developer.dbx` - Add description and scopes fields
2. `satellite/console/developer_oauth_clients.go` - Add Description and Scopes to struct
3. `satellite/satellitedb/developer_oauth_clients.go` - Update conversion logic
4. `satellite/developer/functions.go` - Add regenerate and update functions
5. `satellite/developer/auth_controller.go` - Add handlers
6. `satellite/developer/server.go` - Add routes
7. `satellite/console/service.go` - Update request types (or create new file)

### Files to Create:
1. Database migration file for adding description and scopes columns

---

## 🚀 Next Steps

1. **Start with Database Schema** - Add description and scopes fields
2. **Create Migration** - Add columns to existing table
3. **Update Structs** - Add fields to Go structs
4. **Implement Regenerate Secret** - Most critical missing feature
5. **Implement Update Client** - Allow editing name, description, URIs, scopes
6. **Add Get Single Client** - For viewing details
7. **Improve Error Handling** - Better messages and status codes
8. **Add Tests** - Unit and integration tests

---

## 📚 Reference

- Existing implementation: `satellite/developer/functions.go:748-832`
- Database schema: `satellite/satellitedb/dbx/developer.dbx:182-195`
- HTTP handlers: `satellite/developer/auth_controller.go:570-638`
- Routes: `satellite/developer/server.go:175-178`

