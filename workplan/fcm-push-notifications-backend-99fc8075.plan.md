<!-- 99fc8075-9bd3-405e-a323-0ecd513f278b bd682b48-9e71-4d35-8cb8-b07c1fd0c8ae -->
# FCM Push Notifications Backend Implementation Plan

## Overview

Implement complete backend infrastructure for Firebase Cloud Messaging (FCM) push notifications in the StorX platform. This includes database tables for storing FCM tokens, a service for sending notifications, and API endpoints for token management.

## Database Schema

### 1. Create `fcm_tokens` Table

**Location**: `satellite/satellitedb/migrate.go` (new migration step)

**Table Structure**:

```sql
CREATE TABLE fcm_tokens (
    id bytea NOT NULL,
    user_id bytea NOT NULL,
    token text NOT NULL,
    device_id text,
    device_type text, -- 'android', 'ios', 'web'
    app_version text,
    os_version text, -- 'Windows 10', 'Android 13', 'iOS 16.0'
    device_model text, -- 'iPhone 14', 'Samsung Galaxy S21'
    browser_name text, -- 'Chrome', 'Safari', 'Firefox' (web only)
    user_agent text, -- Full user agent string
    ip_address text, -- Client IP address (from server)
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone,
    is_active boolean NOT NULL DEFAULT true,
    PRIMARY KEY ( id )
);

CREATE INDEX fcm_tokens_user_id_index ON fcm_tokens ( user_id );
CREATE INDEX fcm_tokens_token_index ON fcm_tokens ( token );
CREATE INDEX fcm_tokens_user_active_index ON fcm_tokens ( user_id, is_active );
```

**Migration Details**:

- Add new migration steps (version 290 for fcm_tokens, version 291 for push_notifications) in `satellite/satellitedb/migrate.go` (current latest is 289)
- Create corresponding test migration files: `satellite/satellitedb/testdata/postgres.v290.sql` and `postgres.v291.sql`
- Follow existing migration pattern with `SeparateTx: true` for index creation

### 2. Create `push_notifications` Table (Optional - for tracking)

**Location**: `satellite/satellitedb/migrate.go`

**Table Structure**:

```sql
CREATE TABLE push_notifications (
    id bytea NOT NULL,
    user_id bytea NOT NULL,
    token_id bytea,
    title text NOT NULL,
    body text NOT NULL,
    data jsonb,
    status text NOT NULL, -- 'pending', 'sent', 'failed'
    error_message text,
    retry_count integer NOT NULL DEFAULT 0, -- Number of retry attempts for this notification
    sent_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    PRIMARY KEY ( id )
);

CREATE INDEX push_notifications_user_id_index ON push_notifications ( user_id );
CREATE INDEX push_notifications_status_index ON push_notifications ( status );
CREATE INDEX push_notifications_created_at_index ON push_notifications ( created_at );
```

## Database Access Layer

### 3. Create DBX Model

**Location**: `satellite/satellitedb/dbx/satellitedb.dbx`

Add model definitions:

```dbx
model fcm_tokens (
    key id
    
    field id blob
    field user_id blob
    field token text
    field device_id text ( nullable, updatable )
    field device_type text ( nullable, updatable )
    field app_version text ( nullable, updatable )
    field os_version text ( nullable, updatable )
    field device_model text ( nullable, updatable )
    field browser_name text ( nullable, updatable )
    field user_agent text ( nullable, updatable )
    field ip_address text ( nullable, updatable )
    field created_at timestamp ( autoinsert )
    field updated_at timestamp ( updatable )
    field last_used_at timestamp ( nullable, updatable )
    field is_active bool ( updatable, default true )
)

create fcm_tokens ( )
update fcm_tokens ( where fcm_tokens.id = ? )
delete fcm_tokens ( where fcm_tokens.id = ? )

read one (
    select fcm_tokens
    where fcm_tokens.id = ?
)

read all (
    select fcm_tokens
    where fcm_tokens.user_id = ?
    and fcm_tokens.is_active = true
)
```

### 4. Create Database Interface

**Location**: `satellite/console/pushnotifications/db.go`

```go
package pushnotifications

import (
    "context"
    "storj.io/common/uuid"
)

// DB defines database operations for FCM tokens
type DB interface {
    // InsertToken inserts a new FCM token for a user
    InsertToken(ctx context.Context, token FCMToken) (FCMToken, error)
    
    // GetTokensByUserID retrieves all active tokens for a user
    GetTokensByUserID(ctx context.Context, userID uuid.UUID) ([]FCMToken, error)
    
    // GetTokenByID retrieves a token by ID
    GetTokenByID(ctx context.Context, tokenID uuid.UUID) (FCMToken, error)
    
    // UpdateToken updates an existing token
    UpdateToken(ctx context.Context, tokenID uuid.UUID, update UpdateTokenRequest) error
    
    // DeleteToken deletes a token (soft delete by setting is_active = false)
    DeleteToken(ctx context.Context, tokenID uuid.UUID) error
    
    // DeleteTokensByUserID deletes all tokens for a user
    DeleteTokensByUserID(ctx context.Context, userID uuid.UUID) error
}
```

### 5. Implement Database Layer

**Location**: `satellite/satellitedb/fcmtokens.go`

Implement the DB interface using dbx generated code, following the pattern of `satellite/satellitedb/users.go`.

## FCM Service

### 6. Create FCM Service Package

**Location**: `satellite/console/pushnotifications/service.go`

**Service Structure**:

```go
package pushnotifications

import (
    "context"
    "firebase.google.com/go/v4/messaging"
    "go.uber.org/zap"
    "storj.io/common/uuid"
)

// Config contains FCM configuration
type Config struct {
    Enabled          bool   `help:"enable FCM push notifications" default:"false"`
    ProjectID        string `help:"Firebase project ID" default:""`
    CredentialsPath  string `help:"path to Firebase service account credentials JSON" default:""`
    CredentialsJSON  string `help:"Firebase credentials as JSON string (alternative to path)" default:""`
}

// Service handles FCM push notification operations
type Service struct {
    log     *zap.Logger
    db      DB
    client  *messaging.Client
    config  Config
    enabled bool
}

// NewService creates a new FCM service
func NewService(log *zap.Logger, db DB, config Config) (*Service, error)

// SendNotification sends a push notification to a user
// This is the main function that will be called to send notifications
func (s *Service) SendNotification(ctx context.Context, userID uuid.UUID, notification Notification) error

// SendNotificationToToken sends a push notification to a specific token
func (s *Service) SendNotificationToToken(ctx context.Context, token string, notification Notification) error

// SendNotificationToMultipleTokens sends to multiple tokens (batch)
func (s *Service) SendNotificationToMultipleTokens(ctx context.Context, tokens []string, notification Notification) error
```

**Notification Structure**:

```go
type Notification struct {
    Title    string                 `json:"title"`
    Body     string                 `json:"body"`
    Data     map[string]string     `json:"data,omitempty"`
    ImageURL string                 `json:"imageUrl,omitempty"`
    Priority string                 `json:"priority,omitempty"` // "normal" or "high"
}
```

### 7. Implement FCM Client Initialization

**Location**: `satellite/console/pushnotifications/service.go`

- Initialize Firebase Admin SDK
- Create FCM messaging client
- Handle credentials from file or JSON string
- Add proper error handling and logging

### 8. Implement SendNotification Function

**Location**: `satellite/console/pushnotifications/service.go`

**Implementation Details**:

- Retrieve all active FCM tokens for the user from database
- For each token, send FCM message
- Handle invalid tokens (remove from database)
- Log success/failure for each token
- Support batch sending for multiple tokens
- Return error if all tokens fail

## API Endpoints

### 9. Create API Controller

**Location**: `satellite/console/consoleweb/consoleapi/pushnotifications.go`

**Controller Structure**:

```go
package consoleapi

import (
    "net/http"
    "go.uber.org/zap"
    "storj.io/storj/satellite/console"
)

// PushNotifications is an API controller for FCM token management
type PushNotifications struct {
    log     *zap.Logger
    service *console.Service
}

// NewPushNotifications creates a new push notifications controller
func NewPushNotifications(log *zap.Logger, service *console.Service) *PushNotifications

// RegisterToken handles POST /api/v0/push-notifications/tokens
// Saves/registers a new FCM token for the authenticated user
func (p *PushNotifications) RegisterToken(w http.ResponseWriter, r *http.Request)

// UpdateToken handles PUT /api/v0/push-notifications/tokens/:tokenId
// Updates an existing FCM token
func (p *PushNotifications) UpdateToken(w http.ResponseWriter, r *http.Request)

// GetTokens handles GET /api/v0/push-notifications/tokens
// Retrieves all tokens for the authenticated user
func (p *PushNotifications) GetTokens(w http.ResponseWriter, r *http.Request)

// DeleteToken handles DELETE /api/v0/push-notifications/tokens/:tokenId
// Deletes a token
func (p *PushNotifications) DeleteToken(w http.ResponseWriter, r *http.Request)
```

**Request/Response Types**:

```go
// RegisterTokenRequest for POST /api/v0/push-notifications/tokens
type RegisterTokenRequest struct {
    Token       string  `json:"token"`        // Required: FCM token
    DeviceID    *string `json:"deviceId"`     // Optional: device identifier
    DeviceType  *string `json:"deviceType"`   // Optional: "android", "ios", "web"
    AppVersion  *string `json:"appVersion"`   // Optional: app version
    OSVersion   *string `json:"osVersion"`    // Optional: OS version
    DeviceModel *string `json:"deviceModel"`  // Optional: device model
    BrowserName *string `json:"browserName"`  // Optional: browser name (web only)
    UserAgent   *string `json:"userAgent"`    // Optional: full user agent string
    // Note: ip_address is extracted from request on server side, not from client
}

// UpdateTokenRequest for PUT /api/v0/push-notifications/tokens/:tokenId
type UpdateTokenRequest struct {
    Token       *string `json:"token"`
    DeviceID    *string `json:"deviceId"`
    DeviceType  *string `json:"deviceType"`
    AppVersion  *string `json:"appVersion"`
    OSVersion   *string `json:"osVersion"`
    DeviceModel *string `json:"deviceModel"`
    BrowserName *string `json:"browserName"`
    UserAgent   *string `json:"userAgent"`
    IsActive    *bool   `json:"isActive"`
}
```

### 10. Register API Routes

**Location**: `satellite/console/consoleweb/server.go`

Add route registration in `NewServer` function:

```go
// Push Notifications API
pushNotificationsController := consoleapi.NewPushNotifications(logger, service)
pushNotificationsRouter := router.PathPrefix("/api/v0/push-notifications").Subrouter()
pushNotificationsRouter.Use(server.withCORS)
pushNotificationsRouter.Use(server.withAuth)

pushNotificationsRouter.Handle("/tokens", http.HandlerFunc(pushNotificationsController.RegisterToken)).Methods(http.MethodPost, http.MethodOptions)
pushNotificationsRouter.Handle("/tokens/{tokenId}", http.HandlerFunc(pushNotificationsController.UpdateToken)).Methods(http.MethodPut, http.MethodOptions)
pushNotificationsRouter.Handle("/tokens", http.HandlerFunc(pushNotificationsController.GetTokens)).Methods(http.MethodGet, http.MethodOptions)
pushNotificationsRouter.Handle("/tokens/{tokenId}", http.HandlerFunc(pushNotificationsController.DeleteToken)).Methods(http.MethodDelete, http.MethodOptions)
```

## Service Integration

### 11. Integrate FCM Service into Console Service

**Location**: `satellite/console/service.go`

- Add `pushNotificationService` field to `Service` struct
- Initialize in `NewService` constructor
- Expose `SendPushNotification` method on console.Service

### 12. Add Configuration

**Location**: `satellite/console/consoleweb/config.go`

Add FCM configuration to `Config` struct:

```go
type Config struct {
    // ... existing fields
    PushNotifications pushnotifications.Config
}
```

## Dependencies

### 13. Update go.mod

**Location**: `go.mod`

Add Firebase Admin SDK dependency:

```
firebase.google.com/go/v4 v4.12.0
```

## Testing

### 14. Create Unit Tests

**Locations**:

- `satellite/console/pushnotifications/service_test.go`
- `satellite/console/consoleweb/consoleapi/pushnotifications_test.go`
- `satellite/satellitedb/fcmtokens_test.go`

## Important Implementation Notes

1. **Token Array Storage**: The `RegisterToken` API will accept an array of tokens and save each with the same user_id
2. **Token Deduplication**: Check if token already exists before inserting (by token value)
3. **Invalid Token Handling**: Remove tokens that FCM reports as invalid
4. **Error Handling**: Proper error responses for invalid requests, authentication failures
5. **Logging**: Comprehensive logging for debugging and monitoring
6. **Security**: Validate user ownership of tokens in update/delete operations
7. **Batch Operations**: Support registering multiple tokens in a single API call
8. **IP Address Extraction**: Extract client IP address from HTTP request headers (X-Forwarded-For, X-Real-IP, or RemoteAddr) on server side
9. **Optional Fields**: All new fields (os_version, device_model, browser_name, user_agent, ip_address) are optional and nullable
10. **Data Validation**: Validate and sanitize user-provided fields (device_model, browser_name, user_agent) to prevent injection attacks
11. **Retry Count**: `retry_count` is stored in `push_notifications` table only (not in `fcm_tokens`), tracking retry attempts per notification

## Files to Create/Modify

**New Files**:

- `satellite/console/pushnotifications/service.go`
- `satellite/console/pushnotifications/db.go`
- `satellite/console/pushnotifications/types.go`
- `satellite/console/consoleweb/consoleapi/pushnotifications.go`
- `satellite/satellitedb/fcmtokens.go`
- `satellite/satellitedb/pushnotifications.go` (NEW - for tracking sent notifications)

**Modified Files**:

- `satellite/satellitedb/migrate.go` (add migration)
- `satellite/satellitedb/dbx/satellitedb.dbx` (add model)
- `satellite/console/service.go` (integrate service)
- `satellite/console/consoleweb/server.go` (register routes)
- `satellite/console/consoleweb/config.go` (add config)
- `go.mod` (add dependency)
- `satellite/satellitedb/testdata/postgres.v290.sql` (test migration for fcm_tokens)
- `satellite/satellitedb/testdata/postgres.v291.sql` (test migration for push_notifications)

### To-dos

**Status Check**: ✅ Implementation Complete - All core functionality implemented. Only unit tests remaining.

- [x] Create database migration for fcm_tokens table with proper indexes (version 290)
- [x] Create database migration for push_notifications table with proper indexes (version 291)
- [x] Add fcm_tokens model definition to satellitedb.dbx file (include all fields: os_version, device_model, browser_name, user_agent, ip_address) - **Note: Already existed in notification.dbx**
- [x] Create DB interface in satellite/console/pushnotifications/db.go
- [x] Implement database layer in satellite/satellitedb/fcmtokens.go using dbx
- [x] Create FCM service package with Firebase Admin SDK integration
- [x] Implement SendNotification function that retrieves user tokens and sends FCM messages
- [x] Create API controller for token management (register, update, get, delete) with all optional fields
- [x] Register API routes in server.go with proper middleware (CORS, auth)
- [x] Integrate FCM service into console.Service and expose SendPushNotification method
- [x] Add FCM configuration to config.go and wire it through the system
- [x] Add Firebase Admin SDK dependency to go.mod (firebase.google.com/go/v4 v4.18.0)
- [x] Implement IP address extraction from HTTP request headers in API controller
- [ ] Create unit tests for service, API controller, and database layer

## Implementation Status

### ✅ Completed Components

1. **Database Layer**:
   - ✅ Migrations created (v290 for fcm_tokens, v291 for push_notifications)
   - ✅ DBX models exist in `satellite/satellitedb/dbx/notification.dbx`
   - ✅ DB interface defined in `satellite/console/pushnotifications/db.go`
   - ✅ Database implementation in `satellite/satellitedb/fcmtokens.go`
   - ✅ Added to ConsoleDB in `satellite/satellitedb/consoledb.go`
   - ✅ Added to console.DB interface in `satellite/console/database.go`

2. **FCM Service**:
   - ✅ Service package created in `satellite/console/pushnotifications/service.go`
   - ✅ Firebase Admin SDK integration with proper credential handling
   - ✅ SendNotification, SendNotificationToToken, SendNotificationToMultipleTokens methods implemented
   - ✅ Invalid token handling and cleanup
   - ✅ Configuration structure defined

3. **API Layer**:
   - ✅ API controller in `satellite/console/consoleweb/consoleapi/pushnotifications.go`
   - ✅ RegisterToken, UpdateToken, GetTokens, DeleteToken endpoints
   - ✅ IP address extraction from request headers (X-Forwarded-For, X-Real-IP, RemoteAddr)
   - ✅ Token deduplication on registration
   - ✅ User ownership validation
   - ✅ Routes registered in `satellite/console/consoleweb/server.go` with CORS and auth middleware

4. **Integration**:
   - ✅ FCM service integrated into `console.Service`
   - ✅ GetFCMTokens() and SendPushNotification() methods exposed
   - ✅ Configuration added to `satellite/console/config.go`
   - ✅ Service initialized in `console.NewService()`

5. **Dependencies**:
   - ✅ Firebase Admin SDK added (firebase.google.com/go/v4 v4.18.0)
   - ✅ All required dependencies resolved

### ✅ Push Notification Tracking (NEWLY IMPLEMENTED)

1. **Database Layer for Push Notifications**:
   - ✅ `PushNotificationRecord` type added to `satellite/console/pushnotifications/types.go`
   - ✅ `PushNotificationDB` interface added to `satellite/console/pushnotifications/db.go`
   - ✅ Database implementation in `satellite/satellitedb/pushnotifications.go`
   - ✅ Added `PushNotifications()` getter to ConsoleDB and console.DB interface

2. **Service Integration**:
   - ✅ Service updated to accept `PushNotificationDB` parameter
   - ✅ `SendNotification` now creates notification records before sending
   - ✅ Tracks status: "pending" → "sent" or "failed"
   - ✅ Stores error messages for failed notifications
   - ✅ Updates `sent_at` timestamp on successful delivery
   - ✅ One record per token (allows tracking individual delivery status)

3. **Console Service**:
   - ✅ `GetPushNotifications()` method added to `console.Service`
   - ✅ Service initialization updated to pass `PushNotificationDB`

### ⏳ Remaining Tasks

- [ ] Create unit tests:
  - [ ] `satellite/console/pushnotifications/service_test.go`
  - [ ] `satellite/console/consoleweb/consoleapi/pushnotifications_test.go`
  - [ ] `satellite/satellitedb/fcmtokens_test.go`
  - [ ] `satellite/satellitedb/pushnotifications_test.go`
- [ ] Create test migration files (optional):
  - [ ] `satellite/satellitedb/testdata/postgres.v290.sql`
  - [ ] `satellite/satellitedb/testdata/postgres.v291.sql`

### 📝 Implementation Notes

- **DBX Models**: The fcm_tokens and push_notifications models were already defined in `satellite/satellitedb/dbx/notification.dbx`, so no additional model definition was needed.
- **Firebase Initialization**: Uses `google.golang.org/api/option` package for credential configuration (WithCredentialsFile, WithCredentialsJSON).
- **Token Management**: RegisterToken endpoint checks for existing tokens and updates them instead of creating duplicates.
- **Error Handling**: Comprehensive error handling with proper HTTP status codes and error messages.
- **Security**: All endpoints require authentication via `withAuth` middleware, and token ownership is validated for update/delete operations.