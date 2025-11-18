# Developer Package Structure

This package implements the developer console server and all developer-related functionality.

## Package Organization

### Core Files

#### `service.go`
- **Purpose**: Core service definition and initialization
- **Key Components**:
  - `Service` struct - Main business logic service
  - `NewService` / `NewServiceWithMail` - Service constructors
  - Error definitions and constants
  - Audit logging helpers
  - Utility functions (generateRandomSecret, hashSecret)

#### `functions.go`
- **Purpose**: Developer CRUD operations and authentication logic
- **Key Functions**:
  - `CreateDeveloper` - Create new developer account
  - `TokenDeveloper` - Authenticate and generate session token
  - `TokenAuthForDeveloper` - Validate session token
  - `VerifyTokenForDeveloper` - Verify JWT token from email
  - `ResetPasswordWithToken` - Reset password using JWT token
  - `UpdateAccountDeveloper` - Update developer profile
  - `ChangePasswordDeveloper` - Change password
  - OAuth client management (Create, List, Delete, Update)
  - Admin functions (CreateDeveloperAdmin, UpdateDeveloperAdmin, DeleteDeveloperAdmin)

#### `server.go`
- **Purpose**: HTTP server setup and routing
- **Key Components**:
  - `Server` struct - HTTP server instance
  - `NewServer` - Server initialization
  - `Config` - Server configuration
  - `DB` interface - Database abstraction
  - Middleware: `withCORS`, `withAuthDeveloper`
  - Static file serving and SPA routing
  - Rate limiting setup

#### `auth_controller.go`
- **Purpose**: HTTP request handlers for developer authentication endpoints
- **Key Handlers**:
  - `Token` - Login endpoint
  - `Register` - Signup endpoint
  - `GetAccount` - Get developer account info
  - `UpdateAccount` - Update account
  - `ChangePassword` - Change password
  - `Logout` - Logout endpoint
  - `VerifyResetToken` - Verify JWT token from email
  - `ResetPasswordWithToken` - Reset password via email link
  - `ResetPasswordAfterFirstLogin` - Reset password after first login
  - `ActivateAccount` - Activate account with code
  - `RefreshSession` - Refresh session token
  - OAuth client endpoints

#### `admin_functions.go`
- **Purpose**: Admin-only functions for managing developers
- **Key Functions**:
  - `GetAllDevelopersAdmin` - List all developers with stats (pagination, filtering)
  - `GetDeveloperStatsAdmin` - Get aggregated statistics
  - `GetDeveloperDetailsAdmin` - Get developer details with login history
- **Note**: These are used by the admin server (`satellite/admin/developer.go`)

#### `adapter.go`
- **Purpose**: Adapter for registration token checking
- **Key Components**:
  - `ConsoleServiceAdapter` - Adapts console.DB to RegistrationTokenChecker interface
  - Used for validating registration tokens during signup

## API Endpoints

All endpoints are prefixed with `/api/v0/developer/auth`:

- `POST /token` - Login
- `POST /register` - Signup
- `GET /account` - Get account (authenticated)
- `PATCH /account` - Update account (authenticated)
- `POST /account/change-password` - Change password (authenticated)
- `POST /logout` - Logout (authenticated)
- `GET /verify-reset-token?token=xxx` - Verify JWT token
- `POST /reset-password-with-token` - Reset password with token
- `POST /reset-password-after-login` - Reset password after first login (authenticated)
- `PATCH /code-activation` - Activate account with code
- `POST /refresh-session` - Refresh session (authenticated)
- `POST /oauth2/clients` - Create OAuth client (authenticated)
- `GET /oauth2/clients` - List OAuth clients (authenticated)
- `DELETE /oauth2/clients/{id}` - Delete OAuth client (authenticated)
- `PATCH /oauth2/clients/{id}/status` - Update OAuth client status (authenticated)

## Architecture

```
┌─────────────────────────────────┐
│  Developer Console UI (SPA)     │
└──────────────┬──────────────────┘
               │
               │ HTTP Requests
               ▼
┌─────────────────────────────────┐
│  developer/server.go             │
│  - HTTP Server                  │
│  - Routing & Middleware          │
│  - Static File Serving           │
└──────────────┬──────────────────┘
               │
               │ Uses
               ▼
┌─────────────────────────────────┐
│  developer/auth_controller.go    │
│  - Request Handlers              │
│  - Input Validation              │
│  - Response Formatting            │
└──────────────┬──────────────────┘
               │
               │ Calls
               ▼
┌─────────────────────────────────┐
│  developer/service.go            │
│  - Business Logic                │
│  - Authentication                │
│  - Session Management            │
└──────────────┬──────────────────┘
               │
               │ Uses
               ▼
┌─────────────────────────────────┐
│  developer/functions.go          │
│  - Database Operations           │
│  - Password Hashing              │
│  - Token Generation              │
└─────────────────────────────────┘
```

## Key Features

1. **Authentication & Authorization**
   - JWT token-based authentication
   - Session management with expiration
   - Cookie-based auth for web clients
   - Rate limiting (IP-based and UserID-based)

2. **Account Management**
   - Developer registration with email verification
   - Password reset via email link (JWT token)
   - Account activation with activation code
   - Profile updates

3. **Security**
   - Password hashing (bcrypt)
   - Bad password list checking
   - Account lockout after failed login attempts
   - CORS support
   - Audit logging

4. **OAuth2 Client Management**
   - Create, list, delete OAuth clients
   - Client status management
   - Secure client secret generation

## Dependencies

- `satellite/console` - Console database and types
- `satellite/analytics` - Analytics tracking
- `satellite/mailservice` - Email sending
- `satellite/console/consoleauth` - Token signing/verification
- `satellite/console/consoleweb/consolewebauth` - Cookie authentication

## Notes

- `CreateUserFromDeveloper` in `functions.go` is currently unused but kept for potential future use
- Admin functions in `admin_functions.go` are used by the admin server, not the developer server
- The server supports both embedded static assets and file system-based assets
- All endpoints support CORS for cross-origin requests

