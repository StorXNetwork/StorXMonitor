# Work Plan: Implement OAuth2 Access Request Endpoint (`/oauth2/request`)

**Progress Checklist:**
- [x] Database Layer (schema, migration)
- [x] Database Helper & Interface Changes
- [ ] Repository Layer
- [ ] Service Layer
- [ ] Controller Layer
- [ ] Router Entry
- [ ] Curl Example
- [ ] Testing
- [ ] Security & Integration

This document details the implementation plan for the `/oauth2/request` endpoint, which creates and tracks an OAuth2 access request for a user, validating the client, redirect URI, and requested scopes.

---

## 1. Requirement & Contract

- **Purpose:**  
  Allow a user (authenticated via session/cookie) to initiate an OAuth2 access request for a third-party app, validating the client, redirect URI, and requested scopes, and returning a `request_id` for consent.
- **Endpoint:**  
  `POST /api/v0/oauth2/request`
- **Input:**  
  ```json
  {
    "client_id": "string",
    "redirect_uri": "string",
    "scope": ["read", "write", ...]
  }
  ```
- **Output (success):**
  ```json
  {
    "request_id": "uuid",
    "current_access": ["read"],
    "needed_access": ["write"],
    "required_scopes": ["read"],
    "optional_scopes": ["write"]
  }
  ```
- **Output (error):**
  ```json
  {
    "error": "invalid_client_id"
  }
  ```
- **Timeout:**  
  Request expires after 1 minute.

---

## 2. Database Layer

- **Table:** `oauth2_requests`
- **Schema:**
  | Field         | Type    | Description                        |
  |---------------|---------|------------------------------------|
  | id            | UUID PK | Request ID                         |
  | client_id     | TEXT    | FK to developer_oauth_clients      |
  | user_id       | UUID    | FK to users                        |
  | redirect_uri  | TEXT    | Redirect URI                       |
  | scopes        | TEXT    | JSON array of requested scopes     |
  | status        | INT     | (pending, approved, rejected, etc) |
  | created_at    | TIMESTAMP | Creation time                    |
  | expires_at    | TIMESTAMP | Expiry time (created_at + 1 min) |
  | code          | TEXT    | Authorization code (nullable)      |
  | approved_scopes | TEXT  | JSON array of approved scopes      |
  | rejected_scopes | TEXT  | JSON array of rejected scopes      |

- **DBX Model Example:**
  ```
  model oauth2_request (
      key id
      index ( fields client_id )
      index ( fields user_id )
      field id blob
      field client_id text
      field user_id blob
      field redirect_uri text
      field scopes text
      field status int
      field created_at timestamp ( autoinsert )
      field expires_at timestamp
      field code text
  )
  ```
- **DBX Methods:**
  - `create oauth2_request ( )`
  - `update oauth2_request ( where oauth2_request.id = ? )`
  - `read one ( select oauth2_request where oauth2_request.id = ? )`
  - `delete oauth2_request ( where oauth2_request.expires_at < now() )` (for cleanup)

- **Migration:**  
  Migration for this table has been added to `satellitedb/migrate.go` as version 284:
  ```sql
  CREATE TABLE oauth2_requests (
    id bytea NOT NULL,
    client_id text NOT NULL,
    user_id bytea NOT NULL,
    redirect_uri text NOT NULL,
    scopes text NOT NULL,
    status integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    code text NOT NULL,
    approved_scopes text NOT NULL,
    rejected_scopes text NOT NULL,
    PRIMARY KEY ( id )
  );
  ```

**Status:** ✅ Complete (schema and migration defined)

---

## 2.1. Database Helper & Interface Changes

- **Update `satellite/console/database.go`:**
  - Add a new repository getter to the `DB` interface:
    ```go
    // OAuth2Requests is a getter for OAuth2Requests repository.
    OAuth2Requests() OAuth2Requests
    ```
- **Add new interface:**
  - Create a new `OAuth2Requests` interface (in `satellite/console/oauth2_requests.go`), similar to `Users` in `users.go`:
    ```go
    type OAuth2Requests interface {
        Insert(ctx context.Context, req *OAuth2Request) (*OAuth2Request, error)
        Get(ctx context.Context, id uuid.UUID) (*OAuth2Request, error)
        UpdateStatus(ctx context.Context, id uuid.UUID, status int, code string) error
        DeleteExpired(ctx context.Context) error
        // Add other methods as needed for consent/token flows
    }
    ```
- **Implementation:**
  - Implement the interface in a new file: `satellitedb/oauth2_requests.go`.
  - Use DBX-generated methods for all DB operations, with conversion helpers for DBX <-> domain structs.

---

## 3. Repository Layer

- **File:** `satellitedb/oauth2_requests.go`
- **Methods:**
  - `InsertOAuth2Request(ctx, *console.OAuth2Request) (*console.OAuth2Request, error)`
  - `GetOAuth2Request(ctx, id uuid.UUID) (*console.OAuth2Request, error)`
  - `UpdateOAuth2RequestStatus(ctx, id uuid.UUID, status int, code string) error`
  - `DeleteExpiredOAuth2Requests(ctx) error`
- **Conversion helpers** for DBX <-> domain structs.

---

## 4. Service Layer

- **File:** `satellite/console/service.go`
- **Methods:**
  - `CreateOAuth2Request(ctx, req CreateOAuth2Request) (*OAuth2RequestResponse, error)`
    - Validate client_id, redirect_uri, scopes.
    - Check for existing access.
    - Create DB entry, set expiry.
    - Return contract response.
  - `ExpireOAuth2Requests(ctx)` (background cleanup, optional)

- **Structs:**
  ```go
  type CreateOAuth2Request struct {
    ClientID    string
    RedirectURI string
    Scopes      []string
  }
  type OAuth2RequestResponse struct {
    RequestID      uuid.UUID
    CurrentAccess  []string
    NeededAccess   []string
    RequiredScopes []string
    OptionalScopes []string
  }
  ```

---

## 4.1. Service Layer Changes

- **File:** `satellite/console/service.go`
- **Add method to Service struct:**
  ```go
  func (s *Service) CreateOAuth2Request(ctx context.Context, req CreateOAuth2Request) (*OAuth2RequestResponse, error)
  ```
  - Responsibilities:
    - Validate `client_id`, `redirect_uri`, and `scopes`.
    - Check for existing access.
    - Create a new OAuth2 request in the repository.
    - Set expiry and status.
    - Return the contract response.

---

## 5. Controller Layer

- **File:** `satellite/console/consoleweb/consoleapi/oauth2.go`
- **Handler:**
  - `func (a *OAuth2API) CreateOAuth2Request(w http.ResponseWriter, r *http.Request)`
    - Parse/validate input.
    - Call service.
    - Return JSON response or error.

---

## 5.1. Controller Changes

- **File:** `satellite/console/consoleweb/consoleapi/oauth2.go`
- **Add handler:**
  ```go
  func (a *OAuth2API) CreateOAuth2Request(w http.ResponseWriter, r *http.Request)
  ```
  - Responsibilities:
    - Parse and validate the incoming JSON request.
    - Call the service method.
    - Return the JSON response or error.

---

## 6. Route Registration

- **File:** `satellite/console/consoleweb/server.go`
- **Route:**
  ```go
  oauth2Router.Handle("/request", server.withAuth(http.HandlerFunc(oauth2API.CreateOAuth2Request))).Methods(http.MethodPost, http.MethodOptions)
  ```

---

## 6.1. Router Entry in server.go

- **File:** `satellite/console/consoleweb/server.go`
- **Add to oauth2Router setup:**
  ```go
  oauth2Router.Handle("/request", server.withAuth(http.HandlerFunc(oauth2API.CreateOAuth2Request))).Methods(http.MethodPost, http.MethodOptions)
  ```
  - Place this under the `/api/v0/oauth2` router setup, grouped with other OAuth2 endpoints.

---

## 7. Example curl Request

```
curl -X POST \
  http://localhost:10100/api/v0/oauth2/request \
  -H "Content-Type: application/json" \
  -b "_tokenKey=<session_cookie>" \
  -d '{
    "client_id": "your-client-id",
    "redirect_uri": "https://your-app/callback",
    "scope": ["read", "write"]
  }'
```

- Replace `<session_cookie>` with a valid session cookie for an authenticated user.
- Replace `your-client-id` and `https://your-app/callback` with your actual OAuth2 client values.
- The response will be a JSON object with `request_id`, `current_access`, `needed_access`, `required_scopes`, and `optional_scopes` fields, or an error.