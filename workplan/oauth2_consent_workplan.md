# Work Plan: Implement OAuth2 Consent Endpoint (`/oauth2/consent`)

This document details the implementation plan for the `/oauth2/consent` endpoint, which allows a user to approve or reject requested scopes for an OAuth2 access request, and issues a one-time authorization code if approved.

**Progress Checklist:**
- [x] DBX model/fields present
- [x] Repository interface and implementation
- [x] Service layer (with validation)
- [x] Controller handler
- [x] Route registration

---

## 1. Requirement & Contract

- **Purpose:**  
  Allow a user (authenticated via session/cookie) to approve or reject requested scopes for a pending OAuth2 access request (`request_id`). If approved, issue a one-time authorization code and redirect to the app's redirect URI. If rejected, redirect with an error.
- **Endpoint:**  
  `POST /api/v0/oauth2/consent`
- **Input:**  
  ```json
  {
    "request_id": "uuid",
    "approved_scopes": ["read"],
    "rejected_scopes": ["write"]
  }
  ```
- **Output (success):**
  ```json
  {
    "redirect_uri": "https://app.com/callback?code=AUTH_CODE"
  }
  ```
- **Output (rejected):**
  ```json
  {
    "redirect_uri": "https://app.com/callback?error=access_denied"
  }
  ```
- **Timeout:**  
  Consent must be given within 1 minute of request creation. Code expires after 30 seconds.

---

## 2. Database Layer

- **Table:** `oauth2_requests` (reuse from /request)
- **Fields Used/Updated:**
  - `id`, `status`, `code`, `expires_at`, `approved_scopes`, `rejected_scopes`
- **Schema Additions:**
  - Add `approved_scopes` and `rejected_scopes` fields (TEXT, JSON array) if not present.
- **DBX Model Example (additions):**
  ```
  model oauth2_request (
      ...
      field approved_scopes text
      field rejected_scopes text
  )
  ```
- **DBX Methods:**
  - `update oauth2_request ( where oauth2_request.id = ? )`
  - `read one ( select oauth2_request where oauth2_request.id = ? )`

- **Migration:**  
  Add migration to add new fields if needed.

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
        UpdateConsent(ctx context.Context, id uuid.UUID, approvedScopes, rejectedScopes []string, code string, status int) error
        GetByCode(ctx context.Context, code string) (*OAuth2Request, error)
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
  - `UpdateOAuth2Consent(ctx, id uuid.UUID, approvedScopes, rejectedScopes []string, code string, status int) error`
  - `GetOAuth2Request(ctx, id uuid.UUID) (*console.OAuth2Request, error)`

---

## 4. Service Layer

- **File:** `satellite/console/service.go`
- **Methods:**
  - `ConsentOAuth2Request(ctx, req ConsentOAuth2Request) (*ConsentOAuth2Response, error)`
    - Validate request_id, check expiry and status.
    - If approved, generate code, update DB, set expiry (30s), return redirect URI with code.
    - If rejected, update DB, return redirect URI with error.

- **Structs:**
  ```go
  type ConsentOAuth2Request struct {
    RequestID      uuid.UUID
    ApprovedScopes []string
    RejectedScopes []string
  }
  type ConsentOAuth2Response struct {
    RedirectURI string
  }
  ```

---

## 4.1. Service Layer Changes

- **File:** `satellite/console/service.go`
- **Add method to Service struct:**
  ```go
  func (s *Service) ConsentOAuth2Request(ctx context.Context, req ConsentOAuth2Request) (*ConsentOAuth2Response, error)
  ```
  - Responsibilities:
    - Validate `request_id`, check expiry and status.
    - If approved, generate code, update DB, set expiry (30s), return redirect URI with code.
    - If rejected, update DB, return redirect URI with error.

---

## 5. Controller Layer

- **File:** `satellite/console/consoleweb/consoleapi/oauth2.go`
- **Handler:**
  - `func (a *OAuth2API) ConsentOAuth2Request(w http.ResponseWriter, r *http.Request)`
    - Parse/validate input.
    - Call service.
    - Return JSON response or error.

---

## 5.1. Controller Changes

- **File:** `satellite/console/consoleweb/consoleapi/oauth2.go`
- **Add handler:**
  ```go
  func (a *OAuth2API) ConsentOAuth2Request(w http.ResponseWriter, r *http.Request)
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
  oauth2Router.Handle("/consent", server.withAuth(http.HandlerFunc(oauth2API.ConsentOAuth2Request))).Methods(http.MethodPost, http.MethodOptions)
  ```

---

## 6.1. Router Entry in server.go

- **File:** `satellite/console/consoleweb/server.go`
- **Add to oauth2Router setup:**
  ```go
  oauth2Router.Handle("/consent", server.withAuth(http.HandlerFunc(oauth2API.ConsentOAuth2Request))).Methods(http.MethodPost, http.MethodOptions)
  ```
  - Place this under the `/api/v0/oauth2` router setup, grouped with other OAuth2 endpoints.

---

## 7. Example curl Request

```