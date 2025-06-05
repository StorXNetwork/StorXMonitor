# Work Plan: Implement OAuth2 Token Exchange Endpoint (`/oauth2/token`)

This document details the implementation plan for the `/oauth2/token` endpoint, which allows an external application to exchange a one-time authorization code for a **Storj access grant** for a user, based on approved scopes.

---

## 1. Requirement & Contract

- **Purpose:**  
  Allow an external application to exchange a valid, unexpired authorization code (from consent flow) for a **Storj access grant** for the user, scoped to the approved permissions.
- **Endpoint:**  
  `POST /api/v0/oauth2/token`
- **Input:**  
  ```json
  {
    "client_id": "string",
    "client_secret": "string",
    "redirect_uri": "string",
    "code": "string",
    "passphrase": "string"
  }
  ```
- **Output (success):**
  ```json
  {
    "access_grant": "string", // Storj access grant (capability token)
    "scopes": ["read", "write"]
  }
  ```
- **Output (error):**
  ```json
  {
    "error": "invalid_code"
  }
  ```
- **Timeout:**  
  Code expires after 30 seconds and can be used only once.

---

## 2. Database Layer

- **Table:** `oauth2_requests` (reuse from previous steps)
- **Fields Used/Updated:**
  - `id`, `client_id`, `code`, `status`, `approved_scopes`, `user_id`, `expires_at`
- **DBX Methods:**
  - `read one ( select oauth2_request where oauth2_request.code = ? )`
  - `update oauth2_request ( where oauth2_request.id = ? )` (to mark code as used)
- **Repository Interface:**
  - `GetByCode(ctx, code string) (*OAuth2Request, error)`
  - `MarkCodeUsed(ctx, id uuid.UUID) error`
- **Implementation Note:**  
  - Mark code as used atomically to prevent race conditions (e.g., double-spend).

---

## 3. Service Layer: Access Grant Generation (Expanded)

- **User/Project/API Key:**
  1. Use the `user_id` from the OAuth2 request (not email).
  2. Fetch all projects for the user.
     - If none, return an error.
  3. Use the first project (or apply business logic for selection).
  4. Create a new API key for the project, with a name like `"OAUTH2_API_KEY_FOR_<client_id>_<request_id>"`.
     - Optionally, check for an existing key with this name to avoid duplicates.

- **Access Grant:**
  5. Call `CreateAccessGrantForProject` with:
     - The user context
     - The selected project ID
     - (Optional) Passphrase (can be omitted or set to a fixed value for OAuth2)
     - The new API key
     - The approved scopes from the OAuth2 request (ensure these are enforced in the grant)
  6. Return the access grant string, the scopes, and the expiry.

- **Security:**
  - Ensure the access grant is scoped to the approved permissions.
  - Audit log the issuance.
  - Handle errors for missing user, project, or API key.

- **Pseudocode Example:**

```go
user, err := s.store.Users().GetByID(ctx, oauth2Req.UserID)
if err != nil { return error }
projects, err := s.store.Projects().ListByUser(ctx, user.ID)
if len(projects) == 0 { return error }
project := projects[0]
apiKey, err := s.store.APIKeys().Create(ctx, project.ID, "OAUTH2_API_KEY_FOR_"+clientID)
if err != nil { return error }
accessGrant, err := s.CreateAccessGrantForProject(ctx, project.ID, "", nil, nil, apiKey, approvedScopes)
if err != nil { return error }
return accessGrant
```

---

## 4. Controller Layer

- **Handler:**  
  `func (a *OAuth2API) ExchangeOAuth2Code(w http.ResponseWriter, r *http.Request)`
  - Parse/validate input.
  - Call the service.
  - Return JSON response with `access_grant`, `scopes`, and `expires_in`.

---

## 5. Route Registration

- **File:** `satellite/console/consoleweb/server.go`
- **Route:**
  ```go
  oauth2Router.Handle("/token", http.HandlerFunc(oauth2API.ExchangeOAuth2Code)).Methods(http.MethodPost, http.MethodOptions)
  ```
  - Place this under the `/api/v0/oauth2` router setup, grouped with other OAuth2 endpoints.

---

## 6. Example curl Request

```sh
curl -X POST \
  http://localhost:10100/api/v0/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "redirect_uri": "https://your-app/callback",
    "code": "AUTH_CODE",
    "passphrase": "your-passphrase"
  }'
```
- **Response:**
  ```json
  {
    "access_grant": "1A...<redacted>...==",
    "scopes": ["read", "write"],
    "expires_in": 3600
  }
  ```

---

## 7. Security & Best Practices

- **Access grant is scoped** to the approved permissions and user.
- **Code can only be used once** (atomic update).
- **All actions are audit-logged**.
- **Rate limiting** on this endpoint.
- **No sensitive info in error messages**.
- **Project/API key selection** should be deterministic and secure.
- **If user has no project/API key, return a clear error.**
- **PKCE**: If supported, validate code_verifier (future-proof).
- **CORS/CSRF**: Not needed for server-to-server, but document for completeness.

---

## 8. Table-Driven Testing

- Valid/invalid client credentials.
- Valid/invalid/expired/used code.
- Redirect URI mismatch.
- No approved scopes.
- User with/without project/API key.
- API key creation failure.
- Access grant creation failure.
- Duplicate API key name handling.
- Success and all error paths.

---

## 9. Implementation Notes

- **Reuse** the logic from `APIKeys.GetAccessGrantForDeveloper` for access grant generation.
- **Inject** the correct user, project, and scopes.
- **Do not** return raw S3 credentials; only the access grant.
- **Audit log** all sensitive actions.

---

## 10. Current Status

- **Service Layer:** ✅ Implemented
- **Controller Layer:** ✅ Implemented
- **Route Registration:** ✅ Implemented
- **Testing:** ❌ Pending