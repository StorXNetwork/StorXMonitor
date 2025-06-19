# Work Plan: Implement OAuth2 Token Exchange Endpoint (`/oauth2/token`) with JWT-Encoded Client Secret

This document details the implementation plan for the `/oauth2/token` endpoint, where the client authenticates by sending a JWT-encoded `client_id` in the `client_secret` field. The backend validates the JWT using the stored `client_secret` for the given `client_id`, increasing security by never transmitting the secret directly.

---

## 1. Requirement & Contract

- **Purpose:**  
  Allow an external application to exchange a valid, unexpired authorization code (from consent flow) for a **Storj access grant** for the user, using a JWT for client authentication.

- **Endpoint:**  
  `POST /api/v0/oauth2/token`

- **Input:**  
  ```json
  {
    "client_id": "string",
    "client_secret": "jwt-string", // JWT-encoded client_id, signed with client_secret
    "redirect_uri": "string",
    "code": "string",
    "passphrase": "string"
  }
  ```
  - `client_id`: Sent as plain text.
  - `client_secret`: JWT string, signed with the actual client secret. The JWT payload must include:
    - `client_id`: string
    - `exp`: unix timestamp (expiry)
  - `redirect_uri`, `code`, `passphrase`: as before

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
    "error": "invalid_code" // or "client_secret_expired" if JWT is expired
  }
  ```

- **Timeout:**  
  - Code expires after 30 seconds and can be used only once.
  - JWT must not be expired (`exp` claim). If expired, error is `client_secret_expired`.

---

## 2. JWT Client Secret

- **JWT Payload Example:**
  ```json
  {
    "client_id": "your-client-id",
    "exp": 1712345678
  }
  ```
- **JWT is signed using the client_secret as the HMAC key.**
- **Backend:**
  - Parse JWT from `client_secret` field.
  - Extract and verify `client_id` and `exp`.
  - Fetch stored secret for `client_id`.
  - Validate JWT signature.
  - Check `exp` is in the future.

---

## 3. Development Steps

### 3.1. Update API Contract
- Change request body to accept `client_id` and `client_secret` (JWT) as described above.
- Update OpenAPI/specs and documentation.

### 3.2. Controller Layer
- In `/oauth2/token` handler:
  - Parse `client_id` and `client_secret` (JWT).
  - Fetch client from DB using `client_id`.
  - Validate JWT signature using stored `client_secret`.
  - Check JWT payload for correct `client_id` and valid `exp`.
  - If invalid, return `invalid_client` error.
  - If expired, return `jwt_expired` error.
  - Continue with code exchange logic as before.

### 3.3. Service Layer
- Remove direct `client_secret` comparison.
- Add JWT validation logic (see Web3Auth.Token for reference).
- On success, proceed with access grant issuance as before.

### 3.4. Security
- Never log or return the JWT or client_secret.
- Audit log all sensitive actions.
- Rate limit the endpoint.

### 3.5. Testing
- Add table-driven tests for:
  - Valid/invalid JWTs (signature, expiry, payload)
  - Valid/invalid/expired/used code
  - All error and success paths

### 3.6. Example JWT Creation (Client Side)
- Use a JWT library to create a token:
  - Header: `{ "alg": "HS256", "typ": "JWT" }`
  - Payload: `{ "client_id": "...", "exp": ... }`
  - Sign with `client_secret` as HMAC key.

---

## 4. Example curl Request

```sh
# Assume you have generated a JWT and stored it in $JWT
curl -X POST \
  http://localhost:10100/api/v0/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "'$JWT'",
    "redirect_uri": "https://your-app/callback",
    "code": "AUTH_CODE",
    "passphrase": "your-passphrase"
  }'
```

---

## 5. Implementation Notes

- Use the pattern from `Web3Auth.Token` for JWT parsing and validation.
- Use the `client_secret` from the DB as the HMAC key for validation.
- Only allow JWTs with a short expiry (e.g., 1-5 minutes).
- Do not accept JWTs with missing/invalid `client_id` or `exp`.
- If the JWT is expired, the error returned is `client_secret_expired`.

---

## 6. Migration/Deprecation

- If you have existing clients using the old method, consider supporting both for a transition period, or require all clients to update.

---

## 7. Summary of Required Changes

- [ ] Update API contract and documentation
- [ ] Update controller to parse and validate JWT in `client_secret`
- [ ] Update service to use JWT-based client authentication
- [ ] Remove direct client_secret usage from request
- [ ] Add/Update tests for JWT validation and error cases

---

## 8. Table-Driven Testing

- Valid/invalid JWTs (signature, expiry, payload)
- Valid/invalid/expired/used code
- Redirect URI mismatch
- No approved scopes
- User with/without project/API key
- API key creation failure
- Access grant creation failure
- Duplicate API key name handling
- Success and all error paths

---

## 9. Implementation Notes

- **Reuse** the logic from `APIKeys.GetAccessGrantForDeveloper` for access grant generation.
- **Inject** the correct user, project, and scopes.
- **Do not** return raw S3 credentials; only the access grant.
- **Audit log** all sensitive actions.

---

## 10. Current Status

- **Service Layer:** ✅ Implemented (JWT validation, error 'client_secret_expired' for expired JWT)
- **Controller Layer:** ✅ Implemented (accepts JWT in client_secret)
- **Route Registration:** ✅ Implemented
- **Testing:** ❌ Pending