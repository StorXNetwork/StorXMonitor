# StorX OAuth2 UI Integration Guide

This document provides a practical, implementation-aligned guide for integrating the StorX OAuth2 flow into the UI. It covers all endpoints, request/response formats, and step-by-step UI actions for a seamless developer and user experience.

---

## 1. OAuth2 Flow Overview

### Actors
- **Developer:** Registers OAuth2 clients (apps)
- **User:** Grants/revokes app access to their StorX account
- **External App:** Uses OAuth2 to access StorX APIs on behalf of the user

---

## 2. Endpoints & Contracts

### 2.1. Developer: Register OAuth2 Client
- **Endpoint:** `POST /api/v0/developer/auth/oauth2/clients`
- **Auth:** Bearer token (developer)
- **Request:**
  ```json
  {
    "name": "My App",
    "redirect_uris": "https://myapp.com/callback"
  }
  ```
- **Response:**
  ```json
  {
    "client_id": "string",
    "client_secret": "string" // Only shown once
  }
  ```
- **Other endpoints:**
  - `GET /api/v0/developer/auth/oauth2/clients` (list)
  - `DELETE /api/v0/developer/auth/oauth2/clients/{id}` (delete)
  - `PATCH /api/v0/developer/auth/oauth2/clients/{id}/status` (update status)

---

### 2.2. User: Initiate OAuth2 Request
- **Endpoint:** `POST /api/v0/oauth2/request`
- **Auth:** Session/cookie (user)
- **Request:**
  ```json
  {
    "client_id": "string",
    "redirect_uri": "string",
    "scope": ["read", "write"]
  }
  ```
- **Response (success):**
  ```json
  {
    "request_id": "uuid",
    "current_access": ["read"],
    "needed_access": ["write"],
    "required_scopes": ["read"],
    "optional_scopes": ["write"]
  }
  ```
- **Response (error):**
  ```json
  {
    "error": "invalid_client_id"
  }
  ```
- **Timeout:** 1 minute

---

### 2.3. User: Consent to Scopes
- **Endpoint:** `POST /api/v0/oauth2/consent`
- **Auth:** Session/cookie (user)
- **Request:**
  ```json
  {
    "request_id": "uuid",
    "approved_scopes": ["read"],
    "rejected_scopes": ["write"]
  }
  ```
- **Response (approved):**
  ```json
  {
    "redirect_uri": "https://app.com/callback?code=AUTH_CODE"
  }
  ```
- **Response (rejected):**
  ```json
  {
    "redirect_uri": "https://app.com/callback?error=access_denied"
  }
  ```
- **Timeout:** Consent within 1 minute, code valid for 30 seconds

---

### 2.4. External App: Exchange Code for Access Grant
- **Endpoint:** `POST /api/v0/oauth2/token`
- **Auth:** None (rate-limited)
- **Request:**
  ```json
  {
    "client_id": "string",
    "client_secret": "string",
    "redirect_uri": "string",
    "code": "string",
    "passphrase": "string" // optional, for access grant encryption
  }
  ```
- **Response (success):**
  ```json
  {
    "access_grant": "string",
    "scopes": ["read", "write"],
    "expires_in": 3600
  }
  ```
- **Response (error):**
  ```json
  {
    "error": "invalid_code"
  }
  ```
- **Timeout:** Code expires after 30 seconds, single use

---

### 2.5. Use Access Grant
- **Purpose:** Use the returned `access_grant` to access StorX APIs (S3, etc.) as permitted by granted scopes.

---

## 3. UI Flow: Step-by-Step

### 3.1. App Registration (Developer Portal)
- Form: Name, Redirect URI(s)
- Show: `client_id`, `client_secret` (copy now, not shown again)

### 3.2. User Authorization
- App redirects user to StorX OAuth2 consent UI
- UI calls `/oauth2/request` → shows consent screen
- On approve/reject, UI calls `/oauth2/consent`
- UI handles redirect to app with code/error

### 3.3. Token Exchange
- App backend exchanges code for access grant via `/oauth2/token`
- App uses access grant for S3 API calls

---

## 4. Error Handling
- All endpoints return JSON error objects:
  ```json
  { "error": "error_code" }
  ```
- UI should display user-friendly messages for known errors.

---

## 5. Security & Timeouts
- **client_secret** is shown only once, store securely.
- **Consent:** Must be given within 1 minute.
- **Code:** Expires after 30 seconds, single use.
- **All endpoints require authentication (except `/token`, which is rate-limited).**
- **All actions are audit-logged.**
- **PKCE is recommended for public clients.**
- **Strict redirect URI validation.**
- **Immediate invalidation of used/expired codes.**
- **Granular scopes, least privilege.**
- **CORS/CSRF protections for browser flows.**
- **Clear error messages, no sensitive info.**
- **Credential rotation and environment separation recommended.**

---

## 6. Example Requests

**Register OAuth2 Client**
```sh
curl -X POST https://<host>/api/v0/developer/auth/oauth2/clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","redirect_uris":"https://myapp.com/callback"}'
```

**Initiate OAuth2 Request**
```sh
curl -X POST https://<host>/api/v0/oauth2/request \
  -H "Content-Type: application/json" \
  -b "_tokenKey=<session_cookie>" \
  -d '{"client_id":"...","redirect_uri":"...","scope":["read","write"]}'
```

**Consent**
```sh
curl -X POST https://<host>/api/v0/oauth2/consent \
  -H "Content-Type: application/json" \
  -b "_tokenKey=<session_cookie>" \
  -d '{"request_id":"...","approved_scopes":["read"],"rejected_scopes":["write"]}'
```

**Token Exchange**
```sh
curl -X POST https://<host>/api/v0/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"...","client_secret":"...","redirect_uri":"...","code":"..."}'
```

---

## 7. API Endpoints Summary

| Method | Path                                         | Purpose                        | Auth         |
|--------|----------------------------------------------|-------------------------------|--------------|
| POST   | `/api/v0/developer/auth/oauth2/clients`      | Register OAuth2 client         | Developer    |
| GET    | `/api/v0/developer/auth/oauth2/clients`      | List OAuth2 clients            | Developer    |
| DELETE | `/api/v0/developer/auth/oauth2/clients/{id}` | Delete OAuth2 client           | Developer    |
| PATCH  | `/api/v0/developer/auth/oauth2/clients/{id}/status` | Update client status   | Developer    |
| POST   | `/api/v0/oauth2/request`                     | Create OAuth2 access request   | User         |
| POST   | `/api/v0/oauth2/consent`                     | Approve/reject scopes          | User         |
| POST   | `/api/v0/oauth2/token`                       | Exchange code for access grant | None (rate-limited) |

---

## 8. Sequence Diagram

```
Developer        User            External App         StorX Backend
    |               |                  |                   |
    |--register---->|                  |                   |
    |<--client_id---|                  |                   |
    |               |                  |                   |
    |               |<--(OAuth2 flow)--|                   |
    |               |                  |--request-------->|
    |               |                  |<--request_id-----|
    |               |<--consent UI---- |                   |
    |               |--consent-------->|                   |
    |               |                  |--consent-------->|
    |               |                  |<--code-----------|
    |               |<--redirect-------|                   |
    |               |                  |                   |
    |               |                  |--token exchange->|
    |               |                  |<--access_grant---|
    |               |                  |                   |
    |               |                  |--S3 API calls--->|
    |               |                  |<--data-----------|
```

---

## 9. What the UI Team Needs to Know

- **All endpoints and request/response formats are stable and documented above.**
- **Consent and code timeouts must be handled in the UI.**
- **Show `client_secret` only once on registration.**
- **Display clear error messages for all error codes.**
- **Use secure storage and transmission for all secrets and tokens.**
- **Follow the sequence: register client → request → consent → token exchange.**
- **Contact backend team for any ambiguity or error not covered here.**

---

> This document is aligned with the current backend implementation. For questions or updates, contact the backend team. 