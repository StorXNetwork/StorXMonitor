# StorX OAuth2 Integration Flow: Abstract Overview

This document provides a high-level, implementation-agnostic overview of the OAuth2 integration flow for StorX. It focuses on the contract, sequence, and integration between the main actors (developer, user, external application, StorX backend), and outlines the required API endpoints and their relationships.

---

## 1. Abstract Requirements & User Stories

- **As a developer**, I want to register my application with StorX and obtain credentials (client_id, client_secret) to enable OAuth2-based access for my users.
- **As a user**, I want to securely grant and manage access to my StorX account for third-party applications, with fine-grained control over permissions (scopes).
- **As an external application**, I want to request access to a user's StorX account, obtain temporary credentials, and use them to interact with StorX resources (e.g., S3 API).

---

## 2. High-Level Flow & API Contracts

### 2.1. Developer Flow: Registering an OAuth2 Client

- **Endpoint:** `POST /api/v0/developer/auth/oauth2/clients`
- **Actor:** Developer (authenticated)
- **Purpose:** Register a new application, receive `client_id` and `client_secret`.
- **Contract:**
  - **Input:** Application name, redirect URIs
  - **Output:** `client_id`, `client_secret` (shown only once)

---

### 2.2. User Flow: OAuth2 Authorization Request

#### Step 1: Initiate OAuth2 Request (Create Access Request)
- **Endpoint:** `POST /api/v0/oauth2/request`
- **Actor:** User (authenticated via cookie/session)
- **Purpose:** Validate `client_id`, `redirect_uri`, and requested scopes, and create an OAuth2 access request entry.
- **Note:** The endpoint is named `/request` (not `/validate`) to reflect that it creates and tracks a new access request, not just validation.
- **Contract:**
  - **Input:** `client_id`, `redirect_uri`, `scope[]`
  - **Output:**
    - If invalid: error message
    - If valid: array of current access, needed access, required/optional scopes, and a `request_id` (tracks the consent request, 1 min timeout)

#### Step 2: User Consent (Approve/Reject Scopes)
- **Endpoint:** `POST /api/v0/oauth2/consent`
- **Actor:** User (via UI, authenticated)
- **Purpose:** User approves/rejects requested scopes for the application.
- **Contract:**
  - **Input:** `request_id`, `approved_scopes[]`, `rejected_scopes[]`
  - **Output:**
    - If approved: redirect to `redirect_uri` with a one-time `code` (30 sec timeout)
    - If rejected: redirect to `redirect_uri` with error

---

### 2.3. External Application: Exchange Code for S3 Credentials

- **Endpoint:** `POST /api/v0/oauth2/token`
- **Actor:** External application (server-to-server)
- **Purpose:** Exchange the one-time `code` for S3 credentials for the user, based on approved scopes.
- **Contract:**
  - **Input:** `client_id`, `client_secret`, `redirect_uri`, `code`
  - **Output:**
    - If valid: S3 credentials (access key, secret, etc.) for the user, with granted scopes
    - If invalid/expired: error

---

### 2.4. External Application: Use S3 Credentials

- **Actor:** External application
- **Purpose:** Use the S3 credentials to access StorX resources on behalf of the user, within the granted scopes (read, upload, delete, etc.).
- **Contract:**
  - **Input:** S3 credentials
  - **Output:** Access to StorX APIs as permitted

---

## 3. Sequence Diagram (Textual)

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
    |               |                  |<--S3 creds-------|
    |               |                  |                   |
    |               |                  |--S3 API calls--->|
    |               |                  |<--data-----------|
```

---

## 4. Security & Timeout Considerations

- **client_secret** is shown only once and must be stored securely by the developer.
- **OAuth2 request** (`request_id`) expires after 1 minute if not completed.
- **Authorization code** expires after 30 seconds and can be used only once.
- **All endpoints require appropriate authentication (developer, user, or app).**
- **S3 credentials** are scoped to the approved permissions and user account.
- **Audit logging** and tracking for all sensitive actions.

---

## 5. Summary of API Contracts

| Endpoint                        | Actor           | Purpose/Contract Summary                |
|---------------------------------|-----------------|-----------------------------------------|
| POST /developer/auth/oauth2/clients | Developer      | Register app, get client_id/secret      |
| POST /oauth2/request            | User            | Create access request, validate app/scopes, get request_id  |
| POST /oauth2/consent            | User            | Approve/reject scopes, get code         |
| POST /oauth2/token              | External App    | Exchange code for S3 credentials        |

---

## 6. Recommendations & Best Practices

- **PKCE (Proof Key for Code Exchange):**
  - Strongly recommend PKCE for public clients (mobile/web apps) to prevent authorization code interception.
- **Rate Limiting & Brute-Force Protection:**
  - Apply rate limiting to sensitive endpoints (`/token`, `/consent`, `/request`) to prevent abuse.
- **Redirect URI Validation:**
  - Strictly validate and log all redirect URIs to prevent open redirect and phishing attacks.
- **Granular Scopes & Least Privilege:**
  - Define scopes as granular as possible; default to least-privilege access.
- **Secret Management:**
  - Store all secrets (client_secret, S3 credentials) securely; never log or expose them.
- **Immediate Invalidation:**
  - Expire and invalidate used or expired codes and requests immediately to prevent replay attacks.
- **Refresh Tokens:**
  - Consider supporting refresh tokens for long-lived access, with revocation and rotation support.
- **Audit Logging:**
  - Log all sensitive actions (consent, token exchange, credential issuance) for traceability.
- **CORS & CSRF Protections:**
  - Implement CORS and CSRF protections for browser-based flows and endpoints.
- **Error Handling:**
  - Return clear, actionable error messages, but avoid leaking sensitive details.
- **Credential Rotation:**
  - Encourage regular review and rotation of client credentials and S3 keys.
- **Environment Separation:**
  - Recommend developers register separate clients for development, staging, and production environments.
- **Security Standards Review:**
  - Regularly review the flow and implementation against the latest OAuth2 and OIDC security best current practices (BCPs).

> Following these recommendations will help ensure a secure, robust, and user-friendly OAuth2 integration for StorX.

---

> This document is a living contract for OAuth2 integration. Implementation details are tracked separately. 