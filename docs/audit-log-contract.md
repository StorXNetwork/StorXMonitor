# Audit Log Contract

`contract_version: 13`

## Overview

User activity log matching the **System Audit Logs** UI: who did what, on which resource, from where, with a human-readable outcome message and status.

## Table schema

| Column | UI column | Description |
|--------|-----------|-------------|
| `id` | (search) | Record ID |
| `timestamp` | TIMESTAMP | When it happened |
| `actor_id` | — | Console user ID (`users.id`, server-side filter) |
| `action` | ACTION | Action code (e.g. `GB_JOB_CREATE`) |
| `resource` | RESOURCE | What was affected |
| `message` | MESSAGE | **Required** human-readable outcome (error text or success text) |
| `ip_address` | IP ADDRESS | Client IP |
| `status` | STATUS | Outcome: `success` or `failed` |

## Status values

| Status | When to use |
|--------|-------------|
| `success` | Operation completed successfully |
| `failed` | Any failure (error text goes in `message`) |

Only `success` and `failed` are stored and returned.

## Write path

**Controllers only.** HTTP handlers in `satellite/console/consoleweb/consoleapi/` call audit helpers after the service method returns. Service business logic must not call `RecordUserAudit*`.

Each handler sets its own success message. Pass `err` from the operation.

- **Success** (`err == nil`, HTTP 2xx) → `successMessage` + `success`
- **Failure** (`err != nil`) → `err.Error()` + `failed`
- **HTTP failure** → error from response body, or `request failed (HTTP n)` + `failed`

```go
// Authenticated route (user in context)
result, err := d.service.CreateDomain(ctx, payload)
d.service.RecordUserAudit(ctx, "DOMAIN_CREATE", "Domain", "Domain created", err)

// User known by email (login) — records success and failed attempts when a matching account exists
a.service.RecordUserAuditForEmail(ctx, email, "AUTH_LOGIN", "Session", "User logged in", err)

// Backup-Tools / HTTP proxy
g.service.RecordUserAuditHTTP(ctx, "GB_JOB_CREATE", "Auto-sync job", "Auto-sync job created", status, body, err)
```

### Service methods (`audit_activity.go`)

| Method | Use when |
|--------|----------|
| `RecordUserAudit(ctx, action, resource, successMessage, err)` | Authenticated routes |
| `RecordUserAuditForUser(ctx, user, action, resource, successMessage, err)` | User already loaded |
| `RecordUserAuditForEmail(ctx, email, action, resource, successMessage, err)` | Login / email-based flows (resolves verified, unverified, or pending-verification accounts) |
| `RecordUserAuditHTTP(ctx, action, resource, successMessage, httpStatus, body, err)` | Backup-Tools / HTTP proxy |

Call these from HTTP controllers only; do not invoke from other service business logic. One route may log multiple actions (e.g. `GB_JOB_CREATE` then `GB_ONBOARDING_COMPLETE` when the controller checks the response).

## Action codes

### Auth & account
`AUTH_LOGIN`, `AUTH_LOGOUT`, `AUTH_ACTIVATE`, `AUTH_RESET_PASSWORD`, `AUTH_GOOGLE_BACKUP`, `AUTH_REFRESH_SESSION`, `AUTH_INVALIDATE_SESSION`, `ACCOUNT_UPDATE`, `ACCOUNT_INFO_UPDATE`, `ACCOUNT_SETUP`, `ACCOUNT_SETTINGS_UPDATE`, `ACCOUNT_CHANGE_PASSWORD`, `ACCOUNT_CHANGE_EMAIL`, `ACCOUNT_DELETE_REQUEST`, `ACCOUNT_DELETE`

### MFA
`MFA_ENABLE`, `MFA_DISABLE`, `MFA_GENERATE_SECRET`, `MFA_REGENERATE_RECOVERY`

### Projects
`PROJECT_CREATE`, `PROJECT_UPDATE`, `PROJECT_DELETE`, `PROJECT_LIMITS_UPDATE`, `PROJECT_LIMIT_INCREASE`, `PROJECT_INVITE`, `PROJECT_REINVITE`, `PROJECT_INVITATION_RESPOND`, `PROJECT_MEMBER_UPDATE`, `PROJECT_MEMBERS_DELETE`

### API keys
`API_KEY_CREATE`, `API_KEY_DELETE`, `REST_KEY_CREATE`, `REST_KEY_REVOKE`

### Google Backup
`GB_CONNECT`, `GB_JOB_CREATE`, `GB_JOB_UPDATE`, `GB_POLICY_UPDATE`, `GB_POLICY_MERGE`, `GB_ONBOARDING_COMPLETE`, `GB_RESTORE_AUTH`, `GB_RESTORE_INITIATED`, `GB_RESTORE_CANCEL`, `GB_MANUAL_RESTORE`

### Domains, buckets, payments
`DOMAIN_CREATE`, `DOMAIN_DELETE`, `DOMAIN_CHECK_DNS`, `BUCKET_MIGRATION_UPDATE`, `BUCKET_IMMUTABILITY_UPDATE`, `PAYMENT_GENERATE_LINK`

### Notifications & OAuth
`NOTIFICATION_PREF_UPDATE`, `NOTIFICATION_DISMISS`, `NOTIFICATION_READ_ALL`, `FCM_TOKEN_REGISTER`, `FCM_TOKEN_UPDATE`, `FCM_TOKEN_DELETE`, `OAUTH2_REQUEST`, `OAUTH2_CONSENT`, `DEVELOPER_ACCESS_REVOKE`

## Read APIs

| Endpoint | Description |
|----------|-------------|
| `GET /api/v0/audit-logs` | List user's logs |
| `GET /api/v0/audit-logs/actions` | Distinct action names for filter dropdown |
| `GET /api/v0/audit-logs/export` | CSV export (includes `message` column) |

API responses include `actor` and `actor_email` joined from the `users` table at read time (not stored in `audit_logs`).

**Not logged:** GET/read routes and audit-log list/export APIs.
