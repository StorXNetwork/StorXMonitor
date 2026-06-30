package consoleweb

// @title StorX Monitor API
// @version 1.0
// @description API documentation for StorX Monitor server
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// Omit @host so Swagger UI uses the same origin as /swagger/ (avoids localhost vs 127.0.0.1 mismatch).
// @BasePath /api/v0

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description Bearer / API key (rare for console routes).

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name _tokenKey
// @description Session cookie after login. **Swagger Authorize:** paste the token value only (from `POST /auth/token` response `token` field). Do not prefix with `Cookie:` or `_tokenKey=`. Copied curl uses `-b '_tokenKey=...'` (not a header). Login via Swagger auto-fills this.

// @securityDefinitions.apikey CSRFAuth
// @in header
// @name X-CSRF-Token
// @description When `console.csrf-protection-enabled` is true: copy `csrfToken` from `GET /config` and Authorize here. Must match `csrf_token` cookie (set by GET /config or synced by Swagger UI). Required for `POST /auth/token`, `POST /auth/account/set-password`, and other CSRF-protected routes.

// @tag.name projects
// @tag.description Project management: invitations, members, usage, and project CRUD

// @tag.name projects-daily-usage
// @tag.description Storage & bandwidth trends: GET /api/v0/projects/{id}/daily-usage — daily storageUsage and settledBandwidthUsage (bytes per day) for charts

// @tag.name projects-s3-vault-setup
// @tag.description S3 credentials & vault setup: GET /api/v0/projects/{id}/config — salt, passphrase, role, placements, and feature flags for access-grant / vault flows in the frontend

// @tag.name api-keys-s3-vault-setup
// @tag.description S3 credentials & vault setup: DELETE /api/v0/api-keys/delete-by-name — remove an API key by name and project when revoking S3 credentials from the frontend vault flow

// @tag.name buckets
// @tag.description Bucket management: usage-totals (paginated per-bucket usage), usage-totals-for-reserved, and bucket APIs

// @tag.name buckets-reserved-usage
// @tag.description Reserved integration vault usage: GET /api/v0/buckets/usage-totals-for-reserved — bucketName, storage (GB), objectCount per vault (Google Backup, Dropbox, etc.)

// @tag.name buckets-quota-check
// @tag.description Storage & bandwidth quota popup: POST /api/v0/buckets/check-upload — usage percents, allow_upload/download, popup_show + message (login, upload, download). Same usage data as dashboard quota cards.

// @tag.name api-keys
// @tag.description API key management operations

// @tag.name payments
// @tag.description Payment and billing: GET /payment-plans (server root), GET /api/v0/payments/coupons, POST /api/v0/payments/generate-payment-link, GET /api/v0/payments/invoice-history

// @tag.name analytics
// @tag.description Analytics operations

// @tag.name google-backup-onboarding
// @tag.description Google Backup combined auth: `GET /auth/google-backup` (register or login by email). Returns `action`, `onboarding` block, and `google_backup`. OAuth redirect = `GOOGLE_OAUTH_REDIRECT_URL_GOOGLE_BACKUP`.

// @tag.name google-backup
// @tag.description Google Backup auto-sync APIs (jobs, connect, domain-users). OAuth `code` on `POST /google-backup/connect` and `PUT /auto-sync/jobs/project` uses `GOOGLE_OAUTH_REDIRECT_URL_GOOGLE_BACKUP` (same as `GET /auth/google-backup`). `POST /auto-sync/jobs` sets onboarding complete on success.

// @tag.name google-backup-autosync-live
// @tag.description Live backup progress poll: GET /api/v0/google-backup/auto-sync/live → Backup-Tools GET /auto-sync/live (running/failed tasks only; poll 3–5s). Not `/autosync/live`.

// @tag.name google-backup-users-groups
// @tag.description GET /google-backup/users-groups/*

// @tag.name google-backup-policy
// @tag.description Google Backup shared policies: schedule, retention, merge (Backup-Tools /auto-sync/policy/*)

// @tag.name google-backup-auth
// @tag.description Google Backup authentication: POST /google-backup/google-auth (Backup-Tools google-auth JWT)

// @tag.name google-backup-restore-manual
// @tag.description Google Backup manual restore: POST /google-backup/google/* (1–10 vault keys per request; same body for single or multiple items). Authorization header = Backup-Tools JWT from POST /google-backup/google-auth. No ACCESS_TOKEN (StorX from DB). Session cookie required.

// @tag.name google-backup-restore-cron
// @tag.description Google Backup restore-all scheduler: GET /restore/prepare (flat), POST /restore/all, GET /restore/live|jobs|job/* (token_key only; list/detail/live use {message,success,failed} envelope). UI service param (gmail,drive,...) maps to DB method (gmail,google_drive,...). OAuth reconnect via POST /google-backup/connect or PUT /auto-sync/jobs/project.

// @tag.name google-backup-logs
// @tag.description GET /google-backup/backup-restore/logs

// @tag.name auth-account
// @tag.description Logged-in account: profile (`GET/PATCH /auth/account` — check `hasPassword`), change-password when password exists, MFA, settings, onboarding PATCH, refresh-session, developer-access. Login: Google via `/auth/google-backup` or email via `POST /auth/token`.

// @tag.name auth-email-login
// @tag.description **Email + password login:** `GET /config` first for `captcha.login` site keys and `csrfToken` when CSRF is enabled, then `POST /auth/token` with `captchaResponse` and optional `X-CSRF-Token` header. Sets `_tokenKey` cookie. Response: `token`, `success`, `action` (`logged_in`), `onboarding` (same block as google-backup), `google_backup` when user has stored Google credentials (scopes refreshed via refresh token). Send `mfaPasscode` or `mfaRecoveryCode` on second request if MFA enabled.

// @tag.name auth-set-password
// @tag.description **Optional first password** when `GET /auth/account` returns `hasPassword: false`. **Swagger test:** (1) `GET /config` → copy `csrfToken`. (2) Authorize **CookieAuth** = `_tokenKey` value from Google login / `auth/token`. (3) Authorize **CSRFAuth** = same `csrfToken`. (4) `POST /auth/account/set-password` with `{ "newPassword": "..." }`.

// @tag.name auth-password-recovery
// @tag.description **Forgot password (no CSRF):** `POST /auth/forgot-password` and `POST /auth/reset-password` do **not** require `X-CSRF-Token` (only login captcha / recovery token). Flow: forgot-password → email link `/password-recovery?token=` → reset-password → **`POST /auth/token` needs CSRF** when enabled: call `GET /config` first, copy `csrfToken`, Authorize **CSRFAuth**, then login with the new password.

// @tag.name settings-fcm
// @tag.description Settings → Push devices: register and manage FCM tokens at `/api/v0/fcm-token` (session cookie). IP address is set server-side.

// @tag.name settings-notification-preferences
// @tag.description Settings → Notification preferences: global channel thresholds at `/api/v0/user/notification-preferences` (push, email, sms minimum priority levels applied to all notifications).

// @tag.name access
// @tag.description Access management: GET /api/v0/api-keys/list-paged (paginated keys), POST /v1/access (exchange access grant for S3 credentials on auth host)

// @tag.name notifications
// @tag.description In-app notifications: GET/PUT /api/v0/notifications (list, count, detail, dismiss, read-all)

// @tag.name config
// @tag.description Public console bootstrap config: GET /api/v0/config (feature flags, API base URL, CSRF token, billing/UI toggles)

// @tag.name audit-logs
// @tag.description System audit logs: GET /api/v0/audit-logs (list with filters), GET /api/v0/audit-logs/actions (filter dropdown), GET /api/v0/audit-logs/export (CSV)

// @tag.name static-api
// @tag.description Public static content at server root (not under /api/v0): GET /resources-list, /blog-list, /guides, /user-guideline-for-app. Swagger may prefix paths with /api/v0 — use the host root path when calling.

// Common response models
type ErrorResponse struct {
	Error string `json:"error" example:"error message"`
}

type TokenResponse struct {
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

type Project struct {
	ID          string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Name        string `json:"name" example:"My Project"`
	Description string `json:"description" example:"Project description"`
	CreatedAt   string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

type Bucket struct {
	Name      string `json:"name" example:"my-bucket"`
	CreatedAt string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

type APIKey struct {
	ID        string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Name      string `json:"name" example:"My API Key"`
	CreatedAt string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

type User struct {
	ID        string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Email     string `json:"email" example:"user@example.com"`
	FullName  string `json:"fullName" example:"John Doe"`
	CreatedAt string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

type Pagination struct {
	Limit  int `json:"limit" example:"10"`
	Offset int `json:"offset" example:"0"`
}

type PaginatedResponse struct {
	Items      interface{} `json:"items"`
	TotalCount int         `json:"totalCount" example:"100"`
	Limit      int         `json:"limit" example:"10"`
	Offset     int         `json:"offset" example:"0"`
}
