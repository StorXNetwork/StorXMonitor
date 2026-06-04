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

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name _tokenKey

// @tag.name projects
// @tag.description Project management: invitations, members, usage, and project CRUD

// @tag.name projects-daily-usage
// @tag.description Storage & bandwidth trends: GET /api/v0/projects/{id}/daily-usage — daily storageUsage and settledBandwidthUsage (bytes per day) for charts

// @tag.name buckets
// @tag.description Bucket management: usage-totals (paginated per-bucket usage), usage-totals-for-reserved, and bucket APIs

// @tag.name buckets-reserved-usage
// @tag.description Reserved integration vault usage: GET /api/v0/buckets/usage-totals-for-reserved — bucketName, storage (GB), objectCount per vault (Google Backup, Dropbox, etc.)

// @tag.name api-keys
// @tag.description API key management operations

// @tag.name payments
// @tag.description Payment and billing operations

// @tag.name analytics
// @tag.description Analytics operations

// @tag.name google-backup-onboarding
// @tag.description **Google Backup onboarding — architecture.** **Backend stores** (table `user_settings`): `onboardingStart`, `onboardingEnd`, `onboardingStep` (step name string only — never frontend URLs). **Frontend controls** pages/routes (examples: `/google-backup/onboarding`, `/google-backup/services`, `/google-backup/connect`, `/google-backup/domain-users`); use your router (`router.push`, etc.). **Backend-defined steps** (3 only): `GoogleBackupPending` (auto on register-google), `GoogleBackupCompleted` (auto on POST /auto-sync/jobs; legacy `GoogleBackupServices` accepted), `GoogleBackupSkipped` (UI PATCH skip). **UI-defined steps:** any string with prefix `GoogleBackup` via PATCH — e.g. `GoogleBackupConnect`, `GoogleBackupServiceSelection`, `GoogleBackupDomainUsers` (UI progress / resume). **onboarding_status** (`pending`|`in_progress`|`completed`) is computed for responses, not stored. **Resume:** GET /auth/account/settings → read `onboardingStep` → frontend maps to correct page. **Full flow:** register → Pending → PATCH steps → optional connect/domain-users → POST /auto-sync/jobs → Services + `onboardingEnd=true`. **Login:** `redirect_url` is always dashboard; use `onboarding_status` + settings as hints — UI decides onboarding vs dashboard.

// @tag.name google-backup-onboarding-registration
// @tag.description **Registration** `GET /auth/register-google`. Backend auto-sets `onboardingStep=GoogleBackupPending`, `onboardingEnd=false`. Returns JSON: `success`, `onboarding_status` (usually `pending`), `google_backup`. No `redirect_url` on success — frontend navigates (e.g. `/google-backup/onboarding`). Tokens stored server-side only. OAuth `redirect_uri` = `GOOGLE_OAUTH_REDIRECT_URL_REGISTER`.

// @tag.name google-backup-onboarding-login
// @tag.description **Login** `GET /auth/login-google`. Sets session cookie. `redirect_url` = `{CLIENT_ORIGIN}/project-dashboard` (fixed; backend does not store frontend URLs). With `?json=true`: optional `onboarding_status` hint from `user_settings` — UI may resume onboarding via GET /auth/account/settings (`onboardingStep`). Persist skip: PATCH onboarding with `GoogleBackupSkipped`, `onboardingEnd=true`.

// @tag.name google-backup-onboarding-settings
// @tag.description **Onboarding state** (authenticated). **GET** `/auth/account/settings` — read `onboardingStart`, `onboardingEnd`, `onboardingStep` for resume (map step → your frontend route). **PATCH** `/auth/account/onboarding` — send step names only (not URLs). Examples: advance `{onboardingStart:true, onboardingEnd:false, onboardingStep:"GoogleBackupServiceSelection"}`; skip `{..., onboardingEnd:true, onboardingStep:"GoogleBackupSkipped"}`. See models `SetGoogleBackupOnboarding*SwaggerRequest` in Schemas.

// @tag.name google-backup
// @tag.description Google Backup auto-sync and policy APIs (jobs, connect, domain-users, policy merge) — use after onboarding or for ongoing management. `POST /auto-sync/jobs` completes onboarding when successful.

// @tag.name google-backup-policy
// @tag.description Google Backup shared policies: schedule, retention, merge (Backup-Tools /auto-sync/policy/*)

// @tag.name google-backup-auth
// @tag.description Google Backup authentication: POST /google-backup/google-auth (Backup-Tools google-auth JWT)

// @tag.name google-backup-restore-manual
// @tag.description Google Backup manual restore: synchronous vault → Google (POST /google-backup/google/*, max 10 keys). Call POST /google-backup/google-auth first.

// @tag.name google-backup-restore-cron
// @tag.description Google Backup restore-all scheduler: GET /restore/prepare, POST /restore/all, GET /restore/live|jobs|job/* (token_key only; OAuth reconnect via auto-sync job PUT)

// @tag.name auth-account
// @tag.description Account & session: profile, settings, refresh-session, developer-access, MFA, FCM tokens, notification-preferences

// @tag.name access
// @tag.description Access management: GET /api/v0/api-keys/list-paged (paginated keys), POST /v1/access (exchange access grant for S3 credentials on auth host)

// @tag.name notifications
// @tag.description In-app notifications: GET/PUT /api/v0/notifications (list, count, detail, dismiss, read-all)

// @tag.name payment-plans
// @tag.description Public billing plans: GET /payment-plans at server root (not under /api/v0). Swagger may show /api/v0/payment-plans — use the host root path when calling.

// @tag.name config
// @tag.description Public console bootstrap config: GET /api/v0/config (feature flags, API base URL, CSRF token, billing/UI toggles)

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
