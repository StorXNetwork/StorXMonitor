// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/common/testrand"
	"github.com/StorXNetwork/common/uuid"
)

// fakeBackupCredentials is an in-memory BackupCredentials.
type fakeBackupCredentials struct {
	mu    sync.Mutex
	rows  []BackupCredential
	clock time.Time
}

func (f *fakeBackupCredentials) now() time.Time {
	f.clock = f.clock.Add(time.Second)
	return f.clock
}

func (f *fakeBackupCredentials) find(match func(*BackupCredential) bool) (*BackupCredential, error) {
	for i := range f.rows {
		if match(&f.rows[i]) {
			c := f.rows[i]
			return &c, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (f *fakeBackupCredentials) update(id uuid.UUID, fn func(*BackupCredential)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rows {
		if f.rows[i].ID == id {
			fn(&f.rows[i])
			f.rows[i].UpdatedAt = f.now()
			return nil
		}
	}
	return sql.ErrNoRows
}

func (f *fakeBackupCredentials) Create(_ context.Context, c BackupCredential) (*BackupCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c.Email = strings.ToLower(strings.TrimSpace(c.Email))
	c.ExternalAccountID = strings.ToLower(strings.TrimSpace(c.ExternalAccountID))
	if c.ExternalAccountID == "" {
		c.ExternalAccountID = c.Email
	}
	for _, row := range f.rows {
		if row.UserID == c.UserID && row.Provider == c.Provider && row.ExternalAccountID == c.ExternalAccountID {
			return nil, sql.ErrTxDone
		}
	}
	c.CreatedAt = f.now()
	c.UpdatedAt = c.CreatedAt
	f.rows = append(f.rows, c)
	return &c, nil
}

func (f *fakeBackupCredentials) GetByID(_ context.Context, id uuid.UUID) (*BackupCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.find(func(c *BackupCredential) bool { return c.ID == id })
}

func (f *fakeBackupCredentials) GetByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (*BackupCredential, error) {
	list, _ := f.ListByUserIDAndProvider(ctx, userID, provider)
	if latest := latestMicrosoftCredential(list); latest != nil {
		return latest, nil
	}
	return nil, sql.ErrNoRows
}

func (f *fakeBackupCredentials) GetByUserIDProviderEmail(_ context.Context, userID uuid.UUID, provider, email string) (*BackupCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.find(func(c *BackupCredential) bool {
		return c.UserID == userID && c.Provider == provider && strings.EqualFold(c.Email, email)
	})
}

func (f *fakeBackupCredentials) GetByUserIDProviderAndAccount(_ context.Context, userID uuid.UUID, provider, externalAccountID string) (*BackupCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.find(func(c *BackupCredential) bool {
		return c.UserID == userID && c.Provider == provider && strings.EqualFold(c.ExternalAccountID, externalAccountID)
	})
}

func (f *fakeBackupCredentials) ListByUserIDAndProvider(_ context.Context, userID uuid.UUID, provider string) ([]BackupCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []BackupCredential
	for _, row := range f.rows {
		if row.UserID == userID && row.Provider == provider {
			out = append(out, row)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (f *fakeBackupCredentials) UpdateEmail(_ context.Context, id uuid.UUID, email string) error {
	return f.update(id, func(c *BackupCredential) { c.Email = strings.ToLower(strings.TrimSpace(email)) })
}

func (f *fakeBackupCredentials) UpdateAccountType(_ context.Context, id uuid.UUID, accountType string) error {
	return f.update(id, func(c *BackupCredential) { c.AccountType = accountType })
}

func (f *fakeBackupCredentials) UpdateMicrosoftTenant(_ context.Context, id uuid.UUID, tenantID, tenantName string) error {
	return f.update(id, func(c *BackupCredential) {
		if tenantID != "" {
			c.TenantID = tenantID
		}
		if tenantName != "" {
			c.TenantName = tenantName
		}
	})
}

func (f *fakeBackupCredentials) UpdateTokens(_ context.Context, id uuid.UUID, accessToken, refreshToken string, accessTokenExpiry *time.Time) error {
	return f.update(id, func(c *BackupCredential) {
		c.AccessToken = accessToken
		if refreshToken != "" {
			c.RefreshToken = refreshToken
		}
		c.AccessTokenExpiry = accessTokenExpiry
	})
}

func (f *fakeBackupCredentials) ClearTokens(_ context.Context, id uuid.UUID) error {
	return f.update(id, func(c *BackupCredential) { c.AccessToken, c.RefreshToken = "", "" })
}

func (f *fakeBackupCredentials) DeleteAllByUserID(_ context.Context, userID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.rows[:0]
	for _, row := range f.rows {
		if row.UserID != userID {
			kept = append(kept, row)
		}
	}
	f.rows = kept
	return nil
}

type fakeStorageDestinations struct{ StorageDestinations }

func (fakeStorageDestinations) GetByUserID(context.Context, uuid.UUID) (*StorageDestination, error) {
	return nil, ErrStorageDestinationNotFound.New("not found")
}

// fakeConsoleDB serves only what the Microsoft backup service paths use.
type fakeConsoleDB struct {
	DB
	credentials *fakeBackupCredentials
}

func (db *fakeConsoleDB) BackupCredentials() BackupCredentials     { return db.credentials }
func (db *fakeConsoleDB) StorageDestinations() StorageDestinations { return fakeStorageDestinations{} }

// backupToolsCall is one request received by the Backup-Tools stub.
type backupToolsCall struct {
	Method  string
	Path    string
	Query   map[string][]string
	Header  http.Header
	Body    map[string]interface{}
	RawBody string
}

type microsoftIdentityHarness struct {
	t           *testing.T
	service     *Service
	credentials *fakeBackupCredentials
	user        *User
	ctx         context.Context

	mu    sync.Mutex
	calls []backupToolsCall
}

func newMicrosoftIdentityHarness(t *testing.T) *microsoftIdentityHarness {
	h := &microsoftIdentityHarness{
		t:           t,
		credentials: &fakeBackupCredentials{clock: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		user:        &User{ID: testrand.UUID(), Email: "owner@storx.test"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := backupToolsCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), RawBody: string(raw)}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &call.Body)
		}
		h.mu.Lock()
		h.calls = append(h.calls, call)
		h.mu.Unlock()
		// 201 keeps job create away from onboarding settings, which the fake DB does not serve.
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	h.service = &Service{
		log:            zaptest.NewLogger(t),
		backupToolsURL: server.URL,
		store:          &fakeConsoleDB{credentials: h.credentials},
	}
	h.ctx = WithUser(context.Background(), h.user)
	return h
}

func (h *microsoftIdentityHarness) addCredential(userID uuid.UUID, provider, email, accountID, homeTenant string) *BackupCredential {
	created, err := h.credentials.Create(context.Background(), BackupCredential{
		ID:                testrand.UUID(),
		UserID:            userID,
		Provider:          provider,
		Email:             email,
		ExternalAccountID: accountID,
		AccessToken:       "access",
		RefreshToken:      "1.refresh-" + email,
		AccountType:       MicrosoftAccountTypeWorkAccount,
		TenantID:          homeTenant,
		TenantName:        "Home " + homeTenant,
	})
	require.NoError(h.t, err)
	return created
}

func (h *microsoftIdentityHarness) lastCall() backupToolsCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotEmpty(h.t, h.calls, "Backup-Tools was not called")
	return h.calls[len(h.calls)-1]
}

func (h *microsoftIdentityHarness) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func requireMicrosoftHeaders(t *testing.T, call backupToolsCall, accountID, homeTenant, selectedTenant string) {
	t.Helper()
	require.Equal(t, accountID, call.Header.Get(BackupToolsHeaderMicrosoftAccountID))
	require.Equal(t, homeTenant, call.Header.Get(BackupToolsHeaderMicrosoftHomeTenantID))
	require.Equal(t, selectedTenant, call.Header.Get(BackupToolsHeaderMicrosoftTenantID))
	_, hasTenant := call.Header[http.CanonicalHeaderKey(BackupToolsHeaderMicrosoftTenantID)]
	require.Equal(t, selectedTenant != "", hasTenant)
}

func TestResolveMicrosoftCredential(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	ctx, userID := h.ctx, h.user.ID

	_, err := h.service.resolveMicrosoftCredential(ctx, userID, "")
	require.True(t, ErrNotFound.Has(err), "%v", err)

	// Google credentials never count as Microsoft accounts.
	google := h.addCredential(userID, BackupProviderGoogle, "user@gmail.com", "", "")
	_, err = h.service.resolveMicrosoftCredential(ctx, userID, "")
	require.True(t, ErrNotFound.Has(err), "%v", err)
	_, err = h.service.resolveMicrosoftCredential(ctx, userID, google.ID.String())
	require.True(t, ErrMicrosoftCredentialNotFound.Has(err), "%v", err)

	first := h.addCredential(userID, BackupProviderMicrosoft, "alice@contoso.com", "oid-a", "tenant-a")
	got, err := h.service.resolveMicrosoftCredential(ctx, userID, "")
	require.NoError(t, err)
	require.Equal(t, first.ID, got.ID)

	second := h.addCredential(userID, BackupProviderMicrosoft, "alice@fabrikam.com", "oid-b", "tenant-b")
	_, err = h.service.resolveMicrosoftCredential(ctx, userID, "")
	require.True(t, ErrMicrosoftCredentialRequired.Has(err), "%v", err)

	got, err = h.service.resolveMicrosoftCredential(ctx, userID, " "+second.ID.String()+" ")
	require.NoError(t, err)
	require.Equal(t, second.ID, got.ID)

	foreign := h.addCredential(testrand.UUID(), BackupProviderMicrosoft, "mallory@contoso.com", "oid-m", "tenant-a")
	_, err = h.service.resolveMicrosoftCredential(ctx, userID, foreign.ID.String())
	require.True(t, ErrMicrosoftCredentialNotFound.Has(err), "%v", err)

	_, err = h.service.resolveMicrosoftCredential(ctx, userID, testrand.UUID().String())
	require.True(t, ErrMicrosoftCredentialNotFound.Has(err), "%v", err)

	_, err = h.service.resolveMicrosoftCredential(ctx, userID, "not-a-uuid")
	require.True(t, ErrValidation.Has(err), "%v", err)

	accounts, err := h.service.ListMicrosoftBackupAccounts(ctx)
	require.NoError(t, err)
	require.Len(t, accounts, 2)
	require.Equal(t, first.ID.String(), accounts[0].ID)
	require.Equal(t, "oid-a", accounts[0].ExternalAccountID)
	require.Equal(t, "tenant-a", accounts[0].HomeTenantID)
	require.True(t, accounts[0].HasRefreshToken)
	require.Equal(t, second.ID.String(), accounts[1].ID)
}

func TestMicrosoftBackupToolsHeaders(t *testing.T) {
	credential := &BackupCredential{ExternalAccountID: "oid-a", TenantID: "tenant-home"}

	require.Equal(t, map[string]string{
		BackupToolsHeaderMicrosoftAccountID:    "oid-a",
		BackupToolsHeaderMicrosoftHomeTenantID: "tenant-home",
	}, microsoftBackupToolsHeaders(credential, ""))

	require.Equal(t, map[string]string{
		BackupToolsHeaderMicrosoftAccountID:    "oid-a",
		BackupToolsHeaderMicrosoftHomeTenantID: "tenant-home",
		BackupToolsHeaderMicrosoftTenantID:     "tenant-guest",
	}, microsoftBackupToolsHeaders(credential, "tenant-guest"))

	require.Empty(t, microsoftBackupToolsHeaders(nil, ""))
}

func TestMicrosoftTenantScopedRoutes(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	alice := h.addCredential(h.user.ID, BackupProviderMicrosoft, "alice@contoso.com", "oid-a", "tenant-home")
	h.addCredential(h.user.ID, BackupProviderMicrosoft, "alice@fabrikam.com", "oid-b", "tenant-other")
	sel := MicrosoftTenantSelection{CredentialID: alice.ID.String(), TenantID: "Tenant-Guest"}

	t.Run("organization routes require tenant_id", func(t *testing.T) {
		before := h.callCount()
		noTenant := MicrosoftTenantSelection{CredentialID: alice.ID.String()}

		_, err := h.service.GetMicrosoftBackupStatus(h.ctx, "session", noTenant)
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, err = h.service.RefreshMicrosoftBackupCapabilities(h.ctx, "session", noTenant)
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, err = h.service.ListMicrosoftBackupDirectoryUsers(h.ctx, "session", noTenant, nil)
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, err = h.service.GetMicrosoftBackupOrgStructure(h.ctx, "session", noTenant)
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, err = h.service.ConnectMicrosoftBackupTenant(h.ctx, "session", noTenant, "organization")
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, err = h.service.DisconnectMicrosoftBackupTenant(h.ctx, "session", noTenant)
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, err = h.service.RefreshMicrosoftBackupTenantRoles(h.ctx, "session", noTenant)
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		_, _, err = h.service.GetMicrosoftBackupTeamsList(h.ctx, "session", "", "credential_id="+alice.ID.String())
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)

		require.Equal(t, before, h.callCount(), "no request may reach Backup-Tools without a tenant")
	})

	t.Run("several accounts require credential_id", func(t *testing.T) {
		_, err := h.service.GetMicrosoftBackupStatus(h.ctx, "session", MicrosoftTenantSelection{TenantID: "tenant-guest"})
		require.True(t, ErrMicrosoftCredentialRequired.Has(err), "%v", err)
	})

	t.Run("status sends the selected tenant", func(t *testing.T) {
		contract, err := h.service.GetMicrosoftBackupStatus(h.ctx, "session", sel)
		require.NoError(t, err)
		require.Equal(t, alice.ID.String(), contract["credential_id"])

		call := h.lastCall()
		require.Equal(t, "/microsoft/workspace", call.Path)
		require.Equal(t, "tenant-guest", call.Query["tenant_id"][0])
		require.Equal(t, "session", call.Header.Get("token_key"))
		require.Equal(t, "1.refresh-alice@contoso.com", call.Header.Get("REFRESH_TOKEN"))
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("guest tenant contract does not change account_type", func(t *testing.T) {
		got, err := h.credentials.GetByID(h.ctx, alice.ID)
		require.NoError(t, err)
		h.service.syncMicrosoftAccountTypeFromWorkspace(h.ctx, got, "tenant-guest", map[string]interface{}{"account_type": MicrosoftAccountTypeAdminWorkspace})
		got, err = h.credentials.GetByID(h.ctx, alice.ID)
		require.NoError(t, err)
		require.Equal(t, MicrosoftAccountTypeWorkAccount, got.AccountType)

		h.service.syncMicrosoftAccountTypeFromWorkspace(h.ctx, got, "tenant-home", map[string]interface{}{"account_type": MicrosoftAccountTypeAdminWorkspace})
		got, err = h.credentials.GetByID(h.ctx, alice.ID)
		require.NoError(t, err)
		require.Equal(t, MicrosoftAccountTypeAdminWorkspace, got.AccountType)
	})

	t.Run("directory users path and query", func(t *testing.T) {
		_, err := h.service.ListMicrosoftBackupDirectoryUsers(h.ctx, "session", sel, map[string][]string{"search": {"bob"}, "credential_id": {"x"}})
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/microsoft/tenants/tenant-guest/directory/users", call.Path)
		require.Equal(t, []string{"bob"}, call.Query["search"])
		require.NotContains(t, call.Query, "credential_id")
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("list tenants is account-level", func(t *testing.T) {
		result, err := h.service.ListMicrosoftBackupTenants(h.ctx, "session", alice.ID.String())
		require.NoError(t, err)
		require.Equal(t, alice.ID.String(), result["credential_id"])
		call := h.lastCall()
		require.Equal(t, http.MethodGet, call.Method)
		require.Equal(t, "/microsoft/accounts/tenants", call.Path)
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "")
	})

	t.Run("connect tenant", func(t *testing.T) {
		_, err := h.service.ConnectMicrosoftBackupTenant(h.ctx, "session", sel, "tenant")
		require.True(t, ErrValidation.Has(err), "%v", err)

		_, err = h.service.ConnectMicrosoftBackupTenant(h.ctx, "session", sel, " Organization ")
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, http.MethodPost, call.Method)
		require.Equal(t, "/microsoft/accounts/tenants/tenant-guest/connect", call.Path)
		require.Equal(t, "organization", call.Body["backup_mode"])
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("disconnect and roles refresh", func(t *testing.T) {
		_, err := h.service.DisconnectMicrosoftBackupTenant(h.ctx, "session", sel)
		require.NoError(t, err)
		require.Equal(t, "/microsoft/accounts/tenants/tenant-guest/disconnect", h.lastCall().Path)

		_, err = h.service.RefreshMicrosoftBackupTenantRoles(h.ctx, "session", sel)
		require.NoError(t, err)
		require.Equal(t, "/microsoft/accounts/tenants/tenant-guest/roles/refresh", h.lastCall().Path)
	})

	t.Run("browse strips credential_id and forwards tenant", func(t *testing.T) {
		_, _, err := h.service.GetMicrosoftBackupTeamsList(h.ctx, "session", "", "credential_id="+alice.ID.String()+"&tenant_id=tenant-guest&page=2")
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/microsoft/teams/list", call.Path)
		require.NotContains(t, call.Query, "credential_id")
		require.Equal(t, []string{"2"}, call.Query["page"])
		require.Equal(t, "1.refresh-alice@contoso.com", call.Header.Get("REFRESH_TOKEN"))
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})
}

func TestMicrosoftPersonalAccountStatus(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	personal, err := h.credentials.Create(h.ctx, BackupCredential{
		ID:                testrand.UUID(),
		UserID:            h.user.ID,
		Provider:          BackupProviderMicrosoft,
		Email:             "me@outlook.com",
		ExternalAccountID: "oid-p",
		RefreshToken:      "1.refresh",
		AccountType:       MicrosoftAccountTypePersonal,
		TenantID:          "9188040d-6c67-4c5b-b112-36a304b66dad",
	})
	require.NoError(t, err)

	contract, err := h.service.GetMicrosoftBackupStatus(h.ctx, "session", MicrosoftTenantSelection{})
	require.NoError(t, err)
	require.Equal(t, personal.ID.String(), contract["credential_id"])
	require.Zero(t, h.callCount())

	_, err = h.service.RefreshMicrosoftBackupCapabilities(h.ctx, "session", MicrosoftTenantSelection{TenantID: "tenant-x"})
	require.True(t, ErrValidation.Has(err), "%v", err)
}

func TestCreateMicrosoftBackupAutoSyncJobsTenant(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	alice := h.addCredential(h.user.ID, BackupProviderMicrosoft, "alice@contoso.com", "oid-a", "tenant-home")

	orgReq := func(tenantID string) CreateMicrosoftBackupAutoSyncJobsRequest {
		return CreateMicrosoftBackupAutoSyncJobsRequest{
			Services:     []string{"outlook"},
			Interval:     "daily",
			BackupMode:   MicrosoftBackupModeOrganization,
			AllUsers:     true,
			ProjectID:    "project-1",
			StorxToken:   "grant",
			CredentialID: alice.ID.String(),
			TenantID:     tenantID,
		}
	}

	t.Run("organization requires tenant_id", func(t *testing.T) {
		_, _, err := h.service.CreateMicrosoftBackupAutoSyncJobs(h.ctx, orgReq(""), "session", "")
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		require.Zero(t, h.callCount())
	})

	t.Run("organization job for a guest tenant", func(t *testing.T) {
		_, status, err := h.service.CreateMicrosoftBackupAutoSyncJobs(h.ctx, orgReq("Tenant-Guest"), "session", "")
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, status)

		call := h.lastCall()
		require.Equal(t, "/microsoft/auto-sync/job", call.Path)
		require.Equal(t, "tenant-guest", call.Body["tenant_id"])
		require.NotContains(t, call.Body, "tenant_name", "the home tenant name must not label another tenant")
		require.NotContains(t, call.Body, "refresh_token")
		require.NotContains(t, call.Body, "credential_id")
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("organization job for the home tenant carries its name", func(t *testing.T) {
		_, _, err := h.service.CreateMicrosoftBackupAutoSyncJobs(h.ctx, orgReq("tenant-home"), "session", "")
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "tenant-home", call.Body["tenant_id"])
		require.Equal(t, "Home tenant-home", call.Body["tenant_name"])
	})

	selfReq := func(tenantID string) CreateMicrosoftBackupAutoSyncJobsRequest {
		return CreateMicrosoftBackupAutoSyncJobsRequest{
			Services:   []string{"outlook"},
			Interval:   "daily",
			BackupMode: MicrosoftBackupModeSelf,
			ProjectID:  "project-1",
			StorxToken: "grant",
			TenantID:   tenantID,
		}
	}

	t.Run("self job never assumes the home tenant", func(t *testing.T) {
		before := h.callCount()
		_, _, err := h.service.CreateMicrosoftBackupAutoSyncJobs(h.ctx, selfReq(""), "session", "")
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		require.Equal(t, before, h.callCount())
	})

	t.Run("self job for the selected tenant", func(t *testing.T) {
		_, _, err := h.service.CreateMicrosoftBackupAutoSyncJobs(h.ctx, selfReq("Tenant-Guest"), "session", "")
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "tenant-guest", call.Body["tenant_id"])
		require.NotContains(t, call.Body, "tenant_name")
		require.Equal(t, "1.refresh-alice@contoso.com", call.Body["refresh_token"])
		require.Equal(t, []interface{}{"alice@contoso.com"}, call.Body["emails"])
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})
}

func TestMicrosoftRestoreIdentity(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	alice := h.addCredential(h.user.ID, BackupProviderMicrosoft, "alice@contoso.com", "oid-a", "tenant-home")

	t.Run("prepare forwards credential and tenant", func(t *testing.T) {
		_, _, err := h.service.PrepareMicrosoftBackupRestore(h.ctx, "session", MicrosoftBackupRestorePrepareParams{
			ProjectID:    "project-1",
			LoginID:      "alice@contoso.com",
			Service:      "mail",
			CredentialID: alice.ID.String(),
			TenantID:     "Tenant-Guest",
		})
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/restore/prepare", call.Path)
		require.Equal(t, []string{"tenant-guest"}, call.Query["tenant_id"])
		require.NotContains(t, call.Query, "credential_id")
		require.Equal(t, "1.refresh-alice@contoso.com", call.Header.Get("REFRESH_TOKEN"))
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("restore all forwards the tenant in body and headers", func(t *testing.T) {
		_, _, err := h.service.StartMicrosoftBackupRestoreAll(h.ctx, "session", MicrosoftBackupRestoreAllRequest{
			Service:   "onedrive",
			ProjectID: "project-1",
			LoginID:   "alice@contoso.com",
			TenantID:  "tenant-guest",
		})
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/restore/all", call.Path)
		require.Equal(t, "tenant-guest", call.Body["tenant_id"])
		require.NotContains(t, call.Body, "credential_id")
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("restore without a tenant is left to Backup-Tools", func(t *testing.T) {
		_, _, err := h.service.StartMicrosoftBackupRestoreAll(h.ctx, "session", MicrosoftBackupRestoreAllRequest{
			Service:   "outlook",
			ProjectID: "project-1",
			LoginID:   "alice@contoso.com",
		})
		require.NoError(t, err)
		call := h.lastCall()
		require.NotContains(t, call.Body, "tenant_id")
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "")
	})

	t.Run("several accounts require credential_id", func(t *testing.T) {
		h.addCredential(h.user.ID, BackupProviderMicrosoft, "alice@fabrikam.com", "oid-b", "tenant-other")
		_, _, err := h.service.StartMicrosoftBackupRestoreAll(h.ctx, "session", MicrosoftBackupRestoreAllRequest{
			Service:   "outlook",
			ProjectID: "project-1",
			LoginID:   "alice@contoso.com",
			TenantID:  "tenant-guest",
		})
		require.True(t, ErrMicrosoftCredentialRequired.Has(err), "%v", err)
	})
}

func TestBackupServicesQuotaCheckIdentity(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	alice := h.addCredential(h.user.ID, BackupProviderMicrosoft, "alice@contoso.com", "oid-a", "tenant-home")
	h.addCredential(h.user.ID, BackupProviderGoogle, "user@gmail.com", "", "")

	t.Run("microsoft uses the selected credential and tenant", func(t *testing.T) {
		_, _, err := h.service.TriggerBackupServicesQuotaCheck(h.ctx, "session",
			[]byte(`{"services":["outlook"],"credential_id":"`+alice.ID.String()+`","tenant_id":"Tenant-Guest"}`))
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/auto-sync/job/services-quota-check", call.Path)
		require.Equal(t, "tenant-guest", call.Body["tenant_id"])
		require.Equal(t, "alice@contoso.com", call.Body["microsoft_email"])
		require.NotContains(t, call.Body, "credential_id")
		requireMicrosoftHeaders(t, call, "oid-a", "tenant-home", "tenant-guest")
	})

	t.Run("microsoft never assumes the home tenant", func(t *testing.T) {
		before := h.callCount()
		_, _, err := h.service.TriggerBackupServicesQuotaCheck(h.ctx, "session", []byte(`{"services":["onedrive"]}`))
		require.True(t, ErrMicrosoftTenantRequired.Has(err), "%v", err)
		require.Equal(t, before, h.callCount())
	})

	t.Run("google is unchanged", func(t *testing.T) {
		_, _, err := h.service.TriggerBackupServicesQuotaCheck(h.ctx, "session", []byte(`{"services":["gmail"]}`))
		require.NoError(t, err)
		call := h.lastCall()
		require.Equal(t, "/auto-sync/job/services-quota-check", call.Path)
		require.Equal(t, "user@gmail.com", call.Body["google_email"])
		require.Equal(t, "1.refresh-user@gmail.com", call.Body["refresh_token"])
		require.NotContains(t, call.Body, "tenant_id")
		require.NotContains(t, call.Body, "microsoft_email")
		for _, header := range []string{BackupToolsHeaderMicrosoftAccountID, BackupToolsHeaderMicrosoftHomeTenantID, BackupToolsHeaderMicrosoftTenantID} {
			require.Empty(t, call.Header.Get(header))
		}
	})
}

func TestStoreMicrosoftBackupCredential(t *testing.T) {
	h := newMicrosoftIdentityHarness(t)
	userID := h.user.ID

	_, err := h.service.StoreMicrosoftBackupCredential(h.ctx, userID, MicrosoftCredentialInput{Email: "alice@contoso.com", RefreshToken: "1.r"})
	require.True(t, ErrValidation.Has(err), "%v", err)

	first, err := h.service.StoreMicrosoftBackupCredential(h.ctx, userID, MicrosoftCredentialInput{
		AccountID:      "OID-A",
		Email:          "alice@contoso.com",
		AccessToken:    "access-1",
		RefreshToken:   "1.refresh-1",
		AccountType:    MicrosoftAccountTypeWorkAccount,
		HomeTenantID:   "tenant-home",
		HomeTenantName: "Contoso",
	})
	require.NoError(t, err)
	require.Equal(t, "oid-a", first.ExternalAccountID)
	require.Equal(t, "tenant-home", first.HomeTenantID())

	t.Run("same oid with a new email updates the label", func(t *testing.T) {
		updated, err := h.service.StoreMicrosoftBackupCredential(h.ctx, userID, MicrosoftCredentialInput{
			AccountID:    "oid-a",
			Email:        "alice.renamed@contoso.com",
			RefreshToken: "1.refresh-2",
		})
		require.NoError(t, err)
		require.Equal(t, first.ID, updated.ID)
		require.Equal(t, "alice.renamed@contoso.com", updated.Email)
		require.Equal(t, "1.refresh-2", updated.RefreshToken)
		require.Equal(t, "access-1", updated.AccessToken)
		require.Equal(t, "tenant-home", updated.HomeTenantID())
		require.Equal(t, MicrosoftAccountTypeWorkAccount, updated.AccountType)
	})

	t.Run("another oid creates a second credential", func(t *testing.T) {
		second, err := h.service.StoreMicrosoftBackupCredential(h.ctx, userID, MicrosoftCredentialInput{
			AccountID:    "oid-b",
			Email:        "alice@contoso.com",
			RefreshToken: "1.refresh-b",
			HomeTenantID: "tenant-other",
		})
		require.NoError(t, err)
		require.NotEqual(t, first.ID, second.ID)

		list, err := h.credentials.ListByUserIDAndProvider(h.ctx, userID, BackupProviderMicrosoft)
		require.NoError(t, err)
		require.Len(t, list, 2)
	})

	t.Run("jwt refresh token is rejected", func(t *testing.T) {
		_, err := h.service.StoreMicrosoftBackupCredential(h.ctx, userID, MicrosoftCredentialInput{
			AccountID:    "oid-c",
			Email:        "c@contoso.com",
			RefreshToken: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
		})
		require.True(t, ErrValidation.Has(err), "%v", err)
	})
}
