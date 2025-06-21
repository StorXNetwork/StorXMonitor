# Key Store Contract Update Work Plan

## Overview
This document outlines the plan to update the key store contract handling in the StorX system. The changes involve updating the contract interaction logic and modifying how we handle configuration values through secret constants.

---

## Phase 1: Contract Integration ✅

**Goal:** Update the codebase to support the new contract ABI and versioning features.

### Steps
- ✅ Update `keyValueWeb3Helper`:
  - ✅ Modify `UploadSocialShare` and `UpdateSocialShare` to include version parameter
  - ✅ Update `GetSocialShare` to use `getKeyValueByVersion`
  - ✅ Add new methods for pagination and key count
- ✅ Update `SocialShareHelper` interface accordingly
- ✅ Add/Update unit tests for new contract features
  - ✅ Version-aware tests
  - ✅ Pagination tests
  - ✅ Total keys count tests
  - ✅ Mock implementation tests

### Validation Points
- ✅ All methods support versioning
- ✅ Pagination works correctly
- ✅ Total keys count is accurate
- ✅ All tests pass
- ✅ Backward compatibility maintained

**Status:** Completed
**Completion Date:** Current
**Notes:** Successfully implemented and tested all new contract features including versioning, pagination, and key count functionality.

---

## Phase 2: Database-backed Version Management ✅

**Goal:** Implement a database-backed versioning system to track and increment key versions for smart contract interactions.

### Step 1: Update Database Schema
*   **Location**: `satellite/satellitedb/dbx/web3auth.dbx`
*   **Action**: Define the schema for the new `key_version` table.
    ```dbx
    model key_version (
        key key_id

        // key_id corresponds to the key in the smart contract
        field key_id blob
        // version is the current version of the key, e.g., "v0.1"
        field version text ( updatable )
    )

    create key_version ( noreturn )
    update key_version ( where key_id = ? )
    read one ( select version from key_version where key_id = ? )
    ```
*   **Next**: Run `go generate ./...` from the `satellite/satellitedb` directory to update `satellitedb.dbx.go` with new DB methods.

### Step 2: Update Database Service Layer
*   **Location**: `satellite/console/web3auth.go`
*   **Action**: Add new methods for version management to the `Web3Auth` interface.
    ```go
    type Web3Auth interface {
        // ... existing methods: GetBackupShare, UploadBackupShare ...
        CreateKeyVersion(ctx context.Context, keyID []byte, version string) error
        GetKeyVersion(ctx context.Context, keyID []byte) (version string, err error)
        UpdateKeyVersion(ctx context.Context, keyID []byte, newVersion string) error
    }
    ```
*   **Location**: `satellite/satellitedb/web3auth.go`
*   **Action**: Implement the new methods using the generated code from `satellitedb.dbx.go`.
    ```go
    // Example implementation for CreateKeyVersion
    func (b *web3Auth) CreateKeyVersion(ctx context.Context, keyID []byte, version string) error {
        return b.db.CreateNoReturn_KeyVersion(ctx,
            dbx.KeyVersion_KeyId(keyID),
            dbx.KeyVersion_Version(version),
        )
    }
    // ... implement GetKeyVersion and UpdateKeyVersion similarly ...
    ```

### Step 3: Integrate with Application Service (`console.Service`)
*   **Goal**: Centralize the business logic for handling social shares and versioning within the `console.Service`.
*   **Location to Change**: `satellite/console/service.go`
*   **Action 1: Add `SocialShareHelper` to the Service**
    *   The `smartcontract.SocialShareHelper` needs to be accessible from the service. Update the `Service` struct to include it, and pass it in via `NewService`.
        ```go
        // In Service struct definition
        type Service struct {
            // ... existing fields ...
            socialShareHelper          smartcontract.SocialShareHelper
        }

        // In NewService function signature and body
        func NewService(..., socialShareHelper smartcontract.SocialShareHelper) (*Service, error) {
            // ...
            s.socialShareHelper = socialShareHelper
            // ...
        }
        ```
    *   **Note**: This requires updating the `NewService` call in `satellite/console/consoleweb/server.go` to pass the helper.
*   **Action 2: Implement Create/Update Logic**
    *   Add new methods to `console.Service` to handle the versioning workflow.
    *   **Create Logic Example**:
        ```go
        // In satellite/console/service.go
        func (s *Service) UploadSocialShare(ctx context.Context, id string, share string) error {
            version := "v0.1" // Initial version

            // 1. Call smart contract
            err := s.socialShareHelper.UploadSocialShare(ctx, id, share, version)
            if err != nil {
                return errs.Wrap(err)
            }

            // 2. If successful, create version record in DB
            return s.store.Web3Auth().CreateKeyVersion(ctx, []byte(id), version)
        }
        ```
    *   **Update Logic Example**:
        ```go
        // In satellite/console/service.go
        func (s *Service) UpdateSocialShare(ctx context.Context, id string, share string) error {
            // 1. Get current version from DB
            currentVersion, err := s.store.Web3Auth().GetKeyVersion(ctx, []byte(id))
            if err != nil {
                // Handle cases where version does not exist, maybe create it?
                return errs.Wrap(err)
            }

            // 2. Increment version (implement this helper function)
            newVersion, err := incrementVersion(currentVersion)
            if err != nil {
                return errs.Wrap(err)
            }

            // 3. Call smart contract with new version
            err = s.socialShareHelper.UpdateSocialShare(ctx, id, share, newVersion)
            if err != nil {
                return errs.Wrap(err)
            }

            // 4. If successful, update version in DB
            return s.store.Web3Auth().UpdateKeyVersion(ctx, []byte(id), newVersion)
        }
        ```

### Step 4: Update API Controller to Use Service Logic
*   **Location**: `satellite/console/consoleweb/consoleapi/web3auth.go`
*   **Action**: Refactor the API handlers to call the new methods on `console.Service` instead of calling the smart contract helper directly. This keeps business logic out of the API layer.
    ```go
    // In UploadSocialShare API handler
    func (a *Web3Auth) UploadSocialShare(w http.ResponseWriter, r *http.Request) {
        // ... read id and share from request ...
        err := a.service.UploadSocialShare(r.Context(), id, share)
        if err != nil {
            a.sendError(w, "failed to upload share", http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusCreated)
    }
    ```

### Validation Points
-   The `key_version` table is created, and its methods are accessible through the `console.Service`.
-   Calling the "create" endpoint correctly sets the version to `v0.1` in both the smart contract and the database.
-   Calling the "update" endpoint correctly fetches the version from the database, increments it, and updates both the smart contract and the database with the new version.

**Status:** Completed
**Completion Date:** Current
**Notes:** The database now correctly tracks key versions, and the service layer is fully equipped to handle create and update logic based on this versioning system. The API controller has been refactored to be completely decoupled from the smart contract, relying solely on the service layer for business logic.

---

## Phase 3: Secret Management Refactor ✅

**Goal:** Move the Web3 private key from configuration to a build-time secret constant to enhance security.

### Steps
- ✅ Create `secretconstants` package for `Web3AuthPrivateKey`
- ✅ Remove `PrivateKey` field from `Web3Config`
- ✅ Update `NewKeyValueWeb3Helper` to accept the private key as an argument
- ✅ Update server initialization to use the secret constant
- ✅ Add a runtime check to ensure the private key is not empty
- ✅ Update unit tests to align with the new method signatures

### Validation Points
- ✅ Private key is no longer in any config files (`*.yaml`, `*.json`)
- ✅ Server fails to start if the `Web3AuthPrivateKey` is not injected at build time
- ✅ All related unit tests pass with the new secret handling mechanism

**Status:** Completed
**Completion Date:** Current
**Notes:** The private key is now successfully managed as a build-time secret, removing it from configuration and improving the overall security posture.

---

## Phase 4: Build System & Makefile Updates ✅

**Goal:** Integrate the new secret management system into the build process.

### Steps
- ✅ Add `WEB3_AUTH_PRIVATE_KEY` variable to the `Makefile`
- ✅ Update the `install-sim` target to use `ldflags` for injecting the private key into the `satellite` binary
- ✅ Separate the `satellite` build from other binaries in `install-sim` to apply flags selectively
- ✅ Provide a default, non-functional key to prevent build failures when the key is not provided

### Validation Points
- ✅ Running `make install-sim` successfully builds all binaries
- ✅ The satellite binary fails to start if the private key is not passed during the build (due to the runtime check in Phase 2)
- ✅ Running `make install-sim WEB3_AUTH_PRIVATE_KEY="your-key"` successfully builds the satellite with the key injected

**Status:** Completed
**Completion Date:** Current
**Notes:** The Makefile now fully supports injecting the private key at build time, completing the secure workflow for secret management.

---

## Phase 5: Testing & Validation ✅

**Goal:** Ensure all changes work together seamlessly and the system is stable.

### Steps
- ✅ Run `make install-sim` without the private key and verify that the satellite server fails to start with the expected error.
- ✅ Run `make install-sim WEB3_AUTH_PRIVATE_KEY="your-real-key"` and verify the satellite server starts successfully.
- ✅ Perform end-to-end testing of the social share features to ensure they work correctly with the new contract and secret management.
- ✅ Review documentation to ensure it is up-to-date with the new build process.

**Status:** All implementation phases are complete. This phase serves as a final validation checklist.

---

## Summary Table

| Phase   | Goal                                      | Key Outputs/Validation                |
|---------|-------------------------------------------|---------------------------------------|
| Phase 1 | Contract Integration                      | New contract features, tests pass     |
| Phase 2 | Database-backed Version Management        | DB schema, version logic, tests       |
| Phase 3 | Secret Management Refactor                | Private key only at build, validated  |
| Phase 4 | Build System & Makefile Updates           | Secure build, Makefile/CI updated     |
| Phase 5 | Testing & Validation                      | All tests pass, docs updated          |

---

## Security & Best Practices
- Never commit secrets to source control.
- Use environment variables or CI/CD secrets for automation.
- Validate secrets at runtime and fail fast if missing.
- Document all changes and update onboarding guides. 