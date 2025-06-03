# Work Plan: Implement OAuth2 Developer Client Registration (client_id & client_secret)

This document outlines the step-by-step plan to add an endpoint for developers to create OAuth2 clients (client_id and client_secret) in the StorXMonitor project. The plan covers database schema changes, migration, service layer, controller, and route steps.

---

## ✅ 1. Database Layer (Complete)

- **DBX model and methods for `developer_oauth_client` are implemented.**
- **Migration for the new table is written and applied.**
- **Go ORM code is generated.**

### 1.1. Design Table Schema
- **Table Name:** `developer_oauth_clients` (or similar)
- **Fields:**
  - `id` (UUID, PK)
  - `developer_id` (UUID, FK to developers)
  - `client_id` (string, unique)
  - `client_secret` (string, hashed)
  - `name` (string, optional, for display)
  - `redirect_uris` (text/JSON, for OAuth2)
  - `created_at` (timestamp)
  - `updated_at` (timestamp)

### 1.2. Update DBX Schema
- Add a model block for developer_oauth_client:
  ```
  model developer_oauth_client (
      key id
      index ( fields developer_id )
      field id blob
      field developer_id blob
      field client_id text
      field client_secret text
      field name text
      field redirect_uris text
      field created_at timestamp ( autoinsert )
      field updated_at timestamp ( updatable )
  )
  ```
- Add CRUD and read methods:
  ```
  create developer_oauth_client ( )
  update developer_oauth_client ( where developer_oauth_client.id = ? )
  delete developer_oauth_client ( where developer_oauth_client.id = ? )
  delete developer_oauth_client ( where developer_oauth_client.developer_id = ? )

  read all (
      select developer_oauth_client
      where developer_oauth_client.developer_id = ?
  )
  read one (
      select developer_oauth_client
      where developer_oauth_client.id = ?
  )
  ```
- Use `blob` for UUID fields, `text` for strings, and `timestamp` for time fields, matching your conventions.
- Use `autoinsert` and `updatable` as needed for timestamps and updatable fields.
- Add indexes for foreign keys (e.g., `developer_id`).

### 1.3. Generate Go ORM Code [manual step]
- Run the DBX code generation command to update Go files (e.g., `go generate ./...` or project-specific command).
- This will update `satellitedb/dbx/developer_dbx.go` and related files.

### 1.4. Write Migration
- In `satellitedb/migrate.go`, add a migration to create the new table using the migration step pattern as shown in other migrations.
- Example:
  ```go
  {
    DB:          &db.migrationDB,
    Description: "Create developer_oauth_clients table",
    Version:     <next_version>, // e.g., 283
    Action: migrate.SQL{
      `CREATE TABLE developer_oauth_clients (
        id uuid PRIMARY KEY,
        developer_id uuid REFERENCES developers(id),
        client_id text UNIQUE NOT NULL,
        client_secret text NOT NULL,
        name text,
        redirect_uris text,
        created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
      );`,
    },
  },
  ```
- Replace `<next_version>` with the next available migration version number.

---

## 2. Repository/Storage Layer (satellitedb/developers.go)

- **Struct:**  
  The repository is implemented as a `developers` struct with a `db *satelliteDB` field.
- **CRUD Methods:**  
  For each model, you implement methods like:
  - `Insert(ctx, *console.Developer) (*console.Developer, error)`
  - `Get(ctx, id uuid.UUID) (*console.Developer, error)`
  - `Update(ctx, id uuid.UUID, updateRequest console.UpdateDeveloperRequest) error`
  - `Delete(ctx, id uuid.UUID) error`
  - Plus custom queries (e.g., `GetByEmailWithUnverified`)
- **DBX Integration:**  
  These methods use the generated DBX methods (e.g., `db.Create_Developer`, `db.Get_Developer_By_Id`, etc.).
- **Entity Conversion:**  
  Use helper functions (e.g., `developerFromDBX`) to convert DBX structs to your domain structs.

**For `developer_oauth_client`, you should:**
- Implement methods like:
  - `InsertOAuthClient(ctx, *console.OAuthClient) (*console.OAuthClient, error)`
  - `GetOAuthClient(ctx, id uuid.UUID) (*console.OAuthClient, error)`
  - `UpdateOAuthClient(ctx, id uuid.UUID, updateRequest console.UpdateOAuthClientRequest) error`
  - `UpdateOAuthClientStatus(ctx, id uuid.UUID, status int, updatedAt time.Time) error`
  - `DeleteOAuthClient(ctx, id uuid.UUID) error`
  - `ListOAuthClientsByDeveloper(ctx, developerID uuid.UUID) ([]console.OAuthClient, error)`
- Use DBX-generated methods for all DB operations.
- Add conversion helpers as needed.

---

## 3. Service Layer (satellite/console/service.go)

- **Struct:**  
  The service is implemented as a `Service` struct, which holds a reference to the repository/storage layer.
- **Business Logic:**  
  Service methods:
  - Accept context and domain structs.
  - Call repository methods for DB operations.
  - Handle business logic, validation, and security (e.g., hashing secrets, checking for duplicates).
  - Use audit logging and metrics as needed.
- **Example Patterns:**  
  - `CreateDeveloper`, `GetDeveloperByEmailWithUnverified`, `UpdateAccountDeveloper`, etc.
  - Use transactions for multi-step operations.
  - Use helper methods for logging and error handling.

**For `developer_oauth_client`, you should:**
- Add methods like:
  - `CreateDeveloperOAuthClient(ctx, req CreateOAuthClientRequest) (*OAuthClient, error)`
    - Validate input, check for duplicates, hash secrets, call repository.
  - `ListDeveloperOAuthClients(ctx, developerID uuid.UUID) ([]OAuthClient, error)`
    - Fetch all clients for a developer.
  - `DeleteDeveloperOAuthClient(ctx, id uuid.UUID) error`
    - Remove a client by ID.
  - `UpdateDeveloperOAuthClient(ctx, id uuid.UUID, req UpdateOAuthClientRequest) error`
    - Update client name, redirect URIs, etc.
  - `UpdateDeveloperOAuthClientStatus(ctx, id uuid.UUID, status int) error`
    - Update client status (active, revoked, etc).
- Use audit logging and error handling as in other service methods.

---

## 4. Controller Layer (satellite/console/consoleweb/consoleapi/developer.go)

- **Struct:**  
  The controller is implemented as a `DeveloperAuth` struct, which holds a reference to the service.
- **HTTP Handlers:**  
  - Parse/validate HTTP request data.
  - Call service methods.
  - Return JSON responses and handle errors.
  - Use authentication middleware as needed.
- **Example Patterns:**  
  - `Register`, `GetAccount`, `ChangePassword`, etc.

**For `developer_oauth_client`, you should:**
- Add handlers like:
  - `CreateOAuthClient(w http.ResponseWriter, r *http.Request)`
    - Parse JSON, call `service.CreateDeveloperOAuthClient`, return client_id and (only once) client_secret.
  - `ListOAuthClients(w http.ResponseWriter, r *http.Request)`
    - Call `service.ListDeveloperOAuthClients`, return list.
  - `DeleteOAuthClient(w http.ResponseWriter, r *http.Request)`
    - Parse ID, call `service.DeleteDeveloperOAuthClient`.
  - `UpdateOAuthClient(w http.ResponseWriter, r *http.Request)`
    - Parse ID and update fields, call `service.UpdateDeveloperOAuthClient`.
  - `UpdateOAuthClientStatus(w http.ResponseWriter, r *http.Request)`
    - Parse ID and status, call `service.UpdateDeveloperOAuthClientStatus`.
- Use consistent error handling and response formatting.

---

## 5. Route Registration

Register the following endpoints (all require authentication):

| Method | Path                                 | Description                        |
|--------|--------------------------------------|------------------------------------|
| POST   | `/oauth2/clients`                    | Create a new OAuth client          |
| GET    | `/oauth2/clients`                    | List all OAuth clients for user    |
| DELETE | `/oauth2/clients/{id}`               | Delete an OAuth client by ID       |
| PATCH  | `/oauth2/clients/{id}/status`        | Update OAuth client status         |

---

## 5.1 Example curl Requests

> Replace `$TOKEN` with your developer auth token and `$ID` with the OAuth client UUID.

### Create OAuth Client

```sh
curl -X POST https://<host>/api/v0/developer/auth/oauth2/clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "redirect_uris": "https://myapp.com/callback"
  }'
```

### List OAuth Clients
```sh
curl -X GET https://<host>/api/v0/developer/auth/oauth2/clients \
  -H "Authorization: Bearer $TOKEN"
```

### Delete OAuth Client
```sh
curl -X DELETE https://<host>/api/v0/developer/auth/oauth2/clients/$ID \
  -H "Authorization: Bearer $TOKEN"
```

### Update OAuth Client Status
```sh
curl -X PATCH https://<host>/api/v0/developer/auth/oauth2/clients/$ID/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": 1
  }'
```

---

### Developer Registration and Login

#### Register Developer
```sh
curl -X POST https://<host>/api/v0/developer/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Your Name",
    "email": "your@email.com",
    "password": "YourSecurePassword"
  }'
```

#### Login Developer
```sh
curl -X POST https://<host>/api/v0/developer/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your@email.com",
    "password": "YourSecurePassword"
  }'
```

> Use the returned token for all authenticated developer API requests.

---

## 6. Testing

### 6.1. Table-Driven Tests
- Add table-driven tests for:
  - Service methods (create, list, update, status update, delete)
  - Controller handlers (API endpoints)
- Place tests in appropriate `*_test.go` files.

---

## 7. Documentation & Security

- Document the API endpoints (request/response, authentication required).
- Ensure client secrets are hashed in DB and never returned in plaintext after creation.
- Follow best practices for OAuth2 client management.

---

## 8. Summary Checklist

- [x] Update DBX schema and generate Go code
- [x] Write DB migration
- [x] Implement repository methods in `developers.go` (including update and status update)
- [x] Add service methods in `service.go` (including update and status update)
- [x] Implement controller handlers in `developer.go` (including update and status update)
- [x] Register routes in `server.go` (including update and status update)
- [ ] Add table-driven tests
- [ ] Document endpoints and security considerations
- [x] Add example curl requests for all endpoints

---

### Example Method Signatures (Updated)

**Repository:**
```go
func (dev *developers) InsertOAuthClient(ctx context.Context, client *console.OAuthClient) (*console.OAuthClient, error)
func (dev *developers) GetOAuthClient(ctx context.Context, id uuid.UUID) (*console.OAuthClient, error)
func (dev *developers) ListOAuthClientsByDeveloper(ctx context.Context, developerID uuid.UUID) ([]console.OAuthClient, error)
func (dev *developers) DeleteOAuthClient(ctx context.Context, id uuid.UUID) error
func (dev *developers) UpdateOAuthClientStatus(ctx context.Context, id uuid.UUID, status int, updatedAt time.Time) error
```

**Service:**
```go
func (s *Service) CreateDeveloperOAuthClient(ctx context.Context, req CreateOAuthClientRequest) (*OAuthClient, error)
func (s *Service) ListDeveloperOAuthClients(ctx context.Context, developerID uuid.UUID) ([]OAuthClient, error)
func (s *Service) DeleteDeveloperOAuthClient(ctx context.Context, id uuid.UUID) error
func (s *Service) UpdateDeveloperOAuthClientStatus(ctx context.Context, id uuid.UUID, status int) error
```

**Controller:**
```go
func (a *DeveloperAuth) CreateOAuthClient(w http.ResponseWriter, r *http.Request)
func (a *DeveloperAuth) ListOAuthClients(w http.ResponseWriter, r *http.Request)
func (a *DeveloperAuth) DeleteOAuthClient(w http.ResponseWriter, r *http.Request)
func (a *DeveloperAuth) UpdateOAuthClientStatus(w http.ResponseWriter, r *http.Request)
```

---

**References:**
- [OAuth2 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- Project's DBX/DB migration and service architecture 

## Development Flow (Project Convention)

1. **DBX Model/Methods:**  
   Define the model and all required methods in `developer.dbx` as above.
2. **Generate Go Code:**  
   Run the DBX code generator to produce Go structs and repository methods.
3. **Repository Layer:**  
   Use the generated Go code in `satellitedb/developers.go` to implement repository functions.
4. **Service Layer:**  
   Add business logic in `service.go` using the repository.
5. **Controller Layer:**  
   Expose endpoints in the API controller (e.g., `developer.go`).
6. **Route Registration:**  
   Register endpoints in `server.go`.
7. **Testing:**  
   Write table-driven tests for service and controller logic. 