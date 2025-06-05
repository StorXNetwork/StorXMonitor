# Swagger Setup Plan for StorX Monitor Server

## Overview
This document outlines the steps required to integrate Swagger/OpenAPI documentation into the StorX Monitor server.

## Prerequisites
- Go 1.16 or higher
- Basic understanding of OpenAPI/Swagger specifications
- Access to the codebase

## Implementation Steps

### 1. Add Required Dependencies
```bash
go get -u github.com/swaggo/swag/cmd/swag
go get -u github.com/swaggo/gin-swagger
go get -u github.com/swaggo/files
```

### 2. Create Swagger Base Configuration
1. Create a new file `docs/swagger.go` with basic Swagger configuration
2. Add package-level documentation
3. Define server information and base paths

### 3. Add Swagger Annotations
1. Add package-level annotations in `server.go`:
```go
// @title StorX Monitor API
// @version 1.0
// @description API documentation for StorX Monitor server
// @host localhost:10100
// @BasePath /api/v0
```

2. Add endpoint-level annotations for each API route:
- Auth endpoints
- Project endpoints
- Bucket endpoints
- API Key endpoints
- Payment endpoints
- Analytics endpoints

### 4. Create Swagger Models
1. Create `docs/models.go` to define request/response models
2. Document all DTOs and models used in API responses
3. Add proper model annotations

### 5. Generate Swagger Documentation
1. Add `swag init` command to generate documentation
2. Create a script to automate documentation generation
3. Add documentation generation to CI/CD pipeline

### 6. Integrate Swagger UI
1. Add Swagger UI endpoint to server
2. Configure Swagger UI options
3. Add security definitions for authentication

### 7. Testing
1. Test Swagger UI accessibility
2. Verify all endpoints are properly documented
3. Test authentication flows in Swagger UI
4. Validate request/response models

### 8. Documentation
1. Create README section for API documentation
2. Document how to use Swagger UI
3. Add examples for common API calls

## File Structure
```
.
├── docs/
│   ├── swagger.go
│   ├── models.go
│   └── swagger.json
├── server.go
└── swagger_setup_plan.md
```

## Implementation Details

### Auth Endpoints to Document
- POST /api/v0/auth/token
- POST /api/v0/auth/token-by-api-key
- POST /api/v0/auth/refresh-session
- POST /api/v0/auth/logout
- PATCH /api/v0/auth/account
- POST /api/v0/auth/account/change-password

### Project Endpoints to Document
- GET /api/v0/projects
- POST /api/v0/projects
- GET /api/v0/projects/{id}
- PATCH /api/v0/projects/{id}
- GET /api/v0/projects/{id}/members
- POST /api/v0/projects/{id}/invite/{email}

### Bucket Endpoints to Document
- GET /api/v0/buckets/bucket-names
- GET /api/v0/buckets/bucket-metadata
- GET /api/v0/buckets/usage-totals

### API Key Endpoints to Document
- POST /api/v0/api-keys/create/{projectID}
- GET /api/v0/api-keys/list-paged
- DELETE /api/v0/api-keys/delete-by-name
- DELETE /api/v0/api-keys/delete-by-ids

## Security Considerations
1. Document authentication methods
2. Add security definitions for:
   - API Key authentication
   - Cookie-based authentication
   - OAuth2 flows

## Next Steps
1. Review and approve the plan
2. Set up development environment
3. Begin implementation following the steps above
4. Regular testing and validation
5. Documentation review and updates

## Timeline
- Setup and configuration: 1 day
- Adding annotations: 2-3 days
- Testing and validation: 1-2 days
- Documentation and review: 1 day

Total estimated time: 5-7 days 