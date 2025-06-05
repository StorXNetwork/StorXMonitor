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

// @host localhost:10100
// @BasePath /api/v0

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name _tokenKey

// @tag.name auth
// @tag.description Authentication operations

// @tag.name projects
// @tag.description Project management operations

// @tag.name buckets
// @tag.description Bucket management operations

// @tag.name api-keys
// @tag.description API key management operations

// @tag.name payments
// @tag.description Payment and billing operations

// @tag.name analytics
// @tag.description Analytics operations

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
