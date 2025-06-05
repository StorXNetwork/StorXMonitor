package docs

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"error message"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// Project represents a project
type Project struct {
	ID          string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Name        string `json:"name" example:"My Project"`
	Description string `json:"description" example:"Project description"`
	CreatedAt   string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

// Bucket represents a bucket
type Bucket struct {
	Name      string `json:"name" example:"my-bucket"`
	CreatedAt string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

// APIKey represents an API key
type APIKey struct {
	ID        string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Name      string `json:"name" example:"My API Key"`
	CreatedAt string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

// User represents a user
type User struct {
	ID        string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Email     string `json:"email" example:"user@example.com"`
	FullName  string `json:"fullName" example:"John Doe"`
	CreatedAt string `json:"createdAt" example:"2024-03-20T10:00:00Z"`
}

// Pagination represents pagination parameters
type Pagination struct {
	Limit  int `json:"limit" example:"10"`
	Offset int `json:"offset" example:"0"`
}

// PaginatedResponse represents a paginated response
type PaginatedResponse struct {
	Items      interface{} `json:"items"`
	TotalCount int         `json:"totalCount" example:"100"`
	Limit      int         `json:"limit" example:"10"`
	Offset     int         `json:"offset" example:"0"`
}
