// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// Swagger models for audit log read/export APIs (used by swag only).

// AuditLogRecordSwagger is one row in GET /audit-logs responses.
type AuditLogRecordSwagger struct {
	ID         string `json:"id" example:"878b7ed7-e0b8-499f-b7ad-eae3af6153c6"`
	Timestamp  string `json:"timestamp" example:"2026-06-02T10:15:30Z"`
	ActorID    string `json:"actor_id,omitempty" example:"00000000-0000-0000-0000-000000000001"`
	Actor      string `json:"actor" example:"Jane Doe"`
	ActorEmail string `json:"actor_email,omitempty" example:"jane@example.com"`
	Action     string `json:"action" example:"AUTH_LOGIN"`
	Resource   string `json:"resource" example:"Session"`
	Message    string `json:"message" example:"User logged in"`
	IPAddress  string `json:"ip_address" example:"203.0.113.10"`
	Status     string `json:"status" example:"success" enums:"success,failed"`
}

// AuditLogListSwaggerResponse is returned from GET /audit-logs.
type AuditLogListSwaggerResponse struct {
	Items      []AuditLogRecordSwagger `json:"Items"`
	NextCursor string                  `json:"NextCursor" example:""`
	TotalCount int                     `json:"TotalCount" example:"42"`
}

// AuditLogActionsSwaggerResponse is returned from GET /audit-logs/actions.
type AuditLogActionsSwaggerResponse struct {
	Actions []string `json:"actions" example:"AUTH_LOGIN,AUTH_LOGOUT,PROJECT_CREATE"`
}
