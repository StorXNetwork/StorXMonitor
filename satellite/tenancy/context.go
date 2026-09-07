// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package tenancy

import (
	"context"
	"strings"

	"github.com/StorXNetwork/common/uuid"
)

// Context contains tenant information for a request.
type Context struct {
	// TenantID identifies which tenant this request belongs to.
	// Empty string ("") represents the main platform. For reseller hosts, this is the reseller UUID string.
	TenantID string
	// ResellerID is set when the request host resolves to an active reseller domain.
	ResellerID uuid.UUID
}

// tenancyKey is the context key for tenant Context.
type tenancyKey struct{}

// contextKey is the singleton instance of tenancyKey used for context storage.
var contextKey = tenancyKey{}

// defaultContext is the default tenant context (Storj tenant).
var defaultContext = &Context{TenantID: ""}

// FromHostname determines the tenant ID based on the request hostname.
func FromHostname(hostname string, lookupMap map[string]string) string {
	// Remove port if present.
	host := hostname
	if idx := strings.Index(hostname, ":"); idx != -1 {
		host = hostname[:idx]
	}

	// Check if the hostname matches any configured tenant hostname.
	if tenantID, ok := lookupMap[host]; ok {
		return tenantID
	}

	return ""
}

// WithContext attaches tenant context to the given context.Context.
func WithContext(ctx context.Context, tenantCtx *Context) context.Context {
	if tenantCtx == nil {
		tenantCtx = defaultContext
	}
	return context.WithValue(ctx, contextKey, tenantCtx)
}

// GetContext retrieves tenant context from the given context.Context.
// This function never returns nil - it returns a default Storj tenant context if no tenant context is set.
func GetContext(ctx context.Context) *Context {
	if tenantCtx, ok := ctx.Value(contextKey).(*Context); ok && tenantCtx != nil {
		return tenantCtx
	}
	return defaultContext
}

// TenantIDFromContext retrieves the tenant ID from the given context.Context.
func TenantIDFromContext(ctx context.Context) string {
	tenantCtx := GetContext(ctx)
	if tenantCtx != nil {
		return tenantCtx.TenantID
	}
	return ""
}

// ResellerIDFromContext retrieves the reseller ID from the given context.Context.
func ResellerIDFromContext(ctx context.Context) uuid.UUID {
	tenantCtx := GetContext(ctx)
	if tenantCtx != nil {
		return tenantCtx.ResellerID
	}
	return uuid.UUID{}
}

// IsResellerTenant returns true when the request resolved to a reseller domain.
func IsResellerTenant(ctx context.Context) bool {
	return ResellerIDFromContext(ctx) != (uuid.UUID{})
}

// DetachContext returns a context that keeps tenancy values but is not canceled when the parent ends.
// Use this for async email/notification work that must outlive the HTTP request.
func DetachContext(ctx context.Context) context.Context {
	return WithContext(context.Background(), GetContext(ctx))
}
