// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/StorXMonitor/satellite/tenancy"
)

// TenantResolver resolves request host to tenant context via reseller_domains.
type TenantResolver struct {
	log      *zap.Logger
	sellerDB seller.DB
	server   *Server
}

// NewTenantResolver returns middleware that maps host to tenant_id = reseller_id.
func NewTenantResolver(log *zap.Logger, sellerDB seller.DB, server *Server) *TenantResolver {
	return &TenantResolver{
		log:      log,
		sellerDB: sellerDB,
		server:   server,
	}
}

// Middleware injects tenancy context from the request host.
func (r *TenantResolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var err error
		ctx := req.Context()
		defer mon.Task()(&ctx)(&err)

		tenantCtx := r.resolve(ctx, requestHost(req))
		ctx = tenancy.WithContext(ctx, tenantCtx)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func (r *TenantResolver) resolve(ctx context.Context, host string) *tenancy.Context {
	if r.server != nil && r.server.isMainConsoleHost(host) {
		return &tenancy.Context{}
	}
	if r.sellerDB == nil || host == "" {
		return &tenancy.Context{}
	}

	domain, err := r.sellerDB.ResellerDomains().GetByDomain(ctx, host)
	if err != nil {
		if !seller.ErrNotFound.Has(err) {
			r.log.Warn("failed to resolve reseller domain for host", zap.String("host", host), zap.Error(err))
		}
		return &tenancy.Context{}
	}
	if domain.Status != seller.DomainStatusActive {
		return &tenancy.Context{}
	}

	resellerID := domain.ResellerID
	return &tenancy.Context{
		TenantID:   resellerID.String(),
		ResellerID: resellerID,
	}
}

// ResolveTenantContext resolves host to tenant context without HTTP middleware (for tests).
func (r *TenantResolver) ResolveTenantContext(ctx context.Context, host string) *tenancy.Context {
	return r.resolve(ctx, host)
}
