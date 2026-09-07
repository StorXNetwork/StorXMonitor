// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

type stubTenantResolverDB struct {
	seller.DB
	domain *seller.ResellerDomain
}

func (s stubTenantResolverDB) ResellerDomains() seller.ResellerDomains {
	return stubTenantResolverDomains{domain: s.domain}
}

type stubTenantResolverDomains struct {
	domain *seller.ResellerDomain
}

func (s stubTenantResolverDomains) Get(ctx context.Context, id uuid.UUID) (*seller.ResellerDomain, error) {
	return nil, seller.ErrNotFound.New("")
}

func (s stubTenantResolverDomains) GetByResellerID(ctx context.Context, resellerID uuid.UUID) (*seller.ResellerDomain, error) {
	return nil, seller.ErrNotFound.New("")
}

func (s stubTenantResolverDomains) GetByDomain(ctx context.Context, domain string) (*seller.ResellerDomain, error) {
	if s.domain != nil && s.domain.Domain == domain {
		return s.domain, nil
	}
	return nil, seller.ErrNotFound.New("")
}

func (s stubTenantResolverDomains) Insert(ctx context.Context, domain *seller.ResellerDomain) (*seller.ResellerDomain, error) {
	return domain, nil
}

func (s stubTenantResolverDomains) Update(ctx context.Context, resellerID uuid.UUID, update seller.UpdateResellerDomainRequest) (*seller.ResellerDomain, error) {
	return nil, nil
}

func TestTenantResolverResellerHost(t *testing.T) {
	resellerID, err := uuid.FromString("22222222-2222-2222-2222-222222222222")
	require.NoError(t, err)

	server := &Server{
		config: Config{
			ExternalAddress: "https://cyberls.com",
		},
	}

	resolver := NewTenantResolver(nil, stubTenantResolverDB{
		domain: &seller.ResellerDomain{
			ResellerID: resellerID,
			Domain:     "portal.acme.com",
			Status:     seller.DomainStatusActive,
		},
	}, server)

	tenantCtx := resolver.ResolveTenantContext(context.Background(), "portal.acme.com")
	require.Equal(t, resellerID.String(), tenantCtx.TenantID)
	require.Equal(t, resellerID, tenantCtx.ResellerID)
}

func TestTenantResolverMainHost(t *testing.T) {
	server := &Server{
		config: Config{
			ExternalAddress: "https://cyberls.com",
		},
	}

	resolver := NewTenantResolver(nil, stubTenantResolverDB{}, server)
	tenantCtx := resolver.ResolveTenantContext(context.Background(), "cyberls.com")
	require.Empty(t, tenantCtx.TenantID)
	require.Equal(t, uuid.UUID{}, tenantCtx.ResellerID)
}
