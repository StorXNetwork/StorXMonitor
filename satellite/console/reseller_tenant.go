// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"strings"

	"go.uber.org/zap"

	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/tenancy"
	"github.com/StorXNetwork/common/uuid"
)

// ResellerTenantLookup resolves reseller-specific external URLs, email branding, and SMTP.
type ResellerTenantLookup interface {
	ResellerExternalAddress(ctx context.Context, resellerID uuid.UUID) string
	ResellerMailBranding(ctx context.Context, resellerID uuid.UUID) (mailservice.WhiteLabelConfig, bool)
	ResellerMailSMTP(ctx context.Context, resellerID uuid.UUID) (mailservice.Config, bool)
}

// SetResellerTenantLookup wires reseller DB-backed tenant resolution.
func (s *Service) SetResellerTenantLookup(lookup ResellerTenantLookup) {
	s.resellerTenantLookup = lookup
}

// ExternalAddressForContext returns the public console URL for the current tenant.
func (s *Service) ExternalAddressForContext(ctx context.Context) string {
	resellerID := tenancy.ResellerIDFromContext(ctx)
	if resellerID != (uuid.UUID{}) && s.resellerTenantLookup != nil {
		if addr := s.resellerTenantLookup.ResellerExternalAddress(ctx, resellerID); addr != "" {
			return addr
		}
	}

	addr := strings.TrimSpace(s.satelliteAddress)
	if addr == "" {
		return "/"
	}
	if !strings.HasSuffix(addr, "/") {
		addr += "/"
	}
	return addr
}

// ResellerMailBranding returns tenant-specific email branding for reseller contexts.
func (s *Service) ResellerMailBranding(ctx context.Context) (mailservice.WhiteLabelConfig, bool) {
	resellerID := tenancy.ResellerIDFromContext(ctx)
	if resellerID == (uuid.UUID{}) || s.resellerTenantLookup == nil {
		return mailservice.WhiteLabelConfig{}, false
	}
	return s.resellerTenantLookup.ResellerMailBranding(ctx, resellerID)
}

// ResellerMailSender returns a seller-dashboard SMTP sender when configured for this reseller domain.
// Otherwise returns false so mailservice falls back to satellite mail.* credentials.
func (s *Service) ResellerMailSender(ctx context.Context) (mailservice.Sender, bool) {
	resellerID := tenancy.ResellerIDFromContext(ctx)
	if resellerID == (uuid.UUID{}) || s.resellerTenantLookup == nil {
		return nil, false
	}
	cfg, ok := s.resellerTenantLookup.ResellerMailSMTP(ctx, resellerID)
	if !ok {
		return nil, false
	}
	sender, err := mailservice.CreateSender(cfg)
	if err != nil {
		s.log.Warn("reseller SMTP sender unavailable; using default mail config",
			zap.String("reseller_id", resellerID.String()),
			zap.Error(err),
		)
		return nil, false
	}
	return sender, true
}
