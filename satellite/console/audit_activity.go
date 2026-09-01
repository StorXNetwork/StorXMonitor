// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/StorXNetwork/StorXMonitor/satellite/console/auditlog"
	"github.com/StorXNetwork/StorXMonitor/satellite/tenancy"
)

// AuditLog returns the audit log service for read/export APIs.
func (s *Service) AuditLog() *auditlog.Service {
	return s.auditLogService
}

// CloseAuditLog drains async audit workers on shutdown.
func (s *Service) CloseAuditLog() error {
	if s.auditLogService == nil {
		return nil
	}
	return s.auditLogService.Close()
}

// RecordUserAudit logs a user action. Called from HTTP controllers only.
// On failure message is err.Error() with failed status; on success uses successMessage.
func (s *Service) RecordUserAudit(ctx context.Context, action, resource, successMessage string, err error) {
	msg, status := userAuditOutcome(successMessage, err)
	s.recordUserAuditFromContext(ctx, action, resource, msg, status)
}

// RecordUserAuditForUser logs when the user is already known (login, activation).
func (s *Service) RecordUserAuditForUser(ctx context.Context, user *User, action, resource, successMessage string, err error) {
	if s.auditLogService == nil || action == "" || successMessage == "" || user == nil {
		return
	}
	msg, status := userAuditOutcome(successMessage, err)
	s.recordUserAuditEvent(ctx, user, action, resource, msg, status)
}

// RecordUserAuditHTTP logs Backup-Tools or HTTP proxy results from controllers.
func (s *Service) RecordUserAuditHTTP(ctx context.Context, action, resource, successMessage string, httpStatus int, body []byte, err error) {
	msg, status := userAuditHTTPOutcome(successMessage, httpStatus, body, err)
	s.recordUserAuditFromContext(ctx, action, resource, msg, status)
}

// RecordUserAuditForEmail logs when the acting user is identified by email (login).
// Failed attempts are recorded when a matching account exists (verified, unverified, or pending verification).
func (s *Service) RecordUserAuditForEmail(ctx context.Context, email, action, resource, successMessage string, err error) {
	if s == nil || email == "" {
		return
	}
	user := s.lookupUserForAuditByEmail(ctx, email)
	if user == nil {
		return
	}
	s.RecordUserAuditForUser(ctx, user, action, resource, successMessage, err)
}

func (s *Service) lookupUserForAuditByEmail(ctx context.Context, email string) *User {
	if user := s.lookupUserForAuditFromStore(ctx, email, auditEmailLookupTenant); user != nil {
		return user
	}
	if user := s.lookupUserForAuditFromStore(ctx, email, auditEmailLookupGlobal); user != nil {
		return user
	}
	return s.lookupUserForAuditFromStore(ctx, email, auditEmailLookupGoogle)
}

type auditEmailLookupScope int

const (
	auditEmailLookupTenant auditEmailLookupScope = iota
	auditEmailLookupGlobal
	auditEmailLookupGoogle
)

func (s *Service) lookupUserForAuditFromStore(ctx context.Context, email string, scope auditEmailLookupScope) *User {
	var verified *User
	var unverified []User
	var err error

	switch scope {
	case auditEmailLookupTenant:
		var tenantID *string
		if tenantCtx := tenancy.GetContext(ctx); tenantCtx != nil {
			tenantID = &tenantCtx.TenantID
		}
		verified, unverified, err = s.store.Users().GetByEmailAndTenantWithUnverified(ctx, email, tenantID)
	case auditEmailLookupGlobal:
		verified, unverified, err = s.store.Users().GetByEmailWithUnverified(ctx, email)
	case auditEmailLookupGoogle:
		verified, unverified, err = s.store.Users().GetByEmailWithUnverified_google(ctx, email)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return userForAuditFromLookup(verified, unverified)
}

func userForAuditFromLookup(verified *User, unverified []User) *User {
	if verified != nil {
		return verified
	}
	for i := range unverified {
		if unverified[i].Status == PendingBotVerification || unverified[i].Status == LegalHold {
			return &unverified[i]
		}
	}
	if len(unverified) > 0 {
		return &unverified[0]
	}
	return nil
}

func userAuditOutcome(successMessage string, err error) (message string, status auditlog.Status) {
	if err != nil {
		return err.Error(), auditlog.StatusFailed
	}
	return successMessage, auditlog.StatusSuccess
}

func userAuditHTTPOutcome(successMessage string, httpStatus int, body []byte, err error) (message string, status auditlog.Status) {
	if err != nil {
		return err.Error(), auditlog.StatusFailed
	}
	if httpStatus < 200 || httpStatus >= 300 {
		if msg := parseAuditHTTPErrorBody(body); msg != "" {
			return msg, auditlog.StatusFailed
		}
		return fmt.Sprintf("request failed (HTTP %d)", httpStatus), auditlog.StatusFailed
	}
	return successMessage, auditlog.StatusSuccess
}

func parseAuditHTTPErrorBody(body []byte) string {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return ""
	}
	var resp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	if resp.Error != "" {
		return resp.Error
	}
	if resp.Message != "" {
		return resp.Message
	}
	return resp.Detail
}

func (s *Service) recordUserAuditFromContext(ctx context.Context, action, resource, message string, status auditlog.Status) {
	if s.auditLogService == nil || action == "" || message == "" {
		return
	}
	user, err := GetUser(ctx)
	if err != nil {
		return
	}
	s.recordUserAuditEvent(ctx, user, action, resource, message, status)
}

func (s *Service) recordUserAuditEvent(ctx context.Context, user *User, action, resource, message string, status auditlog.Status) {
	if status == "" {
		status = auditlog.StatusSuccess
	}
	sourceIP, _ := getRequestingIP(ctx)
	event := auditlog.Event{
		ActorID:   user.ID.String(),
		Action:    action,
		Resource:  resource,
		Message:   message,
		IPAddress: sourceIP,
		Status:    status,
	}
	auditSvc := s.auditLogService
	go func() {
		auditSvc.RecordAsync(context.Background(), event)
	}()
}
