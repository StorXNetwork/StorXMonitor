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
	"github.com/StorXNetwork/common/uuid"
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

// AuditServiceLabel is the name shown for a backup service in an audit message.
func AuditServiceLabel(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "gmail":
		return "Gmail"
	case "google_drive", "drive":
		return "Drive"
	case "google_contacts", "contacts":
		return "Contacts"
	case "google_calendar", "calendar":
		return "Calendar"
	case "google_photos", "photos":
		return "Photos"
	case "outlook", "outlook_mail":
		return "Outlook mail"
	case "outlook_calendar":
		return "Outlook calendar"
	case "outlook_contacts":
		return "Outlook contacts"
	case "outlook_onedrive", "onedrive":
		return "OneDrive"
	default:
		return strings.TrimSpace(service)
	}
}

// InvitationAcceptAuditMessage is the audit text for an accepted project invitation.
// The owner copy names the invited user who accepted.
func InvitationAcceptAuditMessage(projectName, inviteeEmail string, forOwner bool) string {
	name := strings.TrimSpace(projectName)
	if name == "" {
		name = "the project"
	}
	base := "Invitation to " + name + " accepted"
	if !forOwner {
		return base
	}
	return InviteeOwnerAuditMessage(base, inviteeEmail)
}

// InvitationDeclineAuditMessage is the audit text for a declined project invitation.
// The owner copy names the invited user who declined.
func InvitationDeclineAuditMessage(projectName, inviteeEmail string, forOwner bool) string {
	name := strings.TrimSpace(projectName)
	if name == "" {
		name = "the project"
	}
	base := "Invitation to " + name + " declined"
	if !forOwner {
		return base
	}
	return InviteeOwnerAuditMessage(base, inviteeEmail)
}

// RecordProjectInvitationResponse writes the invitee's accept or decline on that user's audit log.
// The project owner and the inviter copies are written from RespondToProjectInvitation, because
// this screen lists only the signed-in user's own rows.
func (s *Service) RecordProjectInvitationResponse(ctx context.Context, projectID uuid.UUID, response ProjectInvitationResponse, callErr error) {
	if s == nil || s.auditLogService == nil {
		return
	}
	user, err := GetUser(ctx)
	if err != nil || user == nil {
		return
	}

	projectName := ""
	if proj, pErr := s.GetProjectNoAuth(ctx, projectID); pErr == nil && proj != nil {
		projectName = proj.Name
	}

	action := "PROJECT_INVITATION_ACCEPT"
	message := InvitationAcceptAuditMessage(projectName, "", false)
	if response == ProjectInvitationDecline {
		action = "PROJECT_INVITATION_DECLINE"
		message = InvitationDeclineAuditMessage(projectName, "", false)
	} else if response != ProjectInvitationAccept {
		action = "PROJECT_INVITATION_RESPOND"
		message = "Invitation to " + displayProjectName(projectName) + " responded"
	}
	s.RecordUserAuditForUser(ctx, user, action, displayProjectName(projectName), message, callErr)
}

// recordInvitationResponseOnProjectAudit copies a successful accept or decline onto the
// project owner and the inviter. Audit log pages only list the signed-in user, and the
// invite itself is already stored on the inviter.
func (s *Service) recordInvitationResponseOnProjectAudit(ctx context.Context, invitee *User, proj *Project, inviterID *uuid.UUID, response ProjectInvitationResponse) {
	if s == nil || s.auditLogService == nil || invitee == nil || proj == nil {
		return
	}
	action := "PROJECT_INVITATION_ACCEPT"
	message := InvitationAcceptAuditMessage(proj.Name, invitee.Email, true)
	if response == ProjectInvitationDecline {
		action = "PROJECT_INVITATION_DECLINE"
		message = InvitationDeclineAuditMessage(proj.Name, invitee.Email, true)
	} else if response != ProjectInvitationAccept {
		return
	}

	resource := invitee.Email
	if strings.TrimSpace(resource) == "" {
		resource = displayProjectName(proj.Name)
	}
	seen := map[uuid.UUID]struct{}{invitee.ID: {}}
	write := func(id uuid.UUID) {
		if id.IsZero() {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		actor, getErr := s.store.Users().Get(ctx, id)
		if getErr != nil || actor == nil {
			return
		}
		s.RecordUserAuditForUser(ctx, actor, action, resource, message, nil)
	}
	write(proj.OwnerID)
	if inviterID != nil {
		write(*inviterID)
	}
}

// InvitationLeaveAuditMessage is the audit text when an invited user leaves a project.
// The owner copy names the invited user who left.
func InvitationLeaveAuditMessage(projectName, inviteeEmail string, forOwner bool) string {
	name := strings.TrimSpace(projectName)
	if name == "" {
		name = "the project"
	}
	if !forOwner {
		return "Left the invitation to " + name
	}
	email := strings.TrimSpace(inviteeEmail)
	if email == "" {
		email = "the invited user"
	}
	return "Invited user " + email + " left the invitation to " + name
}

// RecordProjectMemberRemoval writes a removal on the acting user's audit log.
// When that user leaves their own invitation, the project owner gets the same event.
func (s *Service) RecordProjectMemberRemoval(ctx context.Context, projectID uuid.UUID, emails []string, callErr error) {
	if s == nil || s.auditLogService == nil {
		return
	}
	user, err := GetUser(ctx)
	if err != nil || user == nil {
		return
	}

	selfLeave := len(emails) == 1 && strings.EqualFold(strings.TrimSpace(emails[0]), strings.TrimSpace(user.Email))
	if !selfLeave {
		s.RecordUserAudit(ctx, "PROJECT_MEMBERS_DELETE", "Project members", "Project members removed", callErr)
		return
	}

	projectName := ""
	var owner *User
	if proj, pErr := s.GetProjectNoAuth(ctx, projectID); pErr == nil && proj != nil {
		projectName = proj.Name
		if proj.OwnerID != user.ID && !proj.OwnerID.IsZero() {
			if loaded, oErr := s.store.Users().Get(ctx, proj.OwnerID); oErr == nil {
				owner = loaded
			}
		}
	}

	resource := displayProjectName(projectName)
	s.RecordUserAuditForUser(ctx, user, "PROJECT_INVITATION_LEAVE", resource, InvitationLeaveAuditMessage(projectName, user.Email, false), callErr)
	if callErr == nil && owner != nil {
		s.RecordUserAuditForUser(ctx, owner, "PROJECT_INVITATION_LEAVE", user.Email, InvitationLeaveAuditMessage(projectName, user.Email, true), nil)
	}
}

func displayProjectName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "the project"
	}
	return name
}

// InviteeOwnerAuditMessage is the text stored on the inviter's audit log.
func InviteeOwnerAuditMessage(base, inviteeEmail string) string {
	base = strings.TrimSpace(base)
	inviteeEmail = strings.TrimSpace(inviteeEmail)
	if base == "" {
		base = "Invited user operation"
	}
	if inviteeEmail == "" {
		return base
	}
	return base + " by invited user " + inviteeEmail
}

// RecordInviteeAuditForOwner copies a restore or download result onto the project
// owner audit log when the session user is an invited member, not the owner.
// An empty projectID copies the event to every project owner this user was invited into.
func (s *Service) RecordInviteeAuditForOwner(ctx context.Context, projectID, action, resource, successMessage string, httpStatus int, body []byte, callErr error) {
	if s == nil || s.auditLogService == nil || action == "" {
		return
	}
	user, err := GetUser(ctx)
	if err != nil || user == nil {
		return
	}
	msg, status := userAuditHTTPOutcome(successMessage, httpStatus, body, callErr)
	ownerMsg := InviteeOwnerAuditMessage(msg, user.Email)

	ownerIDs := s.inviteAuditOwnerIDs(ctx, user.ID, projectID)
	seen := map[uuid.UUID]struct{}{}
	for _, ownerID := range ownerIDs {
		if ownerID == user.ID {
			continue
		}
		if _, ok := seen[ownerID]; ok {
			continue
		}
		seen[ownerID] = struct{}{}
		owner, getErr := s.store.Users().Get(ctx, ownerID)
		if getErr != nil || owner == nil {
			continue
		}
		s.recordUserAuditEvent(ctx, owner, action, resource, ownerMsg, status)
	}
}

func (s *Service) inviteAuditOwnerIDs(ctx context.Context, userID uuid.UUID, projectID string) []uuid.UUID {
	if idText := strings.TrimSpace(projectID); idText != "" {
		projectUUID, parseErr := uuid.FromString(idText)
		if parseErr != nil {
			return nil
		}
		member, memberErr := s.isProjectMember(ctx, userID, projectUUID)
		if memberErr != nil || member.project == nil || member.project.OwnerID == userID {
			return nil
		}
		return []uuid.UUID{member.project.OwnerID}
	}

	memberships, err := s.store.ProjectMembers().GetByMemberID(ctx, userID)
	if err != nil {
		return nil
	}
	var owners []uuid.UUID
	for _, membership := range memberships {
		project, getErr := s.store.Projects().Get(ctx, membership.ProjectID)
		if getErr != nil || project == nil || project.OwnerID == userID {
			continue
		}
		owners = append(owners, project.OwnerID)
	}
	return owners
}
