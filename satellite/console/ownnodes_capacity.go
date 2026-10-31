// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"github.com/StorXNetwork/common/uuid"
)

const (
	// MinOwnNodesRequired is the minimum claimed org nodes needed to run
	// backups (and activate jobs) when storage mode is own_nodes.
	MinOwnNodesRequired = 10

	ownNodesInsufficientMessage = "Connect at least %d storage nodes to your node group before starting backups. You currently have %d."
)

var (
	// ErrOwnNodesInsufficient is returned when own_nodes mode is active but
	// fewer than MinOwnNodesRequired nodes are claimed.
	ErrOwnNodesInsufficient = errs.Class("own nodes insufficient")
)

// OwnNodesCapacityStatus describes whether the user can run backups on their nodes.
type OwnNodesCapacityStatus struct {
	Mode      string `json:"mode"`
	Required  bool   `json:"required"`
	NodeCount int    `json:"nodeCount"`
	MinNodes  int    `json:"minNodes"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message,omitempty"`
	OrgID     string `json:"orgId,omitempty"`
}

// GetOwnNodesCapacityStatus returns readiness for the current session user.
func (s *Service) GetOwnNodesCapacityStatus(ctx context.Context) (status *OwnNodesCapacityStatus, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	return s.ownNodesCapacityForUser(ctx, user.ID)
}

// ownNodesCapacityForUser computes readiness for a user.
// When mode is not own_nodes, backups are not gated by node count (Ready=true).
func (s *Service) ownNodesCapacityForUser(ctx context.Context, userID uuid.UUID) (*OwnNodesCapacityStatus, error) {
	status := &OwnNodesCapacityStatus{
		Mode:     StorageDestinationDefault,
		Required: false,
		MinNodes: MinOwnNodesRequired,
		Ready:    true,
	}

	dest, err := s.store.StorageDestinations().GetByUserID(ctx, userID)
	if err != nil {
		if ErrStorageDestinationNotFound.Has(err) {
			return status, nil
		}
		return nil, Error.Wrap(err)
	}
	status.Mode = dest.Mode
	if dest.Mode != StorageDestinationOwnNodes {
		return status, nil
	}

	status.Required = true
	orgID, err := s.resolveOwnNodesOrgIDForUser(ctx, userID)
	if err != nil {
		// Node group missing — treat as not ready.
		status.Ready = false
		status.NodeCount = 0
		status.Message = fmt.Sprintf(ownNodesInsufficientMessage, MinOwnNodesRequired, 0)
		return status, nil
	}
	status.OrgID = orgID.String()

	count, err := s.store.OrgNodes().CountByOrgID(ctx, orgID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	status.NodeCount = count
	if count >= MinOwnNodesRequired {
		status.Ready = true
		return status, nil
	}
	status.Ready = false
	status.Message = fmt.Sprintf(ownNodesInsufficientMessage, MinOwnNodesRequired, count)
	return status, nil
}

// requireOwnNodesReadyForActivation errors when activating backups without enough nodes.
func (s *Service) requireOwnNodesReadyForActivation(ctx context.Context, userID uuid.UUID) error {
	status, err := s.ownNodesCapacityForUser(ctx, userID)
	if err != nil {
		return err
	}
	if status.Required && !status.Ready {
		return ErrOwnNodesInsufficient.New("%s", status.Message)
	}
	return nil
}

// enforceOwnNodesInactiveJobs deactivates all active Backup-Tools jobs when
// own_nodes mode is under MinOwnNodesRequired. Uses existing PUT /users-groups/jobs/active
// with active=false and empty job_ids (deactivate-all). Best-effort only.
func (s *Service) enforceOwnNodesInactiveJobs(ctx context.Context, tokenKey string, status *OwnNodesCapacityStatus) {
	if status == nil || !status.Required || status.Ready {
		return
	}
	if strings.TrimSpace(tokenKey) == "" || s.backupToolsURL == "" {
		return
	}

	msg := status.Message
	if msg == "" {
		msg = fmt.Sprintf(ownNodesInsufficientMessage, MinOwnNodesRequired, status.NodeCount)
	}
	payload, err := json.Marshal(map[string]interface{}{
		"active":  false,
		"message": msg,
	})
	if err != nil {
		return
	}
	body, code, reqErr := s.backupToolsRequest(ctx, http.MethodPut, "/users-groups/jobs/active", tokenKey, "", payload)
	if reqErr != nil {
		s.log.Warn("own-nodes: failed to deactivate Backup-Tools jobs",
			zap.Error(reqErr),
			zap.Int("nodeCount", status.NodeCount),
		)
		return
	}
	if code < 200 || code >= 300 {
		s.log.Warn("own-nodes: Backup-Tools jobs/active deactivate-all returned non-OK",
			zap.Int("status", code),
			zap.Int("nodeCount", status.NodeCount),
			zap.ByteString("body", body),
		)
		return
	}
	s.log.Info("own-nodes: deactivated all Backup-Tools jobs under min nodes",
		zap.Int("nodeCount", status.NodeCount),
	)
}

// mergeOwnNodesIntoJSONObject adds own_nodes capacity fields onto a JSON object body.
// If body is not a JSON object, returns body unchanged.
func mergeOwnNodesIntoJSONObject(body []byte, key string, status *OwnNodesCapacityStatus) []byte {
	if status == nil || len(body) == 0 || body[0] != '{' {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return body
	}
	obj[key] = raw
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

func mergeOwnNodesCreateFlags(body []byte, jobsCreatedInactive bool) []byte {
	if !jobsCreatedInactive || len(body) == 0 || body[0] != '{' {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	raw, err := json.Marshal(true)
	if err != nil {
		return body
	}
	obj["jobs_created_inactive"] = raw
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
