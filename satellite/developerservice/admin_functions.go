// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developerservice

import (
	"context"
	"sort"
	"time"

	"storj.io/storj/satellite/console"
)

// DeveloperListResult contains paginated developer list with stats.
type DeveloperListResult struct {
	Developers         []*DeveloperWithStats
	LastSessionExpiry  []*time.Time
	FirstSessionExpiry []*time.Time
	TotalSessionCounts []int
	OAuthClientCounts  []int
	TotalCount         int
}

// DeveloperWithStats extends Developer with statistics.
type DeveloperWithStats struct {
	Developer          *console.Developer
	LastSessionExpiry  *time.Time
	FirstSessionExpiry *time.Time
	TotalSessionCount  int
	OAuthClientCount   int
}

// DeveloperStats contains aggregated statistics about developers.
type DeveloperStats struct {
	Total                  int
	Active                 int
	Inactive               int
	Deleted                int
	PendingDeletion        int
	LegalHold              int
	PendingBotVerification int
}

// LoginHistoryEntry represents a developer session/login history entry.
type LoginHistoryEntry struct {
	ID        string    `json:"id"`
	IPAddress string    `json:"ipAddress"`
	Status    int       `json:"status"`
	LoginTime time.Time `json:"loginTime"`
	ExpiresAt time.Time `json:"expiresAt"`
	IsActive  bool      `json:"isActive"`
}

// DeveloperDetailsResult contains developer details with login history.
type DeveloperDetailsResult struct {
	Developer *console.Developer
	Sessions  []LoginHistoryEntry
}

// GetAllDevelopersAdmin retrieves all developers with statistics (admin version).
// This supports pagination, filtering, and sorting.
func (s *Service) GetAllDevelopersAdmin(
	ctx context.Context,
	limit, offset int,
	statusFilter *int,
	createdAfter, createdBefore *time.Time,
	search string,
	hasActiveSession *bool,
	lastSessionAfter, lastSessionBefore *time.Time,
	sessionCountMin, sessionCountMax *int,
) (_ *DeveloperListResult, err error) {
	defer mon.Task()(&ctx)(&err)

	developers, lastSessionExpiry, firstSessionExpiry, totalSessionCounts, oauthClientCounts, totalCount, err := s.store.Developers().GetAllDevelopersWithStats(
		ctx,
		limit,
		offset,
		statusFilter,
		createdAfter,
		createdBefore,
		search,
		hasActiveSession,
		lastSessionAfter,
		lastSessionBefore,
		sessionCountMin,
		sessionCountMax,
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Convert to DeveloperWithStats
	developersWithStats := make([]*DeveloperWithStats, len(developers))
	for i, dev := range developers {
		developersWithStats[i] = &DeveloperWithStats{
			Developer:          dev,
			LastSessionExpiry:  lastSessionExpiry[i],
			FirstSessionExpiry: firstSessionExpiry[i],
			TotalSessionCount:  totalSessionCounts[i],
			OAuthClientCount:   oauthClientCounts[i],
		}
	}

	return &DeveloperListResult{
		Developers:         developersWithStats,
		LastSessionExpiry:  lastSessionExpiry,
		FirstSessionExpiry: firstSessionExpiry,
		TotalSessionCounts: totalSessionCounts,
		OAuthClientCounts:  oauthClientCounts,
		TotalCount:         totalCount,
	}, nil
}

// GetDeveloperStatsAdmin returns aggregated statistics about all developers (admin version).
func (s *Service) GetDeveloperStatsAdmin(ctx context.Context) (_ *DeveloperStats, err error) {
	defer mon.Task()(&ctx)(&err)

	total, active, inactive, deleted, pendingDeletion, legalHold, pendingBotVerification, err := s.store.Developers().GetDeveloperStats(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &DeveloperStats{
		Total:                  total,
		Active:                 active,
		Inactive:               inactive,
		Deleted:                deleted,
		PendingDeletion:        pendingDeletion,
		LegalHold:              legalHold,
		PendingBotVerification: pendingBotVerification,
	}, nil
}

// GetDeveloperDetailsAdmin returns developer details with login history (admin version).
func (s *Service) GetDeveloperDetailsAdmin(ctx context.Context, developerEmail string) (_ *DeveloperDetailsResult, err error) {
	defer mon.Task()(&ctx)(&err)

	// Get developer by email
	developer, err := s.store.Developers().GetByEmail(ctx, developerEmail)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Get all webapp sessions for this developer
	sessions, err := s.store.WebappSessionDevelopers().GetAllByDeveloperId(ctx, developer.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Convert sessions to response format
	entries := make([]LoginHistoryEntry, 0, len(sessions))
	now := time.Now()

	for _, session := range sessions {
		entries = append(entries, LoginHistoryEntry{
			ID:        session.ID.String(),
			IPAddress: session.IP,
			Status:    session.Status,
			LoginTime: session.ExpiresAt,
			ExpiresAt: session.ExpiresAt,
			IsActive:  session.ExpiresAt.After(now),
		})
	}

	// Sort by login time (most recent first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LoginTime.After(entries[j].LoginTime)
	})

	return &DeveloperDetailsResult{
		Developer: developer,
		Sessions:  entries,
	}, nil
}
