// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developer

import (
	"context"
	"sort"
	"time"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
)

// DeveloperListResult contains paginated developer list with stats.
type DeveloperListResult struct {
	Developers         []*DeveloperWithStats
	LastSessionExpiry  []*time.Time
	FirstSessionExpiry []*time.Time
	TotalSessionCounts []int
	OAuthClientCounts  []int
	TotalUserCounts    []int // Total unique users per developer
	ActiveUserCounts   []int // Active users (last 30 days) per developer
	TotalCount         int
}

// DeveloperWithStats extends Developer with statistics.
type DeveloperWithStats struct {
	Developer          *console.Developer
	LastSessionExpiry  *time.Time
	FirstSessionExpiry *time.Time
	TotalSessionCount  int
	OAuthClientCount   int
	TotalUsers         int // Total unique users who accessed this developer's applications
	ActiveUsers        int // Active users (last 30 days) who accessed this developer's applications
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

	developers, lastSessionExpiry, firstSessionExpiry, totalSessionCounts, oauthClientCounts, totalUserCounts, activeUserCounts, totalCount, err := s.store.Developers().GetAllDevelopersWithStats(
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
			TotalUsers:         totalUserCounts[i],
			ActiveUsers:        activeUserCounts[i],
		}
	}

	return &DeveloperListResult{
		Developers:         developersWithStats,
		LastSessionExpiry:  lastSessionExpiry,
		FirstSessionExpiry: firstSessionExpiry,
		TotalSessionCounts: totalSessionCounts,
		OAuthClientCounts:  oauthClientCounts,
		TotalUserCounts:    totalUserCounts,
		ActiveUserCounts:   activeUserCounts,
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

// GetDeveloperUserStatistics returns user access statistics for a developer (admin version)
func (s *Service) GetDeveloperUserStatistics(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time) (_ *console.UserStatistics, err error) {
	defer mon.Task()(&ctx)(&err)

	stats, err := s.store.OAuth2Requests().GetUserStatisticsByDeveloperID(ctx, developerID, startDate, endDate)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return stats, nil
}

// GetDeveloperUserAccessTrends returns user access trends for a developer (admin version)
func (s *Service) GetDeveloperUserAccessTrends(ctx context.Context, developerID uuid.UUID, period string, startDate, endDate *time.Time) (_ []console.UserAccessTrend, err error) {
	defer mon.Task()(&ctx)(&err)

	// Validate period
	validPeriods := map[string]bool{"daily": true, "weekly": true, "monthly": true}
	if !validPeriods[period] {
		period = "daily"
	}

	trends, err := s.store.OAuth2Requests().GetUserAccessTrendsByDeveloperID(ctx, developerID, period, startDate, endDate)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return trends, nil
}

// GetDeveloperUserAccessByApplication returns user access breakdown by application (admin version)
func (s *Service) GetDeveloperUserAccessByApplication(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time) (_ []console.ApplicationUserStats, err error) {
	defer mon.Task()(&ctx)(&err)

	apps, err := s.store.OAuth2Requests().GetUserAccessByApplication(ctx, developerID, startDate, endDate)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return apps, nil
}

// GetDeveloperByEmail returns a developer by email (admin version)
// This includes all developers regardless of status (active, inactive, deleted, etc.)
func (s *Service) GetDeveloperByEmail(ctx context.Context, developerEmail string) (_ *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	// Use GetByEmailWithUnverified to get developers regardless of status
	verified, unverified, err := s.store.Developers().GetByEmailWithUnverified(ctx, developerEmail)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Return verified developer if exists, otherwise return first unverified
	if verified != nil {
		return verified, nil
	}

	if len(unverified) > 0 {
		return &unverified[0], nil
	}

	// No developer found
	return nil, ErrEmailNotFound.New("developer with email %q does not exist", developerEmail)
}
