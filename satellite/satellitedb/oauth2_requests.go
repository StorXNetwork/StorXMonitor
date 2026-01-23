package satellitedb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"storj.io/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

type oauth2Requests struct {
	db *satelliteDB
}

var _ console.OAuth2Requests = (*oauth2Requests)(nil)

func (repo *oauth2Requests) Insert(ctx context.Context, req *console.OAuth2Request) (*console.OAuth2Request, error) {
	dbxReq, err := repo.db.Create_Oauth2Request(
		ctx,
		dbx.Oauth2Request_Id(req.ID[:]),
		dbx.Oauth2Request_ClientId(req.ClientID),
		dbx.Oauth2Request_UserId(req.UserID[:]),
		dbx.Oauth2Request_RedirectUri(req.RedirectURI),
		dbx.Oauth2Request_Scopes(req.Scopes),
		dbx.Oauth2Request_Status(req.Status),
		dbx.Oauth2Request_ConsentExpiresAt(req.ConsentExpiresAt),
		dbx.Oauth2Request_Code(req.Code),
		dbx.Oauth2Request_CodeExpiresAt(req.CodeExpiresAt),
		dbx.Oauth2Request_ApprovedScopes(req.ApprovedScopes),
		dbx.Oauth2Request_RejectedScopes(req.RejectedScopes),
	)
	if err != nil {
		return nil, err
	}
	return toConsoleOAuth2Request(dbxReq), nil
}

func (repo *oauth2Requests) Get(ctx context.Context, id uuid.UUID) (*console.OAuth2Request, error) {
	dbxReq, err := repo.db.Get_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]))
	if err != nil {
		return nil, err
	}
	return toConsoleOAuth2Request(dbxReq), nil
}

func (repo *oauth2Requests) UpdateStatus(ctx context.Context, id uuid.UUID, status int, code string) error {
	fields := dbx.Oauth2Request_Update_Fields{
		Status: dbx.Oauth2Request_Status(status),
		Code:   dbx.Oauth2Request_Code(code),
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

func (repo *oauth2Requests) UpdateConsent(ctx context.Context, id uuid.UUID, status int, code, approvedScopes, rejectedScopes string, codeExpiresAt time.Time) error {
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx,
		dbx.Oauth2Request_Id(id[:]),
		dbx.Oauth2Request_Update_Fields{
			Status:         dbx.Oauth2Request_Status(status),
			Code:           dbx.Oauth2Request_Code(code),
			ApprovedScopes: dbx.Oauth2Request_ApprovedScopes(approvedScopes),
			RejectedScopes: dbx.Oauth2Request_RejectedScopes(rejectedScopes),
			CodeExpiresAt:  dbx.Oauth2Request_CodeExpiresAt(codeExpiresAt),
		},
	)
	return err
}

func (repo *oauth2Requests) UpdateConsentExpiry(ctx context.Context, id uuid.UUID, consentExpiresAt time.Time) error {
	fields := dbx.Oauth2Request_Update_Fields{
		ConsentExpiresAt: dbx.Oauth2Request_ConsentExpiresAt(consentExpiresAt),
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

func (repo *oauth2Requests) UpdateCodeAndExpiry(ctx context.Context, id uuid.UUID, code string, codeExpiresAt time.Time) error {
	fields := dbx.Oauth2Request_Update_Fields{
		Code:          dbx.Oauth2Request_Code(code),
		CodeExpiresAt: dbx.Oauth2Request_CodeExpiresAt(codeExpiresAt),
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

func (repo *oauth2Requests) GetByCode(ctx context.Context, code string) (*console.OAuth2Request, error) {
	dbxReq, err := repo.db.Get_Oauth2Request_By_Code(ctx, dbx.Oauth2Request_Code(code))
	if err != nil {
		return nil, err
	}
	return toConsoleOAuth2Request(dbxReq), nil
}

func (repo *oauth2Requests) MarkCodeUsed(ctx context.Context, id uuid.UUID) error {
	fields := dbx.Oauth2Request_Update_Fields{
		Status: dbx.Oauth2Request_Status(2), // 2 = used
	}
	_, err := repo.db.Update_Oauth2Request_By_Id(ctx, dbx.Oauth2Request_Id(id[:]), fields)
	return err
}

// ListByDeveloperID lists OAuth2 requests for a developer's clients with filters
// If limit <= 0, all results are returned (no pagination)
func (repo *oauth2Requests) ListByDeveloperID(ctx context.Context, developerID uuid.UUID, limit, offset int, startDate, endDate *time.Time, status *int, clientID, userID, ipAddress string) ([]console.OAuth2Request, error) {
	query := `
		SELECT oauth2_requests.id, oauth2_requests.client_id, oauth2_requests.user_id, 
		       oauth2_requests.redirect_uri, oauth2_requests.scopes, oauth2_requests.status,
		       oauth2_requests.created_at, oauth2_requests.consent_expires_at,
		       oauth2_requests.code, oauth2_requests.code_expires_at,
		       oauth2_requests.approved_scopes, oauth2_requests.rejected_scopes
		FROM oauth2_requests
		INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
		WHERE developer_oauth_clients.developer_id = $1
	`
	args := []interface{}{developerID[:]}
	argIndex := 2

	// Apply all filters in SQL for optimal performance
	if clientID != "" {
		query += fmt.Sprintf(" AND oauth2_requests.client_id = $%d", argIndex)
		args = append(args, clientID)
		argIndex++
	}

	if userID != "" {
		// Convert userID string to UUID bytea for comparison
		userUUID, err := uuid.FromString(userID)
		if err == nil {
			query += fmt.Sprintf(" AND oauth2_requests.user_id = $%d", argIndex)
			args = append(args, userUUID[:])
			argIndex++
		}
	}

	if status != nil {
		query += fmt.Sprintf(" AND oauth2_requests.status = $%d", argIndex)
		args = append(args, *status)
		argIndex++
	}

	if startDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at >= $%d", argIndex)
		args = append(args, *startDate)
		argIndex++
	}

	if endDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at <= $%d", argIndex)
		args = append(args, *endDate)
		argIndex++
	}

	// // Note: IP address filtering not available without ip_address column
	// // This is a placeholder for when the column is added
	// if ipAddress != "" {
	// 	// Will be implemented when ip_address column is added
	// 	// query += fmt.Sprintf(" AND oauth2_requests.ip_address = $%d", argIndex)
	// 	// args = append(args, ipAddress)
	// 	// argIndex++
	// }

	// Order by timestamp descending (newest first) - done in SQL for performance
	query += " ORDER BY oauth2_requests.created_at DESC"

	// Apply pagination only if limit > 0 (allows fetching all results)
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, limit)
		argIndex++
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, offset)
			argIndex++
		}
	}

	rows, err := repo.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []console.OAuth2Request
	for rows.Next() {
		var req console.OAuth2Request
		var idBytes, userIDBytes []byte
		err := rows.Scan(
			&idBytes, &req.ClientID, &userIDBytes, &req.RedirectURI,
			&req.Scopes, &req.Status, &req.CreatedAt, &req.ConsentExpiresAt,
			&req.Code, &req.CodeExpiresAt, &req.ApprovedScopes, &req.RejectedScopes,
		)
		if err != nil {
			return nil, err
		}
		req.ID, _ = uuid.FromBytes(idBytes)
		req.UserID, _ = uuid.FromBytes(userIDBytes)
		results = append(results, req)
	}

	return results, rows.Err()
}

// CountByDeveloperID counts OAuth2 requests for a developer's clients with filters
// All filter logic is applied in SQL for optimal performance
func (repo *oauth2Requests) CountByDeveloperID(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time, status *int, clientID, userID, ipAddress string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM oauth2_requests
		INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
		WHERE developer_oauth_clients.developer_id = $1
	`
	args := []interface{}{developerID[:]}
	argIndex := 2

	// Apply all filters in SQL for optimal performance
	if clientID != "" {
		query += fmt.Sprintf(" AND oauth2_requests.client_id = $%d", argIndex)
		args = append(args, clientID)
		argIndex++
	}

	if userID != "" {
		// Convert userID string to UUID bytea for comparison
		userUUID, err := uuid.FromString(userID)
		if err == nil {
			query += fmt.Sprintf(" AND oauth2_requests.user_id = $%d", argIndex)
			args = append(args, userUUID[:])
			argIndex++
		}
	}

	if status != nil {
		query += fmt.Sprintf(" AND oauth2_requests.status = $%d", argIndex)
		args = append(args, *status)
		argIndex++
	}

	if startDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at >= $%d", argIndex)
		args = append(args, *startDate)
		argIndex++
	}

	if endDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at <= $%d", argIndex)
		args = append(args, *endDate)
		argIndex++
	}

	// // Note: IP address filtering not available without ip_address column
	// // This is a placeholder for when the column is added
	// if ipAddress != "" {
	// 	// Will be implemented when ip_address column is added
	// 	// query += fmt.Sprintf(" AND oauth2_requests.ip_address = $%d", argIndex)
	// 	// args = append(args, ipAddress)
	// 	// argIndex++
	// }

	var count int
	err := repo.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// GetStatisticsByDeveloperID gets statistics for a developer's OAuth2 requests (no filters, all time)
func (repo *oauth2Requests) GetStatisticsByDeveloperID(ctx context.Context, developerID uuid.UUID, clientID string) (total, approved, pending, rejected int, err error) {
	// Note: Status values: 0=pending (console.OAuth2RequestStatusPending), 1=approved (console.OAuth2RequestStatusApproved), 2=rejected (console.OAuth2RequestStatusRejected)
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE oauth2_requests.status = 1) as approved,
			COUNT(*) FILTER (WHERE oauth2_requests.status = 0) as pending,
			COUNT(*) FILTER (WHERE oauth2_requests.status = 2) as rejected
		FROM oauth2_requests
		INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
		WHERE developer_oauth_clients.developer_id = $1
	`
	args := []interface{}{developerID[:]}
	argIndex := 2

	if clientID != "" {
		query += fmt.Sprintf(" AND oauth2_requests.client_id = $%d", argIndex)
		args = append(args, clientID)
		argIndex++
	}

	err = repo.db.QueryRowContext(ctx, query, args...).Scan(&total, &approved, &pending, &rejected)
	return total, approved, pending, rejected, err
}

// GetUserStatisticsByDeveloperID returns user access statistics for a developer
func (repo *oauth2Requests) GetUserStatisticsByDeveloperID(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time) (*console.UserStatistics, error) {
	query := `
		SELECT 
			COUNT(DISTINCT oauth2_requests.user_id) as total_users,
			COUNT(DISTINCT CASE 
				WHEN oauth2_requests.created_at >= NOW() - INTERVAL '30 days' 
				THEN oauth2_requests.user_id 
			END) as active_users,
			COUNT(*) as total_requests,
			COUNT(*) FILTER (WHERE oauth2_requests.status = 1) as approved_requests,
			COUNT(*) FILTER (WHERE oauth2_requests.status = 0) as pending_requests,
			COUNT(*) FILTER (WHERE oauth2_requests.status = 2) as rejected_requests
		FROM oauth2_requests
		INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
		WHERE developer_oauth_clients.developer_id = $1
	`
	args := []interface{}{developerID[:]}
	argIndex := 2

	if startDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at >= $%d", argIndex)
		args = append(args, *startDate)
		argIndex++
	}

	if endDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at <= $%d", argIndex)
		args = append(args, *endDate)
		argIndex++
	}

	var stats console.UserStatistics
	err := repo.db.QueryRowContext(ctx, query, args...).Scan(
		&stats.TotalUsers,
		&stats.ActiveUsers,
		&stats.TotalRequests,
		&stats.ApprovedRequests,
		&stats.PendingRequests,
		&stats.RejectedRequests,
	)
	if err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetUserAccessTrendsByDeveloperID returns user access trends over time for a developer
func (repo *oauth2Requests) GetUserAccessTrendsByDeveloperID(ctx context.Context, developerID uuid.UUID, period string, startDate, endDate *time.Time) ([]console.UserAccessTrend, error) {
	// Determine date truncation based on period
	var dateTrunc string
	switch period {
	case "daily":
		dateTrunc = "DATE(oauth2_requests.created_at)"
	case "weekly":
		dateTrunc = "DATE_TRUNC('week', oauth2_requests.created_at)"
	case "monthly":
		dateTrunc = "DATE_TRUNC('month', oauth2_requests.created_at)"
	default:
		dateTrunc = "DATE(oauth2_requests.created_at)"
	}

	query := fmt.Sprintf(`
		SELECT 
			%s as date,
			COUNT(DISTINCT oauth2_requests.user_id) as user_count,
			COUNT(*) as request_count
		FROM oauth2_requests
		INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
		WHERE developer_oauth_clients.developer_id = $1
	`, dateTrunc)

	args := []interface{}{developerID[:]}
	argIndex := 2

	if startDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at >= $%d", argIndex)
		args = append(args, *startDate)
		argIndex++
	}

	if endDate != nil {
		query += fmt.Sprintf(" AND oauth2_requests.created_at <= $%d", argIndex)
		args = append(args, *endDate)
		argIndex++
	}

	query += fmt.Sprintf(" GROUP BY %s ORDER BY date ASC", dateTrunc)

	rows, err := repo.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []console.UserAccessTrend
	for rows.Next() {
		var trend console.UserAccessTrend
		err := rows.Scan(&trend.Date, &trend.UserCount, &trend.RequestCount)
		if err != nil {
			return nil, err
		}
		trends = append(trends, trend)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return trends, nil
}

// GetUserAccessByApplication returns user access breakdown by OAuth client for a developer
// This includes ALL applications for the developer, even if they have zero requests
func (repo *oauth2Requests) GetUserAccessByApplication(ctx context.Context, developerID uuid.UUID, startDate, endDate *time.Time) ([]console.ApplicationUserStats, error) {
	query := `
		SELECT 
			developer_oauth_clients.client_id,
			developer_oauth_clients.name as client_name,
			COUNT(DISTINCT oauth2_requests.user_id) as total_users,
			COUNT(DISTINCT CASE 
				WHEN oauth2_requests.created_at >= NOW() - INTERVAL '30 days' 
				THEN oauth2_requests.user_id 
			END) as active_users,
			COUNT(oauth2_requests.id) as total_requests
		FROM developer_oauth_clients
		LEFT JOIN oauth2_requests ON developer_oauth_clients.client_id = oauth2_requests.client_id
		WHERE developer_oauth_clients.developer_id = $1
	`
	args := []interface{}{developerID[:]}
	argIndex := 2

	if startDate != nil {
		query += fmt.Sprintf(" AND (oauth2_requests.created_at IS NULL OR oauth2_requests.created_at >= $%d)", argIndex)
		args = append(args, *startDate)
		argIndex++
	}

	if endDate != nil {
		query += fmt.Sprintf(" AND (oauth2_requests.created_at IS NULL OR oauth2_requests.created_at <= $%d)", argIndex)
		args = append(args, *endDate)
		argIndex++
	}

	query += " GROUP BY developer_oauth_clients.client_id, developer_oauth_clients.name ORDER BY total_users DESC, developer_oauth_clients.name ASC"

	rows, err := repo.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []console.ApplicationUserStats
	for rows.Next() {
		var app console.ApplicationUserStats
		err := rows.Scan(
			&app.ClientID,
			&app.ClientName,
			&app.TotalUsers,
			&app.ActiveUsers,
			&app.TotalRequests,
		)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return apps, nil
}

// GetUserDeveloperAccess returns all developers with access to a user's account
func (repo *oauth2Requests) GetUserDeveloperAccess(ctx context.Context, userID uuid.UUID) ([]console.UserDeveloperAccess, error) {
	query := `
		SELECT 
			d.id as developer_id,
			d.full_name as developer_name,
			d.email as developer_email,
			doc.client_id,
			doc.name as application_name,
			COALESCE(doc.description, '') as application_description,
			MIN(o.created_at) as access_granted_date,
			MAX(o.created_at) as last_access_date,
			MAX(o.consent_expires_at) as consent_expires_at,
			COUNT(*) as total_requests,
			-- Get most recent approved scopes (get the latest non-empty approved_scopes)
			(SELECT approved_scopes FROM oauth2_requests o2 
			 WHERE o2.user_id = $1
			   AND o2.client_id = doc.client_id 
			   AND o2.status = 1 
			   AND o2.approved_scopes != '' 
			 ORDER BY o2.created_at DESC LIMIT 1) as latest_approved_scopes,
			-- Get most recent rejected scopes
			(SELECT rejected_scopes FROM oauth2_requests o3 
			 WHERE o3.user_id = $1
			   AND o3.client_id = doc.client_id 
			   AND o3.status = 1 
			   AND o3.rejected_scopes != '' 
			 ORDER BY o3.created_at DESC LIMIT 1) as latest_rejected_scopes
		FROM oauth2_requests o
		INNER JOIN developer_oauth_clients doc ON o.client_id = doc.client_id
		INNER JOIN developers d ON doc.developer_id = d.id
		WHERE o.user_id = $1
			AND o.status = 1  -- Only approved requests
		GROUP BY d.id, d.full_name, d.email, doc.client_id, doc.name, doc.description
		ORDER BY last_access_date DESC
	`

	rows, err := repo.db.QueryContext(ctx, query, userID[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accessList := make([]console.UserDeveloperAccess, 0)
	for rows.Next() {
		var access console.UserDeveloperAccess
		var latestApprovedScopes, latestRejectedScopes sql.NullString
		var lastAccessDate, consentExpiresAt sql.NullTime

		err := rows.Scan(
			&access.DeveloperID,
			&access.DeveloperName,
			&access.DeveloperEmail,
			&access.ClientID,
			&access.ApplicationName,
			&access.ApplicationDescription,
			&access.AccessGrantedDate,
			&lastAccessDate,
			&consentExpiresAt,
			&access.TotalRequests,
			&latestApprovedScopes,
			&latestRejectedScopes,
		)
		if err != nil {
			return nil, err
		}

		// Parse scopes from comma-separated strings
		if latestApprovedScopes.Valid && latestApprovedScopes.String != "" {
			access.ApprovedScopes = parseScopes(latestApprovedScopes.String)
		} else {
			access.ApprovedScopes = []string{}
		}

		if latestRejectedScopes.Valid && latestRejectedScopes.String != "" {
			access.RejectedScopes = parseScopes(latestRejectedScopes.String)
		} else {
			access.RejectedScopes = []string{}
		}

		// Set nullable time fields
		if lastAccessDate.Valid {
			access.LastAccessDate = &lastAccessDate.Time
		}

		if consentExpiresAt.Valid {
			access.ConsentExpiresAt = &consentExpiresAt.Time
			// Check if consent is still active (not expired)
			access.IsActive = consentExpiresAt.Time.After(time.Now())
		} else {
			access.IsActive = false
		}

		accessList = append(accessList, access)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return accessList, nil
}

// GetUserDeveloperAccessHistory returns access history for a specific developer
func (repo *oauth2Requests) GetUserDeveloperAccessHistory(ctx context.Context, userID uuid.UUID, clientID string) ([]console.UserAccessHistory, error) {
	query := `
		SELECT 
			o.id as request_id,
			o.client_id,
			COALESCE(doc.name, '') as application_name,
			o.scopes,
			o.status,
			o.created_at
		FROM oauth2_requests o
		LEFT JOIN developer_oauth_clients doc ON o.client_id = doc.client_id
		WHERE o.user_id = $1
			AND o.client_id = $2
		ORDER BY o.created_at DESC
	`

	rows, err := repo.db.QueryContext(ctx, query, userID[:], clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	history := make([]console.UserAccessHistory, 0)
	for rows.Next() {
		var h console.UserAccessHistory
		var scopesStr string

		err := rows.Scan(
			&h.RequestID,
			&h.ClientID,
			&h.ApplicationName,
			&scopesStr,
			&h.Status,
			&h.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Parse scopes
		h.Scopes = parseScopes(scopesStr)

		history = append(history, h)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return history, nil
}

// RevokeUserDeveloperAccess revokes a developer's access by expiring consent
func (repo *oauth2Requests) RevokeUserDeveloperAccess(ctx context.Context, userID uuid.UUID, clientID string) error {
	query := `
		UPDATE oauth2_requests
		SET consent_expires_at = NOW()
		WHERE user_id = $1
			AND client_id = $2
			AND status = 1  -- Only approved requests
			AND (consent_expires_at IS NULL OR consent_expires_at > NOW())  -- Only non-expired consents
	`

	result, err := repo.db.ExecContext(ctx, query, userID[:], clientID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no active access found to revoke")
	}

	return nil
}

// parseScopes parses comma-separated scope string into slice
func parseScopes(scopesStr string) []string {
	if scopesStr == "" {
		return []string{}
	}
	scopes := []string{}
	for _, scope := range strings.Split(scopesStr, ",") {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// Conversion helper
func toConsoleOAuth2Request(d *dbx.Oauth2Request) *console.OAuth2Request {
	id, _ := uuid.FromBytes(d.Id)
	userID, _ := uuid.FromBytes(d.UserId)
	return &console.OAuth2Request{
		ID:               id,
		ClientID:         d.ClientId,
		UserID:           userID,
		RedirectURI:      d.RedirectUri,
		Scopes:           d.Scopes,
		Status:           d.Status,
		CreatedAt:        d.CreatedAt,
		ConsentExpiresAt: d.ConsentExpiresAt,
		Code:             d.Code,
		CodeExpiresAt:    d.CodeExpiresAt,
		ApprovedScopes:   d.ApprovedScopes,
		RejectedScopes:   d.RejectedScopes,
	}
}
