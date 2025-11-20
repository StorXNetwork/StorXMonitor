// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/satellitedb/dbx"
)

// ensures that developers implements console.Developers.
var _ console.Developers = (*developers)(nil)

// implementation of Developers interface repository using spacemonkeygo/dbx orm.
type developers struct {
	db *satelliteDB
}

// UpdateFailedLoginCountAndExpiration increments failed_login_count and sets login_lockout_expiration appropriately.
func (dev *developers) UpdateFailedLoginCountAndExpiration(ctx context.Context, failedLoginPenalty *float64, id uuid.UUID) (err error) {
	if failedLoginPenalty != nil {
		// failed_login_count exceeded config.FailedLoginPenalty
		_, err = dev.db.ExecContext(ctx, dev.db.Rebind(`
		UPDATE developers
		SET failed_login_count = COALESCE(failed_login_count, 0) + 1,
		login_lockout_expiration = CURRENT_TIMESTAMP + POWER(?, failed_login_count-1) * INTERVAL '1 minute'
		WHERE id = ?
	`), failedLoginPenalty, id.Bytes())
	} else {
		_, err = dev.db.ExecContext(ctx, dev.db.Rebind(`
		UPDATE developers
		SET failed_login_count = COALESCE(failed_login_count, 0) + 1
		WHERE id = ?
	`), id.Bytes())
	}
	return
}

// AddDeveloperUserMapping is a method for inserting developer user mapping into the database.
func (dev *developers) AddDeveloperUserMapping(ctx context.Context, developerID, userID uuid.UUID) (err error) {
	mappingID, err := uuid.New()
	if err != nil {
		return err
	}

	_, err = dev.db.Create_DeveloperUserMapping(ctx, dbx.DeveloperUserMapping_Id(mappingID[:]),
		dbx.DeveloperUserMapping_DeveloperId(developerID[:]),
		dbx.DeveloperUserMapping_UserId(userID[:]))

	return
}

// Get is a method for querying developer from the database by id.
func (dev *developers) Get(ctx context.Context, id uuid.UUID) (_ *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)
	developer, err := dev.db.Get_Developer_By_Id(ctx, dbx.Developer_Id(id[:]))

	if err != nil {
		return nil, err
	}

	return developerFromDBX(ctx, developer)
}

// GetByEmailWithUnverified is a method for querying developers by email from the database.
func (dev *developers) GetByEmailWithUnverified(ctx context.Context, email string) (verified *console.Developer, unverified []console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)
	developersDbx, err := dev.db.All_Developer_By_NormalizedEmail(ctx, dbx.Developer_NormalizedEmail(normalizeEmail(email)))

	if err != nil {
		return nil, nil, err
	}

	var errors errs.Group
	for _, developerDbx := range developersDbx {
		u, err := developerFromDBX(ctx, developerDbx)
		if err != nil {
			errors.Add(err)
			continue
		}

		if u.Status == console.Active {
			verified = u
		} else {
			unverified = append(unverified, *u)
		}
	}

	return verified, unverified, errors.Err()
}

func (dev *developers) GetByStatus(ctx context.Context, status console.UserStatus, cursor console.DeveloperCursor) (page *console.DeveloperPage, err error) {
	defer mon.Task()(&ctx)(&err)

	if cursor.Limit == 0 {
		return nil, Error.New("limit cannot be 0")
	}

	if cursor.Page == 0 {
		return nil, Error.New("page cannot be 0")
	}

	page = &console.DeveloperPage{
		Limit:  cursor.Limit,
		Offset: uint64((cursor.Page - 1) * cursor.Limit),
	}

	count, err := dev.db.Count_Developer_By_Status(ctx, dbx.Developer_Status(int(status)))
	if err != nil {
		return nil, err
	}
	page.TotalCount = uint64(count)

	if page.TotalCount == 0 {
		return page, nil
	}
	if page.Offset > page.TotalCount-1 {
		return nil, Error.New("page is out of range")
	}

	dbxDevelopers, err := dev.db.Limited_Developer_Id_Developer_Email_Developer_FullName_By_Status(ctx,
		dbx.Developer_Status(int(status)),
		int(page.Limit), int64(page.Offset))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return &console.DeveloperPage{
				Developer: []console.Developer{},
			}, nil
		}
		return nil, Error.Wrap(err)
	}

	for _, usr := range dbxDevelopers {
		id, err := uuid.FromBytes(usr.Id)
		if err != nil {
			return &console.DeveloperPage{
				Developer: []console.Developer{},
			}, nil
		}
		page.Developer = append(page.Developer, console.Developer{
			ID:       id,
			Email:    usr.Email,
			FullName: usr.FullName,
		})
	}

	page.PageCount = uint(page.TotalCount / uint64(cursor.Limit))
	if page.TotalCount%uint64(cursor.Limit) != 0 {
		page.PageCount++
	}

	page.CurrentPage = cursor.Page

	return page, nil
}

// GetAllDevelopersWithStats retrieves developers with session, OAuth client, and user count statistics using optimized JOINs.
// This method handles filtering, pagination, and sorting at the database level for better performance.
// Uses CTE with window function to avoid duplicate COUNT query.
// Results can be sorted by any column using sortColumn and sortOrder parameters.
func (dev *developers) GetAllDevelopersWithStats(ctx context.Context, limit, offset int, statusFilter *int, createdAfter, createdBefore *time.Time, search string, hasActiveSession *bool, lastSessionAfter, lastSessionBefore *time.Time, sessionCountMin, sessionCountMax *int, sortColumn, sortOrder string) (developers []*console.Developer, lastSessionExpiry, firstSessionExpiry []*time.Time, totalSessionCounts, oauthClientCounts, totalUserCounts, activeUserCounts []int, totalCount int, err error) {
	defer mon.Task()(&ctx)(&err)

	// Build WHERE conditions - only add conditions when filters are provided
	whereConditions := []string{}
	args := []interface{}{}
	argIndex := 1

	if statusFilter != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("d.status = $%d", argIndex))
		args = append(args, *statusFilter)
		argIndex++
	}

	if createdAfter != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("d.created_at >= $%d", argIndex))
		args = append(args, *createdAfter)
		argIndex++
	}

	if createdBefore != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("d.created_at <= $%d", argIndex))
		args = append(args, *createdBefore)
		argIndex++
	}

	if search != "" {
		searchPattern := "%" + strings.ToLower(search) + "%"
		whereConditions = append(whereConditions, fmt.Sprintf("(LOWER(d.email) LIKE $%d OR LOWER(d.full_name) LIKE $%d)", argIndex, argIndex))
		args = append(args, searchPattern)
		argIndex++
	}

	// Session filters - add to WHERE clause
	if hasActiveSession != nil {
		if *hasActiveSession {
			// Has active session: last_session_expiry > NOW()
			whereConditions = append(whereConditions, "s.last_session_expiry > NOW()")
		} else {
			// No active session: last_session_expiry IS NULL OR last_session_expiry <= NOW()
			whereConditions = append(whereConditions, "(s.last_session_expiry IS NULL OR s.last_session_expiry <= NOW())")
		}
	}

	if lastSessionAfter != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("s.last_session_expiry >= $%d", argIndex))
		args = append(args, *lastSessionAfter)
		argIndex++
	}

	if lastSessionBefore != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("s.last_session_expiry <= $%d", argIndex))
		args = append(args, *lastSessionBefore)
		argIndex++
	}

	if sessionCountMin != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("COALESCE(s.total_session_count, 0) >= $%d", argIndex))
		args = append(args, *sessionCountMin)
		argIndex++
	}

	if sessionCountMax != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("COALESCE(s.total_session_count, 0) <= $%d", argIndex))
		args = append(args, *sessionCountMax)
		argIndex++
	}

	// Build optimized query with CTE and window function for total count
	// This eliminates the need for a separate COUNT query
	query := `
		WITH developer_stats AS (
			SELECT 
				d.id,
				d.full_name,
				d.email,
				d.status,
				d.created_at,
				s.last_session_expiry,
				s.first_session_expiry,
				s.total_session_count,
				COALESCE(oauth.oauth_client_count, 0) AS oauth_client_count,
				COALESCE(user_stats.total_users, 0) AS total_users,
				COALESCE(user_stats.active_users, 0) AS active_users,
				COUNT(*) OVER() AS total_count
			FROM 
				developers d
			LEFT JOIN (
				SELECT 
					developer_id,
					MAX(expires_at) AS last_session_expiry,
					MIN(expires_at) AS first_session_expiry,
					COUNT(*) AS total_session_count
				FROM 
					webapp_session_developers
				GROUP BY 
					developer_id
			) s ON s.developer_id = d.id
			LEFT JOIN (
				SELECT 
					developer_id,
					COUNT(*) AS oauth_client_count
				FROM 
					developer_oauth_clients
				GROUP BY 
					developer_id
			) oauth ON oauth.developer_id = d.id
			LEFT JOIN (
				SELECT 
					developer_oauth_clients.developer_id,
					COUNT(DISTINCT oauth2_requests.user_id) AS total_users,
					COUNT(DISTINCT CASE 
						WHEN oauth2_requests.created_at >= NOW() - INTERVAL '30 days' 
						THEN oauth2_requests.user_id 
					END) AS active_users
				FROM 
					oauth2_requests
				INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
				GROUP BY 
					developer_oauth_clients.developer_id
			) user_stats ON user_stats.developer_id = d.id
		`

	if len(whereConditions) > 0 {
		query += " WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Add ORDER BY with dynamic sorting
	orderByClause := buildDeveloperOrderByClause(sortColumn, sortOrder)
	query += " ORDER BY " + orderByClause

	// Add LIMIT and OFFSET only if limit is specified (limit > 0)
	// When limit <= 0, fetch all records without LIMIT clause
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, limit, offset)
	} else {
		// Only add OFFSET if limit is not specified but offset is needed
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, offset)
		}
	}

	query += `
		)
		SELECT * FROM developer_stats
	`

	rows, err := dev.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, 0, err
	}
	defer func() { err = errs.Combine(err, rows.Close()) }()

	for rows.Next() {
		var developer console.Developer
		var lastExpiry, firstExpiry sql.NullTime
		var totalSessionCount sql.NullInt32
		var oauthClientCount int
		var totalUsers, activeUsers int
		var rowTotalCount int

		err = rows.Scan(
			&developer.ID,
			&developer.FullName,
			&developer.Email,
			&developer.Status,
			&developer.CreatedAt,
			&lastExpiry,
			&firstExpiry,
			&totalSessionCount,
			&oauthClientCount,
			&totalUsers,
			&activeUsers,
			&rowTotalCount, // Window function count
		)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, 0, err
		}

		// Set totalCount from first row (same for all rows due to window function)
		if totalCount == 0 {
			totalCount = rowTotalCount
		}

		var lastExpiryPtr, firstExpiryPtr *time.Time
		if lastExpiry.Valid {
			lastExpiryPtr = &lastExpiry.Time
		}
		if firstExpiry.Valid {
			firstExpiryPtr = &firstExpiry.Time
		}

		var sessionCount int
		if totalSessionCount.Valid {
			sessionCount = int(totalSessionCount.Int32)
		}

		developers = append(developers, &developer)
		lastSessionExpiry = append(lastSessionExpiry, lastExpiryPtr)
		firstSessionExpiry = append(firstSessionExpiry, firstExpiryPtr)
		totalSessionCounts = append(totalSessionCounts, sessionCount)
		oauthClientCounts = append(oauthClientCounts, oauthClientCount)
		totalUserCounts = append(totalUserCounts, totalUsers)
		activeUserCounts = append(activeUserCounts, activeUsers)
	}

	// Check for errors from iterating over rows (required by tagsql)
	if err = rows.Err(); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, 0, err
	}

	return developers, lastSessionExpiry, firstSessionExpiry, totalSessionCounts, oauthClientCounts, totalUserCounts, activeUserCounts, totalCount, nil
}

// GetDeveloperStats returns counts of developers grouped by status using optimized SQL aggregation
func (dev *developers) GetDeveloperStats(ctx context.Context) (total, active, inactive, deleted, pendingDeletion, legalHold, pendingBotVerification int, err error) {
	defer mon.Task()(&ctx)(&err)

	// Use a single optimized SQL query with FILTER to count developers by status
	// This is much more efficient than fetching all developers and counting in memory
	query := `
		SELECT 
			COUNT(*) FILTER (WHERE status = 0) AS inactive,
			COUNT(*) FILTER (WHERE status = 1) AS active,
			COUNT(*) FILTER (WHERE status = 2) AS deleted,
			COUNT(*) FILTER (WHERE status = 3) AS pending_deletion,
			COUNT(*) FILTER (WHERE status = 4) AS legal_hold,
			COUNT(*) FILTER (WHERE status = 5) AS pending_bot_verification,
			COUNT(*) AS total
		FROM developers
	`

	err = dev.db.QueryRowContext(ctx, query).Scan(
		&inactive,
		&active,
		&deleted,
		&pendingDeletion,
		&legalHold,
		&pendingBotVerification,
		&total,
	)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, 0, err
	}

	return total, active, inactive, deleted, pendingDeletion, legalHold, pendingBotVerification, nil
}

// GetByEmail is a method for querying developer by verified email from the database.
func (dev *developers) GetByEmail(ctx context.Context, email string) (_ *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)
	developer, err := dev.db.Get_Developer_By_NormalizedEmail_And_Status_Not_Number(ctx, dbx.Developer_NormalizedEmail(normalizeEmail(email)))

	if err != nil {
		return nil, err
	}

	return developerFromDBX(ctx, developer)
}

// Insert is a method for inserting developer into the database.
func (dev *developers) Insert(ctx context.Context, developer *console.Developer) (_ *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)

	if developer.ID.IsZero() {
		return nil, errs.New("developer id is not set")
	}

	optional := dbx.Developer_Create_Fields{}
	optional.CompanyName = dbx.Developer_CompanyName(developer.CompanyName)

	if developer.ActivationCode != "" {
		optional.ActivationCode = dbx.Developer_ActivationCode(developer.ActivationCode)
	}

	if developer.SignupId != "" {
		optional.SignupId = dbx.Developer_SignupId(developer.SignupId)
	}

	createdDeveloper, err := dev.db.Create_Developer(ctx,
		dbx.Developer_Id(developer.ID[:]),
		dbx.Developer_Email(developer.Email),
		dbx.Developer_NormalizedEmail(normalizeEmail(developer.Email)),
		dbx.Developer_FullName(developer.FullName),
		dbx.Developer_PasswordHash(developer.PasswordHash),
		optional,
	)

	if err != nil {
		return nil, err
	}

	if developer.Status == console.Active {
		err := dev.Update(ctx, developer.ID, console.UpdateDeveloperRequest{Status: &developer.Status})
		if err != nil {
			return nil, err
		}
	}

	return developerFromDBX(ctx, createdDeveloper)
}

// Delete is a method for deleting developer by ID from the database.
func (dev *developers) Delete(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = dev.db.Delete_Developer_By_Id(ctx, dbx.Developer_Id(id[:]))

	return err
}

// Update is a method for updating developer entity.
func (dev *developers) Update(ctx context.Context, developerID uuid.UUID, updateRequest console.UpdateDeveloperRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	updateFields, err := toUpdateDeveloper(updateRequest)
	if err != nil {
		return err
	}

	_, err = dev.db.Update_Developer_By_Id(
		ctx,
		dbx.Developer_Id(developerID[:]),
		*updateFields,
	)

	return err
}

// toUpdateDeveloper creates dbx.Developer_Update_Fields with only non-empty fields as updatable.
func toUpdateDeveloper(request console.UpdateDeveloperRequest) (*dbx.Developer_Update_Fields, error) {
	update := dbx.Developer_Update_Fields{}
	if request.FullName != nil {
		update.FullName = dbx.Developer_FullName(*request.FullName)
	}

	if request.Email != nil {
		update.Email = dbx.Developer_Email(*request.Email)
		update.NormalizedEmail = dbx.Developer_NormalizedEmail(normalizeEmail(*request.Email))
	}
	if request.PasswordHash != nil {
		if len(request.PasswordHash) > 0 {
			update.PasswordHash = dbx.Developer_PasswordHash(request.PasswordHash)
		}
	}
	if request.Status != nil {
		update.Status = dbx.Developer_Status(int(*request.Status))
	}

	if request.FailedLoginCount != nil {
		update.FailedLoginCount = dbx.Developer_FailedLoginCount(*request.FailedLoginCount)
	}
	if request.LoginLockoutExpiration != nil {
		if *request.LoginLockoutExpiration == nil {
			update.LoginLockoutExpiration = dbx.Developer_LoginLockoutExpiration_Null()
		} else {
			update.LoginLockoutExpiration = dbx.Developer_LoginLockoutExpiration(**request.LoginLockoutExpiration)
		}
	}

	if request.ActivationCode != nil {
		update.ActivationCode = dbx.Developer_ActivationCode(*request.ActivationCode)
	}

	if request.SignupId != nil {
		update.SignupId = dbx.Developer_SignupId(*request.SignupId)
	}

	if request.CompanyName != nil {
		update.CompanyName = dbx.Developer_CompanyName(*request.CompanyName)
	}

	return &update, nil
}

// developerFromDBX is used for creating Developer entity from autogenerated dbx.Developer struct.
func developerFromDBX(ctx context.Context, developer *dbx.Developer) (_ *console.Developer, err error) {
	defer mon.Task()(&ctx)(&err)
	if developer == nil {
		return nil, errs.New("developer parameter is nil")
	}

	id, err := uuid.FromBytes(developer.Id)
	if err != nil {
		return nil, err
	}

	result := console.Developer{
		ID:           id,
		FullName:     developer.FullName,
		Email:        developer.Email,
		PasswordHash: developer.PasswordHash,
		Status:       console.UserStatus(developer.Status),
		CreatedAt:    developer.CreatedAt,
	}

	if developer.CompanyName != nil {
		result.CompanyName = *developer.CompanyName
	}

	if developer.FailedLoginCount != nil {
		result.FailedLoginCount = *developer.FailedLoginCount
	}

	if developer.LoginLockoutExpiration != nil {
		result.LoginLockoutExpiration = *developer.LoginLockoutExpiration
	}

	if developer.ActivationCode != nil {
		result.ActivationCode = *developer.ActivationCode
	}

	if developer.SignupId != nil {
		result.SignupId = *developer.SignupId
	}

	return &result, nil
}

// buildDeveloperOrderByClause builds the ORDER BY clause based on sort column and order
// Maps frontend column names to SQL column names from the developer_stats CTE
func buildDeveloperOrderByClause(sortColumn, sortOrder string) string {
	// Default sorting if no column specified
	if sortColumn == "" {
		return "total_users DESC, d.created_at DESC"
	}

	// Normalize sort order
	order := strings.ToUpper(sortOrder)
	if order != "ASC" && order != "DESC" {
		order = "DESC"
	}

	// Map frontend column names to SQL column names from the CTE
	columnMap := map[string]string{
		"id":                 "d.id",
		"fullName":           "d.full_name",
		"email":              "d.email",
		"status":             "d.status",
		"createdAt":          "d.created_at",
		"lastSessionExpiry":  "s.last_session_expiry",
		"firstSessionExpiry": "s.first_session_expiry",
		"totalSessionCount":  "s.total_session_count",
		"oauthClientCount":   "oauth_client_count",
		"totalUsers":         "total_users",
		"activeUsers":        "active_users",
	}

	// Get SQL column name (case-insensitive lookup)
	sqlColumn := ""
	for key, value := range columnMap {
		if strings.EqualFold(sortColumn, key) {
			sqlColumn = value
			break
		}
	}

	// If column not found, use default
	if sqlColumn == "" {
		return "total_users DESC, d.created_at DESC"
	}

	// Handle NULLS for nullable columns
	nullsClause := ""
	if sqlColumn == "s.last_session_expiry" || sqlColumn == "s.first_session_expiry" {
		if order == "DESC" {
			nullsClause = " NULLS LAST"
		} else {
			nullsClause = " NULLS FIRST"
		}
	}

	return sqlColumn + " " + order + nullsClause + ", d.created_at DESC"
}
