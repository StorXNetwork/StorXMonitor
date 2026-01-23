// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
	"github.com/StorXNetwork/StorXMonitor/satellite/admin"
	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
)

// ensures that adminUsers implements admin.Users.
var _ admin.Users = (*adminUsers)(nil)

// adminUsers provides access to admins table.
type adminUsers struct {
	db *satelliteDB
}

// Get is a method for querying admin from the database by id.
func (users *adminUsers) Get(ctx context.Context, id uuid.UUID) (_ *admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	adminDBX, err := users.db.Get_Admin_By_Id(ctx, dbx.Admin_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, admin.ErrNotFound
		}
		return nil, err
	}

	return adminFromDBX(adminDBX)
}

// GetByEmail is a method for querying admin by email from the database (active only).
func (users *adminUsers) GetByEmail(ctx context.Context, email string) (_ *admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	adminDBX, err := users.db.Get_Admin_By_Email_And_Status_Not_Number(ctx, dbx.Admin_Email(email))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, admin.ErrNotFound
		}
		return nil, err
	}

	return adminFromDBX(adminDBX)
}

// GetByEmailAnyStatus returns admin by email regardless of status (used for activation).
func (users *adminUsers) GetByEmailAnyStatus(ctx context.Context, email string) (_ *admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	// Use All_Admin_By_Email which returns all admins with this email
	adminsDBX, err := users.db.All_Admin_By_Email(ctx, dbx.Admin_Email(email))
	if err != nil {
		return nil, err
	}

	if len(adminsDBX) == 0 {
		return nil, admin.ErrNotFound
	}

	// Return the first one (should only be one per email)
	adminDBX := adminsDBX[0]
	return adminFromDBX(adminDBX)
}

// Insert is a method for inserting admin into the database.
func (users *adminUsers) Insert(ctx context.Context, user *admin.AdminUser) (_ *admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	if user.ID.IsZero() {
		return nil, Error.New("admin user id is not set")
	}

	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	optional := dbx.Admin_Create_Fields{}
	if user.Roles != nil {
		optional.Roles = dbx.Admin_Roles(*user.Roles)
	}
	if user.DeletedAt != nil {
		optional.DeletedAt = dbx.Admin_DeletedAt(*user.DeletedAt)
	}

	createdAdmin, err := users.db.Create_Admin(ctx,
		dbx.Admin_Id(user.ID[:]),
		dbx.Admin_Email(user.Email),
		dbx.Admin_PasswordHash(user.PasswordHash),
		dbx.Admin_UpdatedAt(user.UpdatedAt),
		optional,
	)

	if err != nil {
		return nil, err
	}

	return adminFromDBX(createdAdmin)
}

// Update is a method for updating admin entity.
func (users *adminUsers) Update(ctx context.Context, userID uuid.UUID, updateRequest admin.UpdateAdminUserRequest) (_ *admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	updateFields := dbx.Admin_Update_Fields{}

	if updateRequest.Email != nil {
		updateFields.Email = dbx.Admin_Email(*updateRequest.Email)
	}
	if len(updateRequest.PasswordHash) > 0 {
		updateFields.PasswordHash = dbx.Admin_PasswordHash(updateRequest.PasswordHash)
	}
	if updateRequest.Status != nil {
		updateFields.Status = dbx.Admin_Status(int(*updateRequest.Status))
	}
	if updateRequest.Roles != nil {
		if *updateRequest.Roles == nil {
			updateFields.Roles = dbx.Admin_Roles_Null()
		} else {
			updateFields.Roles = dbx.Admin_Roles(**updateRequest.Roles)
		}
	}

	// Always update updated_at
	updateFields.UpdatedAt = dbx.Admin_UpdatedAt(time.Now())

	updatedAdmin, err := users.db.Update_Admin_By_Id(
		ctx,
		dbx.Admin_Id(userID[:]),
		updateFields,
	)

	if err != nil {
		return nil, err
	}

	if updatedAdmin == nil {
		return nil, admin.ErrNotFound
	}

	return adminFromDBX(updatedAdmin)
}

// Delete is a method for deleting admin by ID from the database (soft delete).
func (users *adminUsers) Delete(ctx context.Context, id uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Soft delete by setting deleted_at timestamp
	now := time.Now()
	updateFields := dbx.Admin_Update_Fields{
		DeletedAt: dbx.Admin_DeletedAt(now),
		UpdatedAt: dbx.Admin_UpdatedAt(now),
		Status:    dbx.Admin_Status(int(admin.AdminDeleted)),
	}

	_, err = users.db.Update_Admin_By_Id(ctx, dbx.Admin_Id(id[:]), updateFields)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return admin.ErrNotFound
		}
		return err
	}

	return nil
}

// List returns all active admin users.
func (users *adminUsers) List(ctx context.Context) (_ []admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	allAdmins, err := users.db.All_Admin(ctx)
	if err != nil {
		return nil, err
	}

	var result []admin.AdminUser
	for _, adminDBX := range allAdmins {
		// Filter only active admins (status = 1 and deleted_at is NULL)
		if adminDBX.Status == int(admin.AdminActive) && adminDBX.DeletedAt == nil {
			adminUser, err := adminFromDBX(adminDBX)
			if err != nil {
				return nil, err
			}
			result = append(result, *adminUser)
		}
	}

	return result, nil
}

// ListAll returns all admin users regardless of status (for seeding checks).
func (users *adminUsers) ListAll(ctx context.Context) (_ []admin.AdminUser, err error) {
	defer mon.Task()(&ctx)(&err)

	allAdmins, err := users.db.All_Admin(ctx)
	if err != nil {
		return nil, err
	}

	var result []admin.AdminUser
	for _, adminDBX := range allAdmins {
		adminUser, err := adminFromDBX(adminDBX)
		if err != nil {
			return nil, err
		}
		result = append(result, *adminUser)
	}

	return result, nil
}

// adminFromDBX is used for creating AdminUser entity from autogenerated dbx.Admin struct.
func adminFromDBX(adminDBX *dbx.Admin) (_ *admin.AdminUser, err error) {
	if adminDBX == nil {
		return nil, Error.New("admin parameter is nil")
	}

	id, err := uuid.FromBytes(adminDBX.Id)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	result := admin.AdminUser{
		ID:           id,
		Email:        adminDBX.Email,
		PasswordHash: adminDBX.PasswordHash,
		Status:       admin.AdminUserStatus(adminDBX.Status),
		Roles:        adminDBX.Roles,
		CreatedAt:    adminDBX.CreatedAt,
		UpdatedAt:    adminDBX.UpdatedAt,
		DeletedAt:    adminDBX.DeletedAt,
	}

	return &result, nil
}
