// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"

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
