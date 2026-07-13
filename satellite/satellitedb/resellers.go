// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/satellite/satellitedb/dbx"
	"github.com/StorXNetwork/StorXMonitor/satellite/seller"
	"github.com/StorXNetwork/common/uuid"
)

var _ seller.DB = (*sellerDB)(nil)

type sellerDB struct {
	db *satelliteDB
}

func (db *sellerDB) Resellers() seller.Resellers {
	return &resellers{db: db.db}
}

func (db *sellerDB) ResellerConfigs() seller.ResellerConfigs {
	return &resellerConfigs{db: db.db}
}

func (db *sellerDB) ResellerDomains() seller.ResellerDomains {
	return &resellerDomains{db: db.db}
}

func (db *sellerDB) WebappSessionResellers() seller.WebappSessionResellers {
	return &webappSessionResellers{db: db.db}
}

func (db *sellerDB) ResetPasswordTokens() seller.ResellerResetPasswordTokens {
	return &resellerResetPasswordTokens{db: db.db}
}

func (db *sellerDB) ResellerDeleteRequests() seller.ResellerDeleteRequests {
	return &resellerDeleteRequests{db: db.db}
}

var _ seller.Resellers = (*resellers)(nil)

type resellers struct {
	db *satelliteDB
}

func (repo *resellers) Get(ctx context.Context, id uuid.UUID) (_ *seller.Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	resellerDBX, err := repo.db.Get_Reseller_By_Id(ctx, dbx.Reseller_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerFromDBX(resellerDBX)
}

func (repo *resellers) GetByEmail(ctx context.Context, email string) (_ *seller.Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	resellerDBX, err := repo.db.Get_Reseller_By_Email_And_Status_Not_Number(ctx, dbx.Reseller_Email(email))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerFromDBX(resellerDBX)
}

func (repo *resellers) GetByEmailAnyStatus(ctx context.Context, email string) (_ *seller.Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	resellerDBX, err := repo.db.Get_Reseller_By_Email(ctx, dbx.Reseller_Email(email))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerFromDBX(resellerDBX)
}

func (repo *resellers) GetByEmailWithUnverified(ctx context.Context, email string) (verified *seller.Reseller, unverified []seller.Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	verified, err = repo.GetByEmail(ctx, email)
	if err != nil && !seller.ErrNotFound.Has(err) {
		return nil, nil, err
	}
	if verified != nil {
		return verified, nil, nil
	}

	anyStatus, err := repo.GetByEmailAnyStatus(ctx, email)
	if err != nil {
		if seller.ErrNotFound.Has(err) {
			return nil, nil, seller.ErrNotFound.New("")
		}
		return nil, nil, err
	}

	if anyStatus.Status != seller.ResellerActive {
		unverified = append(unverified, *anyStatus)
	}

	if verified == nil && len(unverified) == 0 {
		return nil, nil, seller.ErrNotFound.New("")
	}

	return verified, unverified, nil
}

func (repo *resellers) Insert(ctx context.Context, resellerEntity *seller.Reseller) (_ *seller.Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	if resellerEntity.ID.IsZero() {
		return nil, Error.New("reseller id is not set")
	}

	now := time.Now()
	if resellerEntity.CreatedAt.IsZero() {
		resellerEntity.CreatedAt = now
	}
	if resellerEntity.UpdatedAt.IsZero() {
		resellerEntity.UpdatedAt = now
	}

	optional := dbx.Reseller_Create_Fields{}
	if resellerEntity.CompanyName != nil {
		optional.CompanyName = dbx.Reseller_CompanyName(*resellerEntity.CompanyName)
	}
	if resellerEntity.DeletedAt != nil {
		optional.DeletedAt = dbx.Reseller_DeletedAt(*resellerEntity.DeletedAt)
	}

	created, err := repo.db.Create_Reseller(ctx,
		dbx.Reseller_Id(resellerEntity.ID[:]),
		dbx.Reseller_Name(resellerEntity.Name),
		dbx.Reseller_Email(resellerEntity.Email),
		dbx.Reseller_PasswordHash(resellerEntity.PasswordHash),
		dbx.Reseller_UpdatedAt(resellerEntity.UpdatedAt),
		optional,
	)
	if err != nil {
		return nil, err
	}

	return resellerFromDBX(created)
}

func (repo *resellers) Update(ctx context.Context, id uuid.UUID, update seller.UpdateResellerRequest) (_ *seller.Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	updateFields := dbx.Reseller_Update_Fields{
		UpdatedAt: dbx.Reseller_UpdatedAt(update.UpdatedAt),
	}

	if update.Name != nil {
		updateFields.Name = dbx.Reseller_Name(*update.Name)
	}
	if update.Email != nil {
		updateFields.Email = dbx.Reseller_Email(*update.Email)
	}
	if len(update.PasswordHash) > 0 {
		updateFields.PasswordHash = dbx.Reseller_PasswordHash(update.PasswordHash)
	}
	if update.CompanyName != nil {
		updateFields.CompanyName = dbx.Reseller_CompanyName_Raw(update.CompanyName)
	}
	if update.Status != nil {
		updateFields.Status = dbx.Reseller_Status(int(*update.Status))
	}
	if update.DeletedAt != nil {
		updateFields.DeletedAt = dbx.Reseller_DeletedAt_Raw(update.DeletedAt)
	}
	if update.FailedLoginCount != nil {
		updateFields.FailedLoginCount = dbx.Reseller_FailedLoginCount(*update.FailedLoginCount)
	}
	if update.LoginLockoutExpiration != nil {
		updateFields.LoginLockoutExpiration = dbx.Reseller_LoginLockoutExpiration_Raw(*update.LoginLockoutExpiration)
	}
	if update.ActivationCode != nil {
		updateFields.ActivationCode = dbx.Reseller_ActivationCode_Raw(update.ActivationCode)
	}
	if update.SignupID != nil {
		updateFields.SignupId = dbx.Reseller_SignupId_Raw(update.SignupID)
	}
	if update.NewUnverifiedEmail != nil {
		if *update.NewUnverifiedEmail == nil {
			updateFields.NewUnverifiedEmail = dbx.Reseller_NewUnverifiedEmail_Null()
		} else {
			updateFields.NewUnverifiedEmail = dbx.Reseller_NewUnverifiedEmail(**update.NewUnverifiedEmail)
		}
	}
	if update.EmailChangeVerificationStep != nil {
		updateFields.EmailChangeVerificationStep = dbx.Reseller_EmailChangeVerificationStep(*update.EmailChangeVerificationStep)
	}
	if update.MFAEnabled != nil {
		updateFields.MfaEnabled = dbx.Reseller_MfaEnabled(*update.MFAEnabled)
	}
	if update.MFASecretKey != nil {
		if *update.MFASecretKey == nil {
			updateFields.MfaSecretKey = dbx.Reseller_MfaSecretKey_Null()
		} else {
			updateFields.MfaSecretKey = dbx.Reseller_MfaSecretKey(**update.MFASecretKey)
		}
	}
	if update.MFARecoveryCodes != nil {
		if *update.MFARecoveryCodes == nil {
			updateFields.MfaRecoveryCodes = dbx.Reseller_MfaRecoveryCodes_Null()
		} else {
			recoveryBytes, marshalErr := json.Marshal(*update.MFARecoveryCodes)
			if marshalErr != nil {
				return nil, marshalErr
			}
			updateFields.MfaRecoveryCodes = dbx.Reseller_MfaRecoveryCodes(string(recoveryBytes))
		}
	}

	updated, err := repo.db.Update_Reseller_By_Id(ctx, dbx.Reseller_Id(id[:]), updateFields)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerFromDBX(updated)
}

var _ seller.ResellerConfigs = (*resellerConfigs)(nil)

type resellerConfigs struct {
	db *satelliteDB
}

func (repo *resellerConfigs) Get(ctx context.Context, id uuid.UUID) (_ *seller.ResellerConfig, err error) {
	defer mon.Task()(&ctx)(&err)

	configDBX, err := repo.db.Get_ResellerConfig_By_Id(ctx, dbx.ResellerConfig_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerConfigFromDBX(configDBX)
}

func (repo *resellerConfigs) GetByResellerID(ctx context.Context, resellerID uuid.UUID) (_ *seller.ResellerConfig, err error) {
	defer mon.Task()(&ctx)(&err)

	configDBX, err := repo.db.Get_ResellerConfig_By_ResellerId(ctx, dbx.ResellerConfig_ResellerId(resellerID[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerConfigFromDBX(configDBX)
}

func (repo *resellerConfigs) Insert(ctx context.Context, config *seller.ResellerConfig) (_ *seller.ResellerConfig, err error) {
	defer mon.Task()(&ctx)(&err)

	if config.ID.IsZero() {
		return nil, Error.New("reseller config id is not set")
	}
	if config.ResellerID.IsZero() {
		return nil, Error.New("reseller id is not set")
	}

	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	if config.UpdatedAt.IsZero() {
		config.UpdatedAt = now
	}

	created, err := repo.db.Create_ResellerConfig(ctx,
		dbx.ResellerConfig_Id(config.ID[:]),
		dbx.ResellerConfig_ResellerId(config.ResellerID[:]),
		dbx.ResellerConfig_Config(config.Config),
		dbx.ResellerConfig_UpdatedAt(config.UpdatedAt),
		dbx.ResellerConfig_Create_Fields{
			ActiveThemeType: dbx.ResellerConfig_ActiveThemeType(config.ActiveThemeType),
			ActiveThemeId:   activeThemeIDField(config.ActiveThemeID),
		},
	)
	if err != nil {
		return nil, err
	}

	return resellerConfigFromDBX(created)
}

func (repo *resellerConfigs) Update(ctx context.Context, resellerID uuid.UUID, update seller.UpdateResellerConfigRequest) (_ *seller.ResellerConfig, err error) {
	defer mon.Task()(&ctx)(&err)

	updateFields := dbx.ResellerConfig_Update_Fields{
		UpdatedAt: dbx.ResellerConfig_UpdatedAt(update.UpdatedAt),
	}
	if update.Config != nil {
		updateFields.Config = dbx.ResellerConfig_Config(update.Config)
	}
	if update.ActiveThemeType != nil {
		updateFields.ActiveThemeType = dbx.ResellerConfig_ActiveThemeType(*update.ActiveThemeType)
	}
	if update.ActiveThemeID != nil {
		if *update.ActiveThemeID == nil {
			updateFields.ActiveThemeId = dbx.ResellerConfig_ActiveThemeId_Null()
		} else {
			updateFields.ActiveThemeId = dbx.ResellerConfig_ActiveThemeId((*update.ActiveThemeID)[:])
		}
	}

	updated, err := repo.db.Update_ResellerConfig_By_ResellerId(ctx,
		dbx.ResellerConfig_ResellerId(resellerID[:]),
		updateFields,
	)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerConfigFromDBX(updated)
}

func (repo *resellerConfigs) DeleteByResellerID(ctx context.Context, resellerID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	config, err := repo.GetByResellerID(ctx, resellerID)
	if err != nil {
		return err
	}

	_, err = repo.db.Delete_ResellerConfig_By_Id(ctx, dbx.ResellerConfig_Id(config.ID[:]))
	if errs.Is(err, sql.ErrNoRows) {
		return seller.ErrNotFound.New("")
	}
	return err
}

var _ seller.ResellerDomains = (*resellerDomains)(nil)

type resellerDomains struct {
	db *satelliteDB
}

func (repo *resellerDomains) Get(ctx context.Context, id uuid.UUID) (_ *seller.ResellerDomain, err error) {
	defer mon.Task()(&ctx)(&err)

	domainDBX, err := repo.db.Get_ResellerDomain_By_Id(ctx, dbx.ResellerDomain_Id(id[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerDomainFromDBX(domainDBX)
}

func (repo *resellerDomains) GetByResellerID(ctx context.Context, resellerID uuid.UUID) (_ *seller.ResellerDomain, err error) {
	defer mon.Task()(&ctx)(&err)

	domainDBX, err := repo.db.Get_ResellerDomain_By_ResellerId(ctx, dbx.ResellerDomain_ResellerId(resellerID[:]))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerDomainFromDBX(domainDBX)
}

func (repo *resellerDomains) GetByDomain(ctx context.Context, domain string) (_ *seller.ResellerDomain, err error) {
	defer mon.Task()(&ctx)(&err)

	domainDBX, err := repo.db.Get_ResellerDomain_By_Domain(ctx, dbx.ResellerDomain_Domain(domain))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerDomainFromDBX(domainDBX)
}

func (repo *resellerDomains) Insert(ctx context.Context, domain *seller.ResellerDomain) (_ *seller.ResellerDomain, err error) {
	defer mon.Task()(&ctx)(&err)

	if domain.ID.IsZero() {
		return nil, Error.New("reseller domain id is not set")
	}
	if domain.ResellerID.IsZero() {
		return nil, Error.New("reseller id is not set")
	}

	now := time.Now()
	if domain.CreatedAt.IsZero() {
		domain.CreatedAt = now
	}
	if domain.UpdatedAt.IsZero() {
		domain.UpdatedAt = now
	}
	if domain.Status == "" {
		domain.Status = seller.DomainStatusPending
	}
	if domain.VerificationStatus == "" {
		domain.VerificationStatus = seller.VerificationStatusPending
	}
	if domain.SSLStatus == "" {
		domain.SSLStatus = seller.SSLStatusPending
	}

	optional := dbx.ResellerDomain_Create_Fields{}
	if domain.VerificationMethod != nil {
		optional.VerificationMethod = dbx.ResellerDomain_VerificationMethod(*domain.VerificationMethod)
	}
	if domain.DNSTarget != nil {
		optional.DnsTarget = dbx.ResellerDomain_DnsTarget(*domain.DNSTarget)
	}
	if domain.VerifiedAt != nil {
		optional.VerifiedAt = dbx.ResellerDomain_VerifiedAt(*domain.VerifiedAt)
	}
	if domain.DeletedAt != nil {
		optional.DeletedAt = dbx.ResellerDomain_DeletedAt(*domain.DeletedAt)
	}

	created, err := repo.db.Create_ResellerDomain(ctx,
		dbx.ResellerDomain_Id(domain.ID[:]),
		dbx.ResellerDomain_ResellerId(domain.ResellerID[:]),
		dbx.ResellerDomain_Domain(domain.Domain),
		dbx.ResellerDomain_DomainType(domain.DomainType),
		dbx.ResellerDomain_Status(domain.Status),
		dbx.ResellerDomain_VerificationStatus(domain.VerificationStatus),
		dbx.ResellerDomain_SslStatus(domain.SSLStatus),
		dbx.ResellerDomain_UpdatedAt(domain.UpdatedAt),
		optional,
	)
	if err != nil {
		return nil, err
	}

	return resellerDomainFromDBX(created)
}

func (repo *resellerDomains) Update(ctx context.Context, resellerID uuid.UUID, update seller.UpdateResellerDomainRequest) (_ *seller.ResellerDomain, err error) {
	defer mon.Task()(&ctx)(&err)

	updateFields := dbx.ResellerDomain_Update_Fields{
		UpdatedAt: dbx.ResellerDomain_UpdatedAt(update.UpdatedAt),
	}

	if update.Domain != nil {
		updateFields.Domain = dbx.ResellerDomain_Domain(*update.Domain)
	}
	if update.DomainType != nil {
		updateFields.DomainType = dbx.ResellerDomain_DomainType(*update.DomainType)
	}
	if update.Status != nil {
		updateFields.Status = dbx.ResellerDomain_Status(*update.Status)
	}
	if update.VerificationMethod != nil {
		updateFields.VerificationMethod = dbx.ResellerDomain_VerificationMethod_Raw(update.VerificationMethod)
	}
	if update.VerificationStatus != nil {
		updateFields.VerificationStatus = dbx.ResellerDomain_VerificationStatus(*update.VerificationStatus)
	}
	if update.SSLStatus != nil {
		updateFields.SslStatus = dbx.ResellerDomain_SslStatus(*update.SSLStatus)
	}
	if update.DNSTarget != nil {
		updateFields.DnsTarget = dbx.ResellerDomain_DnsTarget_Raw(update.DNSTarget)
	}
	if update.VerifiedAt != nil {
		updateFields.VerifiedAt = dbx.ResellerDomain_VerifiedAt_Raw(update.VerifiedAt)
	}
	if update.DeletedAt != nil {
		updateFields.DeletedAt = dbx.ResellerDomain_DeletedAt_Raw(update.DeletedAt)
	}

	updated, err := repo.db.Update_ResellerDomain_By_ResellerId(ctx, dbx.ResellerDomain_ResellerId(resellerID[:]), updateFields)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return nil, seller.ErrNotFound.New("")
		}
		return nil, err
	}

	return resellerDomainFromDBX(updated)
}

func resellerFromDBX(resellerDBX *dbx.Reseller) (*seller.Reseller, error) {
	if resellerDBX == nil {
		return nil, Error.New("reseller parameter is nil")
	}

	id, err := uuid.FromBytes(resellerDBX.Id)
	if err != nil {
		return nil, err
	}

	var recoveryCodes []string
	if resellerDBX.MfaRecoveryCodes != nil {
		if unmarshalErr := json.Unmarshal([]byte(*resellerDBX.MfaRecoveryCodes), &recoveryCodes); unmarshalErr != nil {
			return nil, unmarshalErr
		}
	}

	return &seller.Reseller{
		ID:                          id,
		Name:                        resellerDBX.Name,
		Email:                       resellerDBX.Email,
		PasswordHash:                resellerDBX.PasswordHash,
		CompanyName:                 resellerDBX.CompanyName,
		Status:                      seller.ResellerStatus(resellerDBX.Status),
		CreatedAt:                   resellerDBX.CreatedAt,
		UpdatedAt:                   resellerDBX.UpdatedAt,
		DeletedAt:                   resellerDBX.DeletedAt,
		FailedLoginCount:            derefInt(resellerDBX.FailedLoginCount),
		LoginLockoutExpiration:      derefTime(resellerDBX.LoginLockoutExpiration),
		ActivationCode:              derefString(resellerDBX.ActivationCode),
		SignupID:                    derefString(resellerDBX.SignupId),
		NewUnverifiedEmail:          resellerDBX.NewUnverifiedEmail,
		EmailChangeVerificationStep: resellerDBX.EmailChangeVerificationStep,
		MFAEnabled:                  resellerDBX.MfaEnabled,
		MFASecretKey:                derefString(resellerDBX.MfaSecretKey),
		MFARecoveryCodes:            recoveryCodes,
	}, nil
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func resellerConfigFromDBX(configDBX *dbx.ResellerConfig) (*seller.ResellerConfig, error) {
	if configDBX == nil {
		return nil, Error.New("reseller config parameter is nil")
	}

	id, err := uuid.FromBytes(configDBX.Id)
	if err != nil {
		return nil, err
	}
	resellerID, err := uuid.FromBytes(configDBX.ResellerId)
	if err != nil {
		return nil, err
	}

	return &seller.ResellerConfig{
		ID:              id,
		ResellerID:      resellerID,
		Config:          configDBX.Config,
		ActiveThemeType: configDBX.ActiveThemeType,
		ActiveThemeID:   activeThemeIDFromDBX(configDBX.ActiveThemeId),
		CreatedAt:       configDBX.CreatedAt,
		UpdatedAt:       configDBX.UpdatedAt,
	}, nil
}

func activeThemeIDFromDBX(raw []byte) *uuid.UUID {
	if len(raw) == 0 {
		return nil
	}
	id, err := uuid.FromBytes(raw)
	if err != nil {
		return nil
	}
	return &id
}

func activeThemeIDField(id *uuid.UUID) dbx.ResellerConfig_ActiveThemeId_Field {
	if id == nil || id.IsZero() {
		return dbx.ResellerConfig_ActiveThemeId_Null()
	}
	return dbx.ResellerConfig_ActiveThemeId(id[:])
}

func resellerDomainFromDBX(domainDBX *dbx.ResellerDomain) (*seller.ResellerDomain, error) {
	if domainDBX == nil {
		return nil, Error.New("reseller domain parameter is nil")
	}

	id, err := uuid.FromBytes(domainDBX.Id)
	if err != nil {
		return nil, err
	}
	resellerID, err := uuid.FromBytes(domainDBX.ResellerId)
	if err != nil {
		return nil, err
	}

	return &seller.ResellerDomain{
		ID:                 id,
		ResellerID:         resellerID,
		Domain:             domainDBX.Domain,
		DomainType:         domainDBX.DomainType,
		Status:             domainDBX.Status,
		VerificationMethod: domainDBX.VerificationMethod,
		VerificationStatus: domainDBX.VerificationStatus,
		SSLStatus:          domainDBX.SslStatus,
		DNSTarget:          domainDBX.DnsTarget,
		VerifiedAt:         domainDBX.VerifiedAt,
		CreatedAt:          domainDBX.CreatedAt,
		UpdatedAt:          domainDBX.UpdatedAt,
		DeletedAt:          domainDBX.DeletedAt,
	}, nil
}
