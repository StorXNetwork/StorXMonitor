// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/StorXNetwork/StorXMonitor/private/post"
	"github.com/StorXNetwork/StorXMonitor/satellite/analytics"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleauth"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/common/http/requestid"
	"github.com/StorXNetwork/common/uuid"
)

var mon = monkit.Package()

const (
	emailNotFoundErrMsg  = "There are no resellers with the specified email"
	credentialsErrMsg    = "Your login credentials are incorrect, please try again"
	changePasswordErrMsg = "Your old password is incorrect, please try again"
	emailUsedErrMsg      = "This email is already in use, try another"
)

var (
	// Error describes internal seller service error.
	Error = errs.Class("seller service")

	// ErrEmailNotFound occurs when no resellers have the specified email.
	ErrEmailNotFound = errs.Class("email not found")
	// ErrTokenExpiration is error type of token reached expiration time.
	ErrTokenExpiration = errs.Class("token expiration")
	// ErrLoginCredentials occurs when provided invalid login credentials.
	ErrLoginCredentials = errs.Class("login credentials")
	// ErrChangePassword occurs when provided old password is incorrect.
	ErrChangePassword = errs.Class("change password")
	// ErrAlreadyMember occurs when email is already registered.
	ErrAlreadyMember = errs.Class("already member")
	// ErrValidation is error type for validation errors.
	ErrValidation = errs.Class("validation")
	// ErrCaptcha is error type for captcha errors.
	ErrCaptcha = errs.Class("captcha")
	// ErrActivationCode is error type for activation code errors.
	ErrActivationCode = errs.Class("activation code")
	// ErrPasswordAlreadySet occurs when set-password is called but password exists.
	ErrPasswordAlreadySet = errs.Class("password already set")
	// ErrBrandingNotFound occurs when reseller has not created branding config yet.
	ErrBrandingNotFound = errs.Class("branding not found")
	// ErrBrandingAlreadyExists occurs when reseller tries to create branding config twice.
	ErrBrandingAlreadyExists = errs.Class("branding already exists")
	// ErrMailNotConfigured occurs when branding is changed without complete SMTP settings.
	ErrMailNotConfigured = errs.Class("mail not configured")
	// ErrDomainNotFound occurs when reseller has not connected a domain yet.
	ErrDomainNotFound = errs.Class("domain not found")
	// ErrDomainAlreadyExists occurs when reseller tries to connect a domain twice.
	ErrDomainAlreadyExists = errs.Class("domain already exists")
	// ErrCustomThemeLimit is returned when a reseller already has MaxCustomThemesPerReseller themes.
	ErrCustomThemeLimit = errs.Class("custom theme limit reached")
	// ErrActiveThemeInUse is returned when deleting the currently active custom theme.
	ErrActiveThemeInUse = errs.Class("cannot delete active theme")
	// ErrThemeNameInUse is returned when a theme name is already taken.
	ErrThemeNameInUse = errs.Class("theme name already in use")
)

// SellerServerRuntimeConfig holds runtime config for seller auth emails and activation.
type SellerServerRuntimeConfig struct {
	SatelliteName         string
	ExternalAddress       string
	LetUsKnowURL          string
	TermsAndConditionsURL string
	ContactInfoURL        string
	GeneralRequestURL     string
}

// Service handles seller-related logic.
//
// architecture: Service
type Service struct {
	log                *zap.Logger
	auditLogger        *zap.Logger
	store              DB
	analytics          *analytics.Service
	tokens             *consoleauth.Service
	authConfig         AuthConfig
	externalAddress    string
	badPasswordsLoaded bool

	mailService                *mailservice.Service
	loginCaptchaHandler        console.CaptchaHandler
	registrationCaptchaHandler console.CaptchaHandler
	runtimeConfig              SellerServerRuntimeConfig
}

// NewService returns a new instance of Service.
func NewService(
	log *zap.Logger,
	store DB,
	analytics *analytics.Service,
	tokens *consoleauth.Service,
	authConfig AuthConfig,
	externalAddress string,
	badPasswordsLoaded bool,
) (*Service, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if store == nil {
		return nil, errs.New("store can't be nil")
	}

	authConfig.applyDefaults()

	s := &Service{
		log:                log,
		auditLogger:        log.Named("auditlog"),
		store:              store,
		analytics:          analytics,
		tokens:             tokens,
		authConfig:         authConfig,
		externalAddress:    externalAddress,
		badPasswordsLoaded: badPasswordsLoaded,
	}
	s.initCaptchaHandlers()
	return s, nil
}

// ExtendService adds auth dependencies to Service.
func (s *Service) ExtendService(
	mailService *mailservice.Service,
	runtimeConfig SellerServerRuntimeConfig,
) {
	s.mailService = mailService
	s.runtimeConfig = runtimeConfig
}

func (s *Service) validateBrandingConfig(cfg ResellerBrandingConfig) (ResellerBrandingConfig, error) {
	if strings.TrimSpace(cfg.BrandName) == "" {
		return ResellerBrandingConfig{}, ErrValidation.New("brandName is required")
	}
	normalizeBrandingConfig(&cfg)
	if !cfg.Theme.IsEmpty() {
		if err := validateThemeColors(cfg.Theme); err != nil {
			return ResellerBrandingConfig{}, err
		}
	}
	return cfg, nil
}

func (s *Service) brandingConfigFromDB(dbCfg *ResellerConfig) (ResellerBrandingConfig, error) {
	if dbCfg == nil || len(dbCfg.Config) == 0 {
		return ResellerBrandingConfig{}, ErrBrandingNotFound.New("branding configuration not found")
	}

	cfg, err := parseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return ResellerBrandingConfig{}, Error.Wrap(err)
	}
	// Mail-only rows (SMTP saved before branding) are not treated as branding yet.
	if strings.TrimSpace(cfg.BrandName) == "" {
		return ResellerBrandingConfig{}, ErrBrandingNotFound.New("branding configuration not found")
	}
	// Never expose SMTP credentials through branding GET.
	cfg.Mail = nil
	return cfg, nil
}

func requireConfiguredSMTP(mail *ResellerMailSettings) error {
	if _, ok := mail.ToMailConfig(); !ok {
		return ErrMailNotConfigured.New("configure SMTP mail settings before setting branding")
	}
	return nil
}

// CreateBrandingForCurrentReseller creates branding config for the authenticated reseller.
func (s *Service) CreateBrandingForCurrentReseller(ctx context.Context, cfg ResellerBrandingConfig) (err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	cfg, err = s.validateBrandingConfig(cfg)
	if err != nil {
		return err
	}

	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return ErrMailNotConfigured.New("configure SMTP mail settings before setting branding")
		}
		return Error.Wrap(err)
	}

	existing, err := parseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return Error.Wrap(err)
	}
	if err = requireConfiguredSMTP(existing.Mail); err != nil {
		return err
	}
	if strings.TrimSpace(existing.BrandName) != "" {
		return ErrBrandingAlreadyExists.New("branding configuration already exists")
	}

	// Preserve SMTP saved before branding; branding multipart must not wipe it.
	cfg.Mail = existing.Mail

	initialTheme := cfg.Theme
	cfg.Theme = ResellerBrandingTheme{}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return Error.Wrap(err)
	}

	_, err = s.store.ResellerConfigs().Update(ctx, reseller.ID, UpdateResellerConfigRequest{
		Config:    encoded,
		UpdatedAt: time.Now(),
	})
	if err != nil {
		return Error.Wrap(err)
	}

	if !initialTheme.IsEmpty() {
		if err := s.maybeCreateCustomThemeFromBranding(ctx, reseller.ID, initialTheme); err != nil {
			return err
		}
	}

	s.auditLog(ctx, fmt.Sprintf("create branding (%s)", cfg.BrandName), &reseller.ID, reseller.Email)
	s.invalidateBrandingCache(ctx, reseller.ID)
	return nil
}

// GetBrandingForCurrentReseller returns branding for the authenticated reseller.
func (s *Service) GetBrandingForCurrentReseller(ctx context.Context) (cfg ResellerBrandingConfig, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return ResellerBrandingConfig{}, Error.Wrap(err)
	}

	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return ResellerBrandingConfig{}, ErrBrandingNotFound.New("branding configuration not found")
		}
		return ResellerBrandingConfig{}, Error.Wrap(err)
	}

	return s.brandingConfigFromDB(dbCfg)
}

// GetBrandingViewForCurrentReseller returns branding with resolved active theme and theme lists.
func (s *Service) GetBrandingViewForCurrentReseller(ctx context.Context) (ResellerBrandingView, error) {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return ResellerBrandingView{}, Error.Wrap(err)
	}

	cfg, err := s.GetBrandingForCurrentReseller(ctx)
	if err != nil {
		return ResellerBrandingView{}, err
	}

	return s.BuildBrandingView(ctx, reseller.ID, cfg)
}

// UpdateBrandingForCurrentReseller updates branding for the authenticated reseller.
func (s *Service) UpdateBrandingForCurrentReseller(ctx context.Context, cfg ResellerBrandingConfig) (err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	cfg, err = s.validateBrandingConfig(cfg)
	if err != nil {
		return err
	}
	cfg.Theme = ResellerBrandingTheme{}

	existingDB, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return ErrBrandingNotFound.New("branding configuration not found")
		}
		return Error.Wrap(err)
	}

	existing, parseErr := parseBrandingConfigJSON(existingDB.Config)
	if parseErr != nil {
		return Error.Wrap(parseErr)
	}
	if err = requireConfiguredSMTP(existing.Mail); err != nil {
		return err
	}
	if strings.TrimSpace(existing.BrandName) == "" {
		return ErrBrandingNotFound.New("branding configuration not found")
	}
	// Preserve seller SMTP settings — branding multipart updates must not wipe them.
	cfg.Mail = existing.Mail

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return Error.Wrap(err)
	}

	_, err = s.store.ResellerConfigs().Update(ctx, reseller.ID, UpdateResellerConfigRequest{
		Config:    encoded,
		UpdatedAt: time.Now(),
	})
	if err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, fmt.Sprintf("update branding (%s)", cfg.BrandName), &reseller.ID, reseller.Email)
	s.invalidateBrandingCache(ctx, reseller.ID)
	return nil
}

// GetMailSettingsForCurrentReseller returns masked SMTP settings for the seller dashboard.
func (s *Service) GetMailSettingsForCurrentReseller(ctx context.Context) (ResellerMailSettingsView, error) {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}

	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return (&ResellerMailSettings{}).toView(), nil
		}
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}

	cfg, err := parseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}
	return cfg.Mail.toView(), nil
}

// UpdateMailSettingsForCurrentReseller saves SMTP settings from the seller dashboard into reseller_configs JSON.
// SMTP may be configured before branding exists; branding create/update then requires it.
func (s *Service) UpdateMailSettingsForCurrentReseller(ctx context.Context, req UpdateResellerMailSettingsRequest) (ResellerMailSettingsView, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}

	var cfg ResellerBrandingConfig
	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID)
	switch {
	case err == nil:
		cfg, err = parseBrandingConfigJSON(dbCfg.Config)
		if err != nil {
			return ResellerMailSettingsView{}, Error.Wrap(err)
		}
	case ErrNotFound.Has(err):
		// Allow saving SMTP before branding is created.
	default:
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}

	mail, err := validateResellerMailSettings(req, cfg.Mail)
	if err != nil {
		return ResellerMailSettingsView{}, err
	}
	cfg.Mail = mail

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}

	now := time.Now()
	if dbCfg == nil {
		configID, idErr := uuid.New()
		if idErr != nil {
			return ResellerMailSettingsView{}, Error.Wrap(idErr)
		}
		_, err = s.store.ResellerConfigs().Insert(ctx, &ResellerConfig{
			ID:         configID,
			ResellerID: reseller.ID,
			Config:     encoded,
			CreatedAt:  now,
			UpdatedAt:  now,
		})
	} else {
		_, err = s.store.ResellerConfigs().Update(ctx, reseller.ID, UpdateResellerConfigRequest{
			Config:    encoded,
			UpdatedAt: now,
		})
	}
	if err != nil {
		return ResellerMailSettingsView{}, Error.Wrap(err)
	}

	s.auditLog(ctx, "update mail settings", &reseller.ID, reseller.Email)
	s.invalidateBrandingCache(ctx, reseller.ID)
	return mail.toView(), nil
}

func (s *Service) resolveMailSettingsForCurrentReseller(ctx context.Context, req UpdateResellerMailSettingsRequest) (*ResellerMailSettings, error) {
	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var existing *ResellerMailSettings
	if dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID); err == nil {
		if cfg, parseErr := parseBrandingConfigJSON(dbCfg.Config); parseErr == nil {
			existing = cfg.Mail
		}
	}

	// When body is empty, reuse saved settings.
	if strings.TrimSpace(req.From) == "" && strings.TrimSpace(req.SMTPServerAddress) == "" &&
		strings.TrimSpace(req.Login) == "" && strings.TrimSpace(req.Password) == "" &&
		strings.TrimSpace(req.AuthType) == "" {
		if existing == nil {
			return nil, ErrValidation.New("save mail settings before testing, or provide SMTP fields in the request body")
		}
		req = UpdateResellerMailSettingsRequest{
			From:              existing.From,
			SMTPServerAddress: existing.SMTPServerAddress,
			AuthType:          existing.AuthType,
			Login:             existing.Login,
			Password:          existing.Password,
		}
	}

	return validateResellerMailSettings(req, existing)
}

func (s *Service) resolveMailConfigForCurrentReseller(ctx context.Context, req UpdateResellerMailSettingsRequest) (mailservice.Config, error) {
	mail, err := s.resolveMailSettingsForCurrentReseller(ctx, req)
	if err != nil {
		return mailservice.Config{}, err
	}
	cfg, ok := mail.ToMailConfig()
	if !ok {
		return mailservice.Config{}, ErrValidation.New("incomplete SMTP settings")
	}
	return cfg, nil
}

// CheckMailHostForCurrentReseller verifies SMTP connectivity for the seller dashboard.
func (s *Service) CheckMailHostForCurrentReseller(ctx context.Context, req UpdateResellerMailSettingsRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	cfg, err := s.resolveMailConfigForCurrentReseller(ctx, req)
	if err != nil {
		return err
	}
	if err = mailservice.VerifySMTPConfig(ctx, cfg); err != nil {
		return ErrValidation.New("%v", err)
	}
	return nil
}

// SendTestMailForCurrentReseller sends a test email, saves the SMTP settings on success, and returns the recipient.
func (s *Service) SendTestMailForCurrentReseller(ctx context.Context, req TestMailSMTPRequest) (to string, err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return "", Error.Wrap(err)
	}

	mail, err := s.resolveMailSettingsForCurrentReseller(ctx, req.UpdateResellerMailSettingsRequest)
	if err != nil {
		return "", err
	}
	cfg, ok := mail.ToMailConfig()
	if !ok {
		return "", ErrValidation.New("incomplete SMTP settings")
	}

	to = strings.TrimSpace(req.To)
	if to == "" {
		to = strings.TrimSpace(reseller.Email)
	}
	if to == "" {
		return "", ErrValidation.New("to is required")
	}

	if err = mailservice.SendTestEmail(ctx, cfg, to); err != nil {
		return "", ErrValidation.New("%v", err)
	}

	// Persist the settings that successfully sent mail so reseller-domain mail uses them.
	if _, err = s.UpdateMailSettingsForCurrentReseller(ctx, UpdateResellerMailSettingsRequest{
		From:              mail.From,
		SMTPServerAddress: mail.SMTPServerAddress,
		AuthType:          mail.AuthType,
		Login:             mail.Login,
		Password:          mail.Password,
	}); err != nil {
		return "", err
	}

	s.auditLog(ctx, "send smtp test email to "+to, &reseller.ID, reseller.Email)
	return to, nil
}

// MailSMTPConfigForReseller returns seller SMTP config when complete for that reseller domain.
// Callers should fall back to satellite mail.* config when ok is false.
func (s *Service) MailSMTPConfigForReseller(ctx context.Context, resellerID uuid.UUID) (mailservice.Config, bool) {
	if s == nil || s.store == nil || resellerID.IsZero() {
		return mailservice.Config{}, false
	}
	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, resellerID)
	if err != nil {
		return mailservice.Config{}, false
	}
	cfg, err := parseBrandingConfigJSON(dbCfg.Config)
	if err != nil {
		return mailservice.Config{}, false
	}
	return cfg.Mail.toMailConfig()
}

// DeleteBrandingForCurrentReseller deletes branding config for the authenticated reseller.
func (s *Service) DeleteBrandingForCurrentReseller(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if err := s.store.ResellerConfigs().DeleteByResellerID(ctx, reseller.ID); err != nil {
		return Error.Wrap(err)
	}
	if err := s.store.ResellerThemes().DeleteByResellerID(ctx, reseller.ID); err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "delete branding", &reseller.ID, reseller.Email)
	s.invalidateBrandingCache(ctx, reseller.ID)
	return nil
}

// ListCustomThemesForCurrentReseller returns custom themes for the authenticated reseller.
func (s *Service) ListCustomThemesForCurrentReseller(ctx context.Context) ([]CustomThemeSummary, error) {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	themes, err := s.store.ResellerThemes().ListByResellerID(ctx, reseller.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return customThemeSummaries(themes), nil
}

// ListThemePresets returns all system theme presets.
func (s *Service) ListThemePresets(ctx context.Context) ([]ThemePresetSummary, error) {
	defer mon.Task()(&ctx)(nil)

	presets, err := s.store.ThemePresets().List(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return presetSummaries(presets), nil
}

// BuildBrandingView returns branding config with resolved active theme and theme lists.
func (s *Service) BuildBrandingView(ctx context.Context, resellerID uuid.UUID, cfg ResellerBrandingConfig) (ResellerBrandingView, error) {
	defer mon.Task()(&ctx)(nil)

	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, resellerID)
	if err != nil {
		return ResellerBrandingView{}, Error.Wrap(err)
	}

	active, err := ResolveActiveTheme(ctx, s.store, dbCfg)
	if err != nil {
		return ResellerBrandingView{}, err
	}

	customThemes, err := s.store.ResellerThemes().ListByResellerID(ctx, resellerID)
	if err != nil {
		return ResellerBrandingView{}, Error.Wrap(err)
	}

	presets, err := s.store.ThemePresets().List(ctx)
	if err != nil {
		return ResellerBrandingView{}, Error.Wrap(err)
	}

	return ResellerBrandingView{
		ResellerBrandingConfig: cfg,
		ActiveTheme:            active,
		CustomThemes:           customThemeSummaries(customThemes),
		CustomThemeCount:       len(customThemes),
		CustomThemeLimit:       MaxCustomThemesPerReseller,
		SystemThemePresets:     presetSummaries(presets),
	}, nil
}

// CreateCustomThemeForCurrentReseller creates a custom theme (max 5).
func (s *Service) CreateCustomThemeForCurrentReseller(ctx context.Context, req CreateCustomThemeRequest) (ResellerCustomTheme, error) {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}

	name, err := validateCustomThemeName(req.Name)
	if err != nil {
		return ResellerCustomTheme{}, err
	}
	if err := validateThemeColors(req.Colors); err != nil {
		return ResellerCustomTheme{}, err
	}
	if err := s.ensureResellerThemeNameAvailable(ctx, reseller.ID, name, uuid.UUID{}); err != nil {
		return ResellerCustomTheme{}, err
	}

	count, err := s.store.ResellerThemes().CountByResellerID(ctx, reseller.ID)
	if err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}
	if count >= MaxCustomThemesPerReseller {
		return ResellerCustomTheme{}, ErrCustomThemeLimit.New("maximum of %d custom themes allowed", MaxCustomThemesPerReseller)
	}

	themeID, err := uuid.New()
	if err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}

	created, err := s.store.ResellerThemes().Insert(ctx, &ResellerCustomTheme{
		ID:         themeID,
		ResellerID: reseller.ID,
		Name:       name,
		Colors:     req.Colors,
	})
	if err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}

	s.invalidateBrandingCache(ctx, reseller.ID)
	return *created, nil
}

// UpdateCustomThemeForCurrentReseller updates a custom theme owned by the reseller.
func (s *Service) UpdateCustomThemeForCurrentReseller(ctx context.Context, themeID uuid.UUID, req UpdateCustomThemeRequest) (ResellerCustomTheme, error) {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}

	name, err := validateCustomThemeName(req.Name)
	if err != nil {
		return ResellerCustomTheme{}, err
	}
	if err := validateThemeColors(req.Colors); err != nil {
		return ResellerCustomTheme{}, err
	}
	if err := s.ensureResellerThemeNameAvailable(ctx, reseller.ID, name, themeID); err != nil {
		return ResellerCustomTheme{}, err
	}

	if _, err := s.store.ResellerThemes().GetByResellerID(ctx, reseller.ID, themeID); err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}

	updated, err := s.store.ResellerThemes().Update(ctx, themeID, name, req.Colors, time.Now())
	if err != nil {
		return ResellerCustomTheme{}, Error.Wrap(err)
	}
	if updated.ResellerID != reseller.ID {
		return ResellerCustomTheme{}, ErrNotFound.New("")
	}

	s.invalidateBrandingCache(ctx, reseller.ID)
	return *updated, nil
}

// DeleteCustomThemeForCurrentReseller deletes a custom theme if it is not active.
func (s *Service) DeleteCustomThemeForCurrentReseller(ctx context.Context, themeID uuid.UUID) error {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	theme, err := s.store.ResellerThemes().GetByResellerID(ctx, reseller.ID, themeID)
	if err != nil {
		return Error.Wrap(err)
	}

	dbCfg, err := s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID)
	if err != nil && !ErrNotFound.Has(err) {
		return Error.Wrap(err)
	}
	if dbCfg != nil &&
		strings.TrimSpace(dbCfg.ActiveThemeType) == ActiveThemeTypeCustom &&
		dbCfg.ActiveThemeID != nil &&
		*dbCfg.ActiveThemeID == theme.ID {
		return ErrActiveThemeInUse.New("switch to another theme before deleting this one")
	}

	if err := s.store.ResellerThemes().Delete(ctx, theme.ID); err != nil {
		return Error.Wrap(err)
	}

	s.invalidateBrandingCache(ctx, reseller.ID)
	return nil
}

// SetActiveThemeForCurrentReseller sets the active theme for the reseller portal.
func (s *Service) SetActiveThemeForCurrentReseller(ctx context.Context, req SetActiveThemeRequest) error {
	defer mon.Task()(&ctx)(nil)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	themeType := strings.TrimSpace(req.Type)
	if themeType != ActiveThemeTypeSystem && themeType != ActiveThemeTypeCustom {
		return ErrValidation.New("type must be system or custom")
	}

	themeID, err := uuid.FromString(strings.TrimSpace(req.ID))
	if err != nil {
		return ErrValidation.New("invalid theme id")
	}

	switch themeType {
	case ActiveThemeTypeCustom:
		if _, getErr := s.store.ResellerThemes().GetByResellerID(ctx, reseller.ID, themeID); getErr != nil {
			return Error.Wrap(getErr)
		}
	default:
		if _, getErr := s.store.ThemePresets().Get(ctx, themeID); getErr != nil {
			return Error.Wrap(getErr)
		}
	}

	if _, err = s.store.ResellerConfigs().GetByResellerID(ctx, reseller.ID); err != nil {
		if ErrNotFound.Has(err) {
			return ErrBrandingNotFound.New("create branding before setting active theme")
		}
		return Error.Wrap(err)
	}

	themeIDCopy := themeID
	activeIDPtr := &themeIDCopy
	now := time.Now()
	if _, err = s.store.ResellerConfigs().Update(ctx, reseller.ID, UpdateResellerConfigRequest{
		ActiveThemeType: &themeType,
		ActiveThemeID:   &activeIDPtr,
		UpdatedAt:       now,
	}); err != nil {
		return Error.Wrap(err)
	}

	s.invalidateBrandingCache(ctx, reseller.ID)
	return nil
}

func (s *Service) defaultPresetID(ctx context.Context) (uuid.UUID, error) {
	preset, err := s.store.ThemePresets().GetDefault(ctx)
	if err != nil {
		return uuid.UUID{}, Error.Wrap(err)
	}
	return preset.ID, nil
}

func (s *Service) setActiveThemeOnConfig(ctx context.Context, resellerID uuid.UUID, themeType string, themeID uuid.UUID) error {
	themeIDCopy := themeID
	activeIDPtr := &themeIDCopy
	now := time.Now()
	_, err := s.store.ResellerConfigs().Update(ctx, resellerID, UpdateResellerConfigRequest{
		ActiveThemeType: &themeType,
		ActiveThemeID:   &activeIDPtr,
		UpdatedAt:       now,
	})
	return err
}

func (s *Service) maybeCreateCustomThemeFromBranding(ctx context.Context, resellerID uuid.UUID, theme ResellerBrandingTheme) error {
	if theme.IsEmpty() {
		return nil
	}
	if err := validateThemeColors(theme); err != nil {
		return err
	}

	count, err := s.store.ResellerThemes().CountByResellerID(ctx, resellerID)
	if err != nil {
		return Error.Wrap(err)
	}
	if count >= MaxCustomThemesPerReseller {
		return ErrCustomThemeLimit.New("maximum of %d custom themes allowed", MaxCustomThemesPerReseller)
	}

	themeID, err := uuid.New()
	if err != nil {
		return Error.Wrap(err)
	}

	created, err := s.store.ResellerThemes().Insert(ctx, &ResellerCustomTheme{
		ID:         themeID,
		ResellerID: resellerID,
		Name:       "Custom",
		Colors:     theme,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	return s.setActiveThemeOnConfig(ctx, resellerID, ActiveThemeTypeCustom, created.ID)
}

func (s *Service) ensureResellerThemeNameAvailable(ctx context.Context, resellerID uuid.UUID, name string, excludeThemeID uuid.UUID) error {
	if preset, err := s.store.ThemePresets().GetByName(ctx, name); err == nil {
		if preset != nil {
			return ErrThemeNameInUse.New("theme name is already used by a system preset")
		}
	} else if !ErrNotFound.Has(err) {
		return Error.Wrap(err)
	}

	existing, err := s.store.ResellerThemes().GetByResellerIDAndName(ctx, resellerID, name)
	if err == nil {
		if excludeThemeID.IsZero() || existing.ID != excludeThemeID {
			return ErrThemeNameInUse.New("you already have a custom theme with this name")
		}
		return nil
	}
	if !ErrNotFound.Has(err) {
		return Error.Wrap(err)
	}
	return nil
}

// GetDomainForCurrentReseller returns the domain row for the authenticated reseller.
func (s *Service) GetDomainForCurrentReseller(ctx context.Context) (*ResellerDomain, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	domain, err := s.store.ResellerDomains().GetByResellerID(ctx, reseller.ID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return nil, ErrDomainNotFound.New("domain not connected")
		}
		return nil, Error.Wrap(err)
	}

	return domain, nil
}

// ConnectCustomDomainForCurrentReseller creates an active custom domain row for the authenticated reseller.
func (s *Service) ConnectCustomDomainForCurrentReseller(ctx context.Context, domainName string) (*ResellerDomain, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	domainName = strings.TrimSpace(domainName)
	if domainName == "" {
		return nil, ErrValidation.New("domain is required")
	}

	_, err = s.store.ResellerDomains().GetByResellerID(ctx, reseller.ID)
	if err == nil {
		return nil, ErrDomainAlreadyExists.New("domain is already connected for this reseller")
	}
	if !ErrNotFound.Has(err) {
		return nil, Error.Wrap(err)
	}

	now := time.Now()
	domainID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	domain := &ResellerDomain{
		ID:                 domainID,
		ResellerID:         reseller.ID,
		Domain:             domainName,
		DomainType:         DomainTypeCustom,
		Status:             DomainStatusActive,
		VerificationStatus: VerificationStatusVerified,
		SSLStatus:          SSLStatusIssued,
		VerifiedAt:         &now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	created, err := s.store.ResellerDomains().Insert(ctx, domain)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, fmt.Sprintf("connect domain (%s)", domainName), &reseller.ID, reseller.Email)
	s.invalidateBrandingCache(ctx, reseller.ID)
	return created, nil
}

// UpdateCustomDomainForCurrentReseller updates the single custom domain row for the authenticated reseller.
func (s *Service) UpdateCustomDomainForCurrentReseller(ctx context.Context, domainName string) (*ResellerDomain, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	domainName = strings.TrimSpace(domainName)
	if domainName == "" {
		return nil, ErrValidation.New("domain is required")
	}

	existing, err := s.store.ResellerDomains().GetByResellerID(ctx, reseller.ID)
	if err != nil {
		if ErrNotFound.Has(err) {
			return nil, ErrDomainNotFound.New("domain not connected")
		}
		return nil, Error.Wrap(err)
	}
	previousDomain := existing.Domain

	now := time.Now()
	updated, err := s.store.ResellerDomains().Update(ctx, reseller.ID, UpdateResellerDomainRequest{
		Domain:             &domainName,
		DomainType:         stringPtr(DomainTypeCustom),
		Status:             stringPtr(DomainStatusActive),
		VerificationStatus: stringPtr(VerificationStatusVerified),
		SSLStatus:          stringPtr(SSLStatusIssued),
		VerifiedAt:         &now,
		UpdatedAt:          now,
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, fmt.Sprintf("update domain (%s)", domainName), &reseller.ID, reseller.Email)
	s.invalidateBrandingCache(ctx, reseller.ID, previousDomain)
	return updated, nil
}

func stringPtr(v string) *string {
	return &v
}

// VerifyRegistrationCaptcha returns whether the registration captcha response is valid.
func (s *Service) VerifyRegistrationCaptcha(ctx context.Context, responseToken, userIP string) error {
	if s.registrationCaptchaHandler == nil {
		return nil
	}
	valid, _, err := s.registrationCaptchaHandler.Verify(ctx, responseToken, userIP)
	if err != nil {
		return ErrCaptcha.Wrap(err)
	}
	if !valid {
		return ErrCaptcha.New("captcha validation unsuccessful")
	}
	return nil
}

// VerifyForgotPasswordCaptcha returns whether the forgot-password captcha response is valid.
// Uses the same login captcha configuration as console users.
func (s *Service) VerifyForgotPasswordCaptcha(ctx context.Context, responseToken, userIP string) error {
	if s.loginCaptchaHandler == nil {
		return nil
	}
	valid, _, err := s.loginCaptchaHandler.Verify(ctx, responseToken, userIP)
	if err != nil {
		return ErrCaptcha.Wrap(err)
	}
	if !valid {
		return ErrCaptcha.New("captcha validation unsuccessful")
	}
	return nil
}

// Status returns basic seller service status information.
func (s *Service) Status(ctx context.Context) (map[string]string, error) {
	defer mon.Task()(&ctx)(nil)

	return map[string]string{
		"service": "seller",
		"status":  "ok",
	}, nil
}

// GetResellerByEmailWithUnverified returns reseller by email, splitting active and inactive accounts.
func (s *Service) GetResellerByEmailWithUnverified(ctx context.Context, email string) (verified *Reseller, unverified []Reseller, err error) {
	defer mon.Task()(&ctx)(&err)

	verified, unverified, err = s.store.Resellers().GetByEmailWithUnverified(ctx, email)
	if err != nil {
		if ErrNotFound.Has(err) {
			return nil, nil, ErrEmailNotFound.New(emailNotFoundErrMsg)
		}
		return nil, nil, err
	}

	return verified, unverified, nil
}

// TokenReseller authenticates reseller by email and password.
func (s *Service) TokenReseller(ctx context.Context, request AuthReseller) (*console.TokenInfo, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	if request.Password == "" {
		return nil, ErrValidation.New("password is required")
	}

	verifyCaptcha := func() error {
		if s.loginCaptchaHandler != nil {
			valid, _, captchaErr := s.loginCaptchaHandler.Verify(ctx, request.CaptchaResponse, request.IP)
			if captchaErr != nil {
				return ErrCaptcha.Wrap(captchaErr)
			}
			if !valid {
				return ErrCaptcha.New("captcha validation unsuccessful")
			}
		}
		return nil
	}

	captchaSkipped := true
	if request.MFARecoveryCode == "" && request.MFAPasscode == "" {
		if err = verifyCaptcha(); err != nil {
			return nil, err
		}
		captchaSkipped = false
	}

	reseller, _, err := s.store.Resellers().GetByEmailWithUnverified(ctx, request.Email)
	if err != nil {
		if ErrNotFound.Has(err) || ErrEmailNotFound.Has(err) {
			return nil, ErrLoginCredentials.New(credentialsErrMsg)
		}
		return nil, Error.Wrap(err)
	}
	if reseller == nil {
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}
	if reseller.Status != ResellerActive {
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	now := time.Now()
	if reseller.LoginLockoutExpiration.After(now) {
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if !console.HasPasswordSet(reseller.PasswordHash) {
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if bcryptErr := bcrypt.CompareHashAndPassword(reseller.PasswordHash, []byte(request.Password)); bcryptErr != nil {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return nil, lockErr
		}
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if reseller.MFAEnabled {
		if err = s.logInVerifyMFAReseller(ctx, reseller, request); err != nil {
			return nil, err
		}
	} else if captchaSkipped {
		if err = verifyCaptcha(); err != nil {
			return nil, err
		}
	}

	if reseller.FailedLoginCount != 0 {
		if resetErr := s.resetAccountLock(ctx, reseller); resetErr != nil {
			return nil, resetErr
		}
	}

	var customDuration *time.Duration
	if request.RememberForOneWeek {
		week := 7 * 24 * time.Hour
		customDuration = &week
	}

	return s.GenerateSessionTokenForReseller(ctx, reseller.ID, reseller.Email, request.IP, customDuration)
}

// RegisterReseller creates a new inactive reseller and sends activation email when enabled.
func (s *Service) RegisterReseller(ctx context.Context, req CreateResellerRequest) (*Reseller, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	if err = console.ValidateFullName(req.FullName); err != nil {
		return nil, ErrValidation.Wrap(err)
	}
	if err = console.ValidateNewPassword(req.Password); err != nil {
		return nil, ErrValidation.Wrap(err)
	}

	verified, unverified, err := s.GetResellerByEmailWithUnverified(ctx, req.Email)
	if err != nil && !ErrEmailNotFound.Has(err) {
		return nil, Error.Wrap(err)
	}
	if verified != nil {
		return nil, ErrAlreadyMember.New("The requested Email ID is already registered. Please try again using a different email address.")
	}
	if len(unverified) > 0 {
		return nil, ErrAlreadyMember.New(emailUsedErrMsg)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.authConfig.PasswordCost)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	resellerID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	now := time.Now()
	status := ResellerInactive
	var companyNamePtr *string
	if req.CompanyName != "" {
		companyNamePtr = &req.CompanyName
	}

	reseller := &Reseller{
		ID:           resellerID,
		Name:         req.FullName,
		Email:        strings.TrimSpace(req.Email),
		PasswordHash: hash,
		CompanyName:  companyNamePtr,
		Status:       status,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if s.authConfig.SignupActivationCodeEnabled {
		code, codeErr := generateVerificationCode()
		if codeErr != nil {
			return nil, Error.Wrap(codeErr)
		}
		requestID := requestid.FromContext(ctx)
		reseller.ActivationCode = code
		reseller.SignupID = requestID
	}

	created, err := s.store.Resellers().Insert(ctx, reseller)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if s.authConfig.SignupActivationCodeEnabled {
		code := reseller.ActivationCode
		signupID := reseller.SignupID
		created, err = s.store.Resellers().Update(ctx, created.ID, UpdateResellerRequest{
			ActivationCode: &code,
			SignupID:       &signupID,
			UpdatedAt:      time.Now(),
		})
		if err != nil {
			return nil, Error.Wrap(err)
		}
	} else {
		active := ResellerActive
		created, err = s.store.Resellers().Update(ctx, created.ID, UpdateResellerRequest{
			Status:    &active,
			UpdatedAt: time.Now(),
		})
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}

	s.sendRegistrationEmail(ctx, created)
	s.auditLog(ctx, "register email", &created.ID, created.Email)
	return created, nil
}

// CreateResellerFromGoogle creates or reuses a reseller account for Google OAuth sign-in.
func (s *Service) CreateResellerFromGoogle(ctx context.Context, fullName, email, companyName string) (*Reseller, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	verified, unverified, err := s.GetResellerByEmailWithUnverified(ctx, email)
	if err != nil && !ErrEmailNotFound.Has(err) {
		return nil, Error.Wrap(err)
	}
	if verified != nil {
		return verified, nil
	}

	var reseller *Reseller
	if len(unverified) > 0 {
		reseller = &unverified[0]
		active := ResellerActive
		updated, updateErr := s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
			Name:      &fullName,
			Status:    &active,
			UpdatedAt: time.Now(),
		})
		if updateErr != nil {
			return nil, Error.Wrap(updateErr)
		}
		return updated, nil
	}

	resellerID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Passwordless social signup: empty bytea satisfies NOT NULL; HasPasswordSet treats len==0 as unset.
	passwordHash := make([]byte, 0)

	now := time.Now()
	var companyNamePtr *string
	if companyName != "" {
		companyNamePtr = &companyName
	}

	reseller = &Reseller{
		ID:           resellerID,
		Name:         fullName,
		Email:        email,
		PasswordHash: passwordHash,
		CompanyName:  companyNamePtr,
		Status:       ResellerActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	created, err := s.store.Resellers().Insert(ctx, reseller)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, "register google", &created.ID, created.Email)
	return created, nil
}

// ActivateAccountReseller verifies signup activation code and logs in.
func (s *Service) ActivateAccountReseller(ctx context.Context, email, code, signupID, ip string) (*console.TokenInfo, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	_, unverified, err := s.GetResellerByEmailWithUnverified(ctx, email)
	if err != nil && !ErrEmailNotFound.Has(err) {
		return nil, Error.Wrap(err)
	}
	if len(unverified) == 0 {
		return nil, ErrActivationCode.New("invalid activation code or account locked")
	}

	reseller := &unverified[0]
	if reseller.ActivationCode != code || (signupID != "" && reseller.SignupID != signupID) {
		if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
			return nil, lockErr
		}
		return nil, ErrActivationCode.New("invalid activation code or account locked")
	}

	if reseller.FailedLoginCount != 0 {
		if resetErr := s.resetAccountLock(ctx, reseller); resetErr != nil {
			return nil, resetErr
		}
	}

	active := ResellerActive
	updated, err := s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		Status:    &active,
		UpdatedAt: time.Now(),
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return s.GenerateSessionTokenForReseller(ctx, updated.ID, updated.Email, ip, nil)
}

// ResendActivationEmailReseller resends activation email or password reset for active accounts.
func (s *Service) ResendActivationEmailReseller(ctx context.Context, email string) error {
	defer mon.Task()(&ctx)(nil)

	verified, unverified, err := s.GetResellerByEmailWithUnverified(ctx, email)
	if err != nil && !ErrEmailNotFound.Has(err) {
		return Error.Wrap(err)
	}

	if verified != nil {
		return s.sendForgotPasswordEmail(ctx, verified)
	}
	if len(unverified) == 0 {
		return nil
	}

	s.sendRegistrationEmail(ctx, &unverified[0])
	return nil
}

// ForgotPasswordReseller sends password recovery email when account exists.
func (s *Service) ForgotPasswordReseller(ctx context.Context, email, captchaResponse, ip string) error {
	var err error
	defer mon.Task()(&ctx)(&err)

	if err = s.VerifyForgotPasswordCaptcha(ctx, captchaResponse, ip); err != nil {
		return err
	}

	reseller, _, err := s.GetResellerByEmailWithUnverified(ctx, email)
	if err != nil || reseller == nil {
		s.sendUnknownResetEmail(ctx, email)
		return nil
	}

	return s.sendForgotPasswordEmail(ctx, reseller)
}

// ResetPasswordReseller resets password using recovery token from email.
func (s *Service) ResetPasswordReseller(ctx context.Context, tokenString, newPassword, passcode, recoveryCode string, t time.Time) error {
	var err error
	defer mon.Task()(&ctx)(&err)

	if err = console.ValidateNewPassword(newPassword); err != nil {
		return ErrValidation.Wrap(err)
	}

	ownerID, createdAt, err := s.store.ResetPasswordTokens().GetBySecret(ctx, tokenString)
	if err != nil {
		return ErrTokenExpiration.New("Your password recovery link has expired, please request another one")
	}

	if time.Since(createdAt) > 24*time.Hour {
		_ = s.store.ResetPasswordTokens().Delete(ctx, tokenString)
		return ErrTokenExpiration.New("Your password recovery link has expired, please request another one")
	}

	reseller, err := s.store.Resellers().Get(ctx, ownerID)
	if err != nil {
		return Error.Wrap(err)
	}

	if reseller.MFAEnabled {
		now := time.Now()
		if reseller.LoginLockoutExpiration.After(now) {
			s.auditLog(ctx, "reset password: 2fa failed account locked out", &reseller.ID, reseller.Email)
			return console.ErrTooManyAttempts.New("too many attempts, please try again later")
		}

		handleLockAccount := func() error {
			return s.handleFailedLogin(ctx, reseller)
		}

		if recoveryCode != "" {
			found := false
			for _, code := range reseller.MFARecoveryCodes {
				if code == recoveryCode {
					found = true
					break
				}
			}
			if !found {
				if lockErr := handleLockAccount(); lockErr != nil {
					return Error.Wrap(lockErr)
				}
				return ErrValidation.Wrap(console.ErrMFARecoveryCode.New("The MFA recovery code is not valid or has been previously used"))
			}
		} else if passcode != "" {
			valid, validateErr := console.ValidateMFAPasscode(passcode, reseller.MFASecretKey, t)
			if validateErr != nil {
				return ErrValidation.Wrap(console.ErrMFAPasscode.Wrap(validateErr))
			}
			if !valid {
				if lockErr := handleLockAccount(); lockErr != nil {
					return Error.Wrap(lockErr)
				}
				return ErrValidation.Wrap(console.ErrMFAPasscode.New("The MFA passcode is not valid or has expired"))
			}
		} else {
			return console.ErrMFAMissing.New("A MFA passcode or recovery code is required")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.authConfig.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	active := ResellerActive
	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		PasswordHash: hash,
		Status:       &active,
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		return Error.Wrap(err)
	}

	_ = s.store.ResetPasswordTokens().Delete(ctx, tokenString)
	_, _ = s.store.WebappSessionResellers().DeleteAllByResellerID(ctx, reseller.ID)

	s.auditLog(ctx, "reset password", &reseller.ID, reseller.Email)
	return nil
}

// ChangePasswordReseller updates password for authenticated reseller.
func (s *Service) ChangePasswordReseller(ctx context.Context, currentPassword, newPassword string) error {
	var err error
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	if bcryptErr := bcrypt.CompareHashAndPassword(reseller.PasswordHash, []byte(currentPassword)); bcryptErr != nil {
		return ErrChangePassword.New(changePasswordErrMsg)
	}
	if err = console.ValidateNewPassword(newPassword); err != nil {
		return ErrValidation.Wrap(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.authConfig.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		PasswordHash: hash,
		UpdatedAt:    time.Now(),
	})
	if err != nil {
		return Error.Wrap(err)
	}

	if secret, _, tokenErr := s.store.ResetPasswordTokens().GetByOwnerID(ctx, reseller.ID); tokenErr == nil {
		_ = s.store.ResetPasswordTokens().Delete(ctx, secret)
	}
	_, _ = s.store.WebappSessionResellers().DeleteAllByResellerID(ctx, reseller.ID)

	s.auditLog(ctx, "change password", &reseller.ID, reseller.Email)
	return nil
}

// SetPasswordReseller sets initial password when none is configured.
func (s *Service) SetPasswordReseller(ctx context.Context, newPassword string) error {
	var err error
	defer mon.Task()(&ctx)(&err)

	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}
	if console.HasPasswordSet(reseller.PasswordHash) {
		return ErrPasswordAlreadySet.New("password is already set")
	}
	if err = console.ValidateNewPassword(newPassword); err != nil {
		return ErrValidation.Wrap(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.authConfig.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		PasswordHash: hash,
		UpdatedAt:    time.Now(),
	})
	return Error.Wrap(err)
}

// GetAccountReseller returns account info for authenticated reseller.
func (s *Service) GetAccountReseller(ctx context.Context) (map[string]interface{}, error) {
	reseller, err := GetReseller(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return map[string]interface{}{
		"id":                   reseller.ID,
		"email":                reseller.Email,
		"name":                 reseller.Name,
		"companyName":          reseller.CompanyName,
		"hasPassword":          console.HasPasswordSet(reseller.PasswordHash),
		"status":               reseller.Status,
		"isMFAEnabled":         reseller.MFAEnabled,
		"mfaRecoveryCodeCount": len(reseller.MFARecoveryCodes),
	}, nil
}

// UpdateAccountReseller updates reseller profile fields.
func (s *Service) UpdateAccountReseller(ctx context.Context, fullName string) error {
	if err := console.ValidateFullName(fullName); err != nil {
		return ErrValidation.Wrap(err)
	}
	reseller, err := GetReseller(ctx)
	if err != nil {
		return Error.Wrap(err)
	}
	_, err = s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		Name:      &fullName,
		UpdatedAt: time.Now(),
	})
	return Error.Wrap(err)
}

// GenerateSessionTokenForReseller creates a signed session token for a reseller.
func (s *Service) GenerateSessionTokenForReseller(ctx context.Context, resellerID uuid.UUID, email, ip string, customDuration *time.Duration) (*console.TokenInfo, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	sessionID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	duration := s.authConfig.Session.Duration
	if customDuration != nil {
		duration = *customDuration
	} else if s.authConfig.Session.InactivityTimerEnabled {
		duration = time.Duration(s.authConfig.Session.InactivityTimerDuration) * time.Second
	}
	expiresAt := time.Now().Add(duration)

	_, err = s.store.WebappSessionResellers().Create(ctx, sessionID, resellerID, ip, expiresAt)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	token := consoleauth.Token{Payload: sessionID.Bytes()}
	signature, err := s.tokens.SignToken(token)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	token.Signature = signature

	s.auditLog(ctx, "login reseller", &resellerID, email)

	return &console.TokenInfo{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// TokenAuthForReseller returns an authenticated context by session token.
func (s *Service) TokenAuthForReseller(ctx context.Context, token consoleauth.Token, authTime time.Time) (_ context.Context, err error) {
	defer mon.Task()(&ctx)(&err)

	valid, err := s.tokens.ValidateToken(token)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !valid {
		return nil, Error.New("incorrect signature")
	}

	sessionID, err := uuid.FromBytes(token.Payload)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	session, err := s.store.WebappSessionResellers().GetBySessionID(ctx, sessionID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(authTime) {
		_ = s.store.WebappSessionResellers().DeleteBySessionID(ctx, sessionID)
		return nil, ErrTokenExpiration.New("authorization failed. expiration reached.")
	}

	reseller, err := s.store.Resellers().Get(ctx, session.ResellerID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if reseller.Status != ResellerActive {
		return nil, ErrTokenExpiration.New("authorization failed. account is not active.")
	}

	return WithReseller(ctx, reseller), nil
}

// DeleteSessionReseller removes session from database.
func (s *Service) DeleteSessionReseller(ctx context.Context, sessionID uuid.UUID) error {
	return Error.Wrap(s.store.WebappSessionResellers().DeleteBySessionID(ctx, sessionID))
}

// RefreshSessionReseller extends session expiration.
func (s *Service) RefreshSessionReseller(ctx context.Context, sessionID uuid.UUID) (time.Time, error) {
	if _, err := GetReseller(ctx); err != nil {
		return time.Time{}, Error.Wrap(err)
	}

	duration := s.authConfig.Session.Duration
	if s.authConfig.Session.InactivityTimerEnabled {
		duration = time.Duration(s.authConfig.Session.InactivityTimerDuration) * time.Second
	}
	expiresAt := time.Now().Add(duration)

	if err := s.store.WebappSessionResellers().UpdateExpiration(ctx, sessionID, expiresAt); err != nil {
		return time.Time{}, Error.Wrap(err)
	}
	return expiresAt, nil
}

func (s *Service) handleFailedLogin(ctx context.Context, reseller *Reseller) error {
	var lockoutDuration time.Duration
	count := reseller.FailedLoginCount + 1
	if count >= s.authConfig.LoginAttemptsWithoutPenalty-1 {
		lockoutDuration = time.Duration(math.Pow(s.authConfig.FailedLoginPenalty, float64(count-1))) * time.Minute
	}
	expiration := time.Now().Add(lockoutDuration)
	var expirationPtr *time.Time
	if lockoutDuration > 0 {
		expirationPtr = &expiration
	}
	_, err := s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		FailedLoginCount:       &count,
		LoginLockoutExpiration: &expirationPtr,
		UpdatedAt:              time.Now(),
	})
	return Error.Wrap(err)
}

func (s *Service) resetAccountLock(ctx context.Context, reseller *Reseller) error {
	zero := 0
	var zeroTime *time.Time
	_, err := s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
		FailedLoginCount:       &zero,
		LoginLockoutExpiration: &zeroTime,
		UpdatedAt:              time.Now(),
	})
	return Error.Wrap(err)
}

func (s *Service) logInVerifyMFAReseller(ctx context.Context, reseller *Reseller, request AuthReseller) error {
	if request.MFARecoveryCode != "" && request.MFAPasscode != "" {
		s.auditLog(ctx, "login: failed mfa conflict", &reseller.ID, reseller.Email)
		return console.ErrMFAConflict.New("Expected either passcode or recovery code, but got both")
	}

	if request.MFARecoveryCode != "" {
		found := false
		codeIndex := -1
		for i, code := range reseller.MFARecoveryCodes {
			if code == request.MFARecoveryCode {
				found = true
				codeIndex = i
				break
			}
		}
		if !found {
			if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
				return lockErr
			}
			s.auditLog(ctx, "login: failed mfa recovery", &reseller.ID, reseller.Email)
			return console.ErrMFARecoveryCode.New("The MFA recovery code is not valid or has been previously used")
		}

		reseller.MFARecoveryCodes = append(reseller.MFARecoveryCodes[:codeIndex], reseller.MFARecoveryCodes[codeIndex+1:]...)
		_, err := s.store.Resellers().Update(ctx, reseller.ID, UpdateResellerRequest{
			MFARecoveryCodes: &reseller.MFARecoveryCodes,
			UpdatedAt:        time.Now(),
		})
		if err != nil {
			return Error.Wrap(err)
		}
	} else if request.MFAPasscode != "" {
		valid, err := console.ValidateMFAPasscode(request.MFAPasscode, reseller.MFASecretKey, time.Now())
		if err != nil {
			if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
				return lockErr
			}
			return console.ErrMFAPasscode.Wrap(err)
		}
		if !valid {
			if lockErr := s.handleFailedLogin(ctx, reseller); lockErr != nil {
				return lockErr
			}
			s.auditLog(ctx, "login: failed mfa passcode invalid", &reseller.ID, reseller.Email)
			return console.ErrMFAPasscode.New("The MFA passcode is not valid or has expired")
		}
	} else {
		s.auditLog(ctx, "login: failed mfa missing", &reseller.ID, reseller.Email)
		return console.ErrMFAMissing.New("A MFA passcode or recovery code is required")
	}

	if reseller.FailedLoginCount != 0 {
		return s.resetAccountLock(ctx, reseller)
	}

	return nil
}

func generateVerificationCode() (string, error) {
	randNum, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	return randNum.Add(randNum, big.NewInt(100000)).String(), nil
}

func (s *Service) sendRegistrationEmail(ctx context.Context, reseller *Reseller) {
	if s.mailService == nil {
		return
	}
	externalAddr := strings.TrimSuffix(s.externalAddress, "/") + "/"
	if s.authConfig.SignupActivationCodeEnabled {
		s.mailService.SendRenderedAsync(ctx, []post.Address{{Address: reseller.Email}}, &console.AccountActivationCodeEmail{
			ActivationCode: reseller.ActivationCode,
		})
		return
	}
	token, err := s.tokens.CreateToken(ctx, reseller.ID, reseller.Email)
	if err != nil {
		s.log.Warn("failed to create activation token", zap.Error(err))
		return
	}
	s.mailService.SendRenderedAsync(ctx, []post.Address{{Address: reseller.Email, Name: reseller.Name}}, &console.AccountActivationEmail{
		Username:       reseller.Name,
		ActivationLink: externalAddr + "login?token=" + token,
		Origin:         s.externalAddress,
	})
}

func (s *Service) sendForgotPasswordEmail(ctx context.Context, reseller *Reseller) error {
	if s.mailService == nil {
		return nil
	}
	if secret, _, err := s.store.ResetPasswordTokens().GetByOwnerID(ctx, reseller.ID); err == nil {
		_ = s.store.ResetPasswordTokens().Delete(ctx, secret)
	}
	token, err := s.store.ResetPasswordTokens().Create(ctx, reseller.ID)
	if err != nil {
		return Error.Wrap(err)
	}
	externalAddr := strings.TrimSuffix(s.externalAddress, "/") + "/"
	s.mailService.SendRenderedAsync(ctx, []post.Address{{Address: reseller.Email, Name: reseller.Name}}, &console.ForgotPasswordEmail{
		UserName:                   reseller.Name,
		Origin:                     s.externalAddress,
		ResetLink:                  externalAddr + "password-recovery?token=" + token,
		CancelPasswordRecoveryLink: externalAddr + "cancel-password-recovery?token=" + token,
		LetUsKnowURL:               s.runtimeConfig.LetUsKnowURL,
		ContactInfoURL:             s.runtimeConfig.ContactInfoURL,
		TermsAndConditionsURL:      s.runtimeConfig.TermsAndConditionsURL,
	})
	return nil
}

func (s *Service) sendUnknownResetEmail(ctx context.Context, email string) {
	if s.mailService == nil {
		return
	}
	externalAddr := strings.TrimSuffix(s.externalAddress, "/") + "/"
	s.mailService.SendRenderedAsync(ctx, []post.Address{{Address: email}}, &console.UnknownResetPasswordEmail{
		Satellite:           s.runtimeConfig.SatelliteName,
		Email:               email,
		DoubleCheckLink:     externalAddr + "login",
		ResetPasswordLink:   externalAddr + "forgot-password",
		CreateAnAccountLink: externalAddr + "signup",
		SupportTeamLink:     s.runtimeConfig.GeneralRequestURL,
	})
}

func (s *Service) auditLog(ctx context.Context, operation string, resellerID *uuid.UUID, email string) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.Bool("seller", true),
	}
	if resellerID != nil {
		fields = append(fields, zap.Stringer("resellerID", *resellerID))
	}
	if email != "" {
		fields = append(fields, zap.String("email", email))
	}
	s.auditLogger.Info("seller activity", fields...)
}

type resellerCtxKey struct{}

// WithReseller creates new context with Reseller.
func WithReseller(ctx context.Context, reseller *Reseller) context.Context {
	return context.WithValue(ctx, resellerCtxKey{}, reseller)
}

// GetReseller gets Reseller from context.
func GetReseller(ctx context.Context) (*Reseller, error) {
	reseller, ok := ctx.Value(resellerCtxKey{}).(*Reseller)
	if !ok || reseller == nil {
		return nil, errs.New("reseller is not set in context")
	}
	return reseller, nil
}
