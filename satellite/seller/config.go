// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"time"

	"github.com/StorXNetwork/StorXMonitor/satellite/console"
)

// AuthConfig contains seller auth configuration separate from console user settings.
type AuthConfig struct {
	Captcha CaptchaConfig `help:"seller captcha configuration for login and registration"`

	PasswordCost                int     `help:"password hashing cost (0=automatic)" testDefault:"4" default:"0"`
	LoginAttemptsWithoutPenalty int     `help:"number of times reseller can try to login without penalty" default:"3"`
	FailedLoginPenalty          float64 `help:"incremental duration of penalty for failed login attempts in minutes" default:"2.0"`

	Session AuthSessionConfig `help:"seller session configuration"`

	SignupActivationCodeEnabled   bool `help:"whether reseller account activation uses an activation code" default:"true" testDefault:"false" devDefault:"false"`
	EmailChangeFlowEnabled        bool `help:"whether reseller email change flow is enabled" default:"false"`
	SelfServeAccountDeleteEnabled bool `help:"whether self-serve reseller account delete flow is enabled" default:"false"`
	ActiveSessionsViewEnabled     bool `help:"whether active sessions table view should be shown in seller UI" default:"false"`
	LiveCheckBadPasswords         bool `help:"whether live bad-password checking is enabled in seller UI" default:"false"`
	BadPasswordsFile              string `help:"path to a file containing bad passwords for seller registration/password flows" default:""`
}

// CaptchaConfig contains seller captcha configuration for login and registration.
type CaptchaConfig struct {
	Login        MultiCaptchaConfig `help:"seller login captcha configuration" json:"login"`
	Registration MultiCaptchaConfig `help:"seller registration captcha configuration" json:"registration"`
}

// MultiCaptchaConfig contains configurations for reCAPTCHA and hCaptcha on seller routes.
type MultiCaptchaConfig struct {
	Recaptcha SingleCaptchaConfig `json:"recaptcha"`
	Hcaptcha  SingleCaptchaConfig `json:"hcaptcha"`
}

// SingleCaptchaConfig contains configuration for a single captcha provider on seller routes.
type SingleCaptchaConfig struct {
	Enabled   bool   `help:"whether captcha is enabled for this seller route" default:"false" json:"enabled"`
	SiteKey   string `help:"captcha site key exposed to seller frontend" json:"siteKey"`
	SecretKey string `help:"captcha secret key used for server-side verification" json:"-"`
}

// AuthSessionConfig contains seller session configuration.
type AuthSessionConfig struct {
	InactivityTimerEnabled  bool          `help:"whether seller sessions can time out due to inactivity" default:"true"`
	InactivityTimerDuration int           `help:"seller inactivity timer delay in seconds" default:"1800"`
	Duration                time.Duration `help:"duration a seller session is valid for when inactivity timer is disabled" default:"168h"`
}

// SellerFrontendConfig holds bootstrap configuration for the seller frontend.
type SellerFrontendConfig struct {
	ExternalAddress               string        `json:"externalAddress"`
	ApiBaseURL                    string        `json:"apiBaseURL"`
	SatelliteName                 string        `json:"satelliteName"`
	Captcha                       CaptchaConfig `json:"captcha"`
	CSRFProtectionEnabled         bool          `json:"csrfProtectionEnabled"`
	CSRFToken                     string        `json:"csrfToken"`
	SignupActivationCodeEnabled   bool          `json:"signupActivationCodeEnabled"`
	PasswordMinimumLength         int           `json:"passwordMinimumLength"`
	PasswordMaximumLength         int           `json:"passwordMaximumLength"`
	InactivityTimerEnabled        bool          `json:"inactivityTimerEnabled"`
	InactivityTimerDuration       int           `json:"inactivityTimerDuration"`
	EmailChangeFlowEnabled        bool          `json:"emailChangeFlowEnabled"`
	SelfServeAccountDeleteEnabled bool          `json:"selfServeAccountDeleteEnabled"`
	ActiveSessionsViewEnabled     bool          `json:"activeSessionsViewEnabled"`
	LiveCheckBadPasswords         bool          `json:"liveCheckBadPasswords"`
	GeneralRequestURL             string        `json:"generalRequestURL"`
	TermsAndConditionsURL         string        `json:"termsAndConditionsURL"`
	ContactInfoURL                string        `json:"contactInfoURL"`
}

// BuildFrontendConfig returns seller frontend bootstrap config.
func (s *Service) BuildFrontendConfig(csrfProtectionEnabled bool, csrfToken string) SellerFrontendConfig {
	externalAddress := s.externalAddress
	liveCheckBadPasswords := s.authConfig.LiveCheckBadPasswords && s.badPasswordsLoaded
	return SellerFrontendConfig{
		ExternalAddress:               externalAddress,
		ApiBaseURL:                    externalAddress,
		SatelliteName:                 s.runtimeConfig.SatelliteName,
		Captcha:                       s.authConfig.Captcha,
		CSRFProtectionEnabled:         csrfProtectionEnabled,
		CSRFToken:                     csrfToken,
		SignupActivationCodeEnabled:   s.authConfig.SignupActivationCodeEnabled,
		PasswordMinimumLength:         console.PasswordMinimumLength,
		PasswordMaximumLength:         console.PasswordMaximumLength,
		InactivityTimerEnabled:        s.authConfig.Session.InactivityTimerEnabled,
		InactivityTimerDuration:       s.authConfig.Session.InactivityTimerDuration,
		EmailChangeFlowEnabled:        s.authConfig.EmailChangeFlowEnabled,
		SelfServeAccountDeleteEnabled: s.authConfig.SelfServeAccountDeleteEnabled,
		ActiveSessionsViewEnabled:     s.authConfig.ActiveSessionsViewEnabled,
		LiveCheckBadPasswords:         liveCheckBadPasswords,
		GeneralRequestURL:             s.runtimeConfig.GeneralRequestURL,
		TermsAndConditionsURL:         s.runtimeConfig.TermsAndConditionsURL,
		ContactInfoURL:                s.runtimeConfig.ContactInfoURL,
	}
}

func (cfg *AuthConfig) applyDefaults() {
	if cfg.PasswordCost == 0 {
		cfg.PasswordCost = 10 // bcrypt.DefaultCost
	}
	if cfg.LoginAttemptsWithoutPenalty == 0 {
		cfg.LoginAttemptsWithoutPenalty = 3
	}
	if cfg.FailedLoginPenalty == 0 {
		cfg.FailedLoginPenalty = 2.0
	}
	if cfg.Session.Duration == 0 {
		cfg.Session.Duration = 168 * time.Hour
	}
}

func (s *Service) initCaptchaHandlers() {
	if s.authConfig.Captcha.Login.Recaptcha.Enabled {
		s.loginCaptchaHandler = console.NewDefaultCaptcha(console.Recaptcha, s.authConfig.Captcha.Login.Recaptcha.SecretKey)
	} else if s.authConfig.Captcha.Login.Hcaptcha.Enabled {
		s.loginCaptchaHandler = console.NewDefaultCaptcha(console.Hcaptcha, s.authConfig.Captcha.Login.Hcaptcha.SecretKey)
	}

	if s.authConfig.Captcha.Registration.Recaptcha.Enabled {
		s.registrationCaptchaHandler = console.NewDefaultCaptcha(console.Recaptcha, s.authConfig.Captcha.Registration.Recaptcha.SecretKey)
	} else if s.authConfig.Captcha.Registration.Hcaptcha.Enabled {
		s.registrationCaptchaHandler = console.NewDefaultCaptcha(console.Hcaptcha, s.authConfig.Captcha.Registration.Hcaptcha.SecretKey)
	}
}
