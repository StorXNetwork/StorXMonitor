// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"strings"

	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
)

// ResellerMailSettings is SMTP configuration stored in reseller_configs.config JSON under "mail".
// CyberLS / main console keeps using satellite mail.* config; reseller domains use this when complete.
// Auth is always LOGIN (username + password / app password).
type ResellerMailSettings struct {
	From              string `json:"from"`
	SMTPServerAddress string `json:"smtpServerAddress"`
	AuthType          string `json:"authType"`
	Login             string `json:"login"`
	Password          string `json:"password,omitempty"`
}

// ResellerMailSettingsView is returned to the seller UI (password never echoed).
type ResellerMailSettingsView struct {
	From              string `json:"from"`
	SMTPServerAddress string `json:"smtpServerAddress"`
	AuthType          string `json:"authType"`
	Login             string `json:"login"`
	PasswordSet       bool   `json:"passwordSet"`
	Configured        bool   `json:"configured"`
}

// UpdateResellerMailSettingsRequest is the body for PUT /seller/mail-settings
// and optional SMTP overrides on check-host / test.
type UpdateResellerMailSettingsRequest struct {
	From              string `json:"from"`
	SMTPServerAddress string `json:"smtpServerAddress"`
	AuthType          string `json:"authType"`
	Login             string `json:"login"`
	Password          string `json:"password"`
}

func (m *ResellerMailSettings) toView() ResellerMailSettingsView {
	if m == nil {
		return ResellerMailSettingsView{AuthType: "login"}
	}
	authType := strings.TrimSpace(m.AuthType)
	if authType == "" {
		authType = "login"
	}
	view := ResellerMailSettingsView{
		From:              m.From,
		SMTPServerAddress: m.SMTPServerAddress,
		AuthType:          authType,
		Login:             m.Login,
		PasswordSet:       strings.TrimSpace(m.Password) != "",
	}
	_, view.Configured = m.toMailConfig()
	return view
}

// ToMailConfig maps seller SMTP settings to mailservice.Config when complete.
func (m *ResellerMailSettings) ToMailConfig() (mailservice.Config, bool) {
	return m.toMailConfig()
}

func (m *ResellerMailSettings) toMailConfig() (mailservice.Config, bool) {
	if m == nil {
		return mailservice.Config{}, false
	}
	authType := strings.TrimSpace(m.AuthType)
	if authType == "" {
		authType = "login"
	}
	cfg := mailservice.Config{
		SMTPServerAddress: strings.TrimSpace(m.SMTPServerAddress),
		From:              strings.TrimSpace(m.From),
		AuthType:          authType,
		Login:             strings.TrimSpace(m.Login),
		Password:          m.Password,
	}
	if cfg.From == "" || cfg.SMTPServerAddress == "" || cfg.Login == "" || cfg.Password == "" {
		return mailservice.Config{}, false
	}
	if cfg.AuthType != "login" {
		return mailservice.Config{}, false
	}
	return cfg, true
}

func validateResellerMailSettings(req UpdateResellerMailSettingsRequest, existing *ResellerMailSettings) (*ResellerMailSettings, error) {
	authType := strings.ToLower(strings.TrimSpace(req.AuthType))
	if authType == "" {
		authType = "login"
	}
	if authType != "login" {
		return nil, ErrValidation.New("authType must be login")
	}

	out := &ResellerMailSettings{
		From:              strings.TrimSpace(req.From),
		SMTPServerAddress: strings.TrimSpace(req.SMTPServerAddress),
		AuthType:          authType,
		Login:             strings.TrimSpace(req.Login),
	}

	password := req.Password
	if strings.TrimSpace(password) == "" && existing != nil {
		password = existing.Password
	}
	out.Password = password

	if out.From == "" {
		return nil, ErrValidation.New("from is required")
	}
	if _, err := mail.ParseAddress(out.From); err != nil {
		return nil, ErrValidation.New("from must be a valid email address (e.g. Name <noreply@domain.com> or noreply@domain.com)")
	}
	if out.SMTPServerAddress == "" {
		return nil, ErrValidation.New("smtpServerAddress is required")
	}
	if _, _, err := net.SplitHostPort(out.SMTPServerAddress); err != nil {
		return nil, ErrValidation.New("smtpServerAddress must be host:port")
	}
	if out.Login == "" {
		return nil, ErrValidation.New("login is required")
	}
	if strings.TrimSpace(out.Password) == "" {
		return nil, ErrValidation.New("password is required")
	}

	mailCfg, ok := out.toMailConfig()
	if !ok {
		return nil, ErrValidation.New("incomplete SMTP settings")
	}
	if _, err := mailservice.CreateSender(mailCfg); err != nil {
		return nil, ErrValidation.New("invalid SMTP settings: %v", err)
	}

	return out, nil
}

// GetMailSettings returns SMTP settings for the authenticated reseller (password masked).
//
// @Summary      Get reseller mail SMTP settings
// @Description  **Route:** `GET /api/v0/seller/mail-settings`. Returns seller-configured SMTP used for emails on that reseller's custom domain. Auth is login only. CyberLS/main console continues using satellite mail.* config. Password is never returned; passwordSet/configured indicate whether SMTP is stored and usable.
// @Tags         reseller-mail
// @Produce      json
// @Success      200  {object}  ResellerMailSettingsView
// @Failure      401  {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Router       /seller/mail-settings [get]
func (b *SellerBranding) GetMailSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	view, err := b.service.GetMailSettingsForCurrentReseller(ctx)
	if err != nil {
		serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// UpdateMailSettings saves SMTP settings for the authenticated reseller.
//
// @Summary      Update reseller mail SMTP settings
// @Description  **Route:** `PUT /api/v0/seller/mail-settings`. Body: from, smtpServerAddress, authType (login), login, password. Omit password to keep the existing one. When complete, emails on this reseller's domain use these credentials.
// @Tags         reseller-mail
// @Accept       json
// @Produce      json
// @Param        body  body  UpdateResellerMailSettingsRequest  true  "SMTP settings"
// @Success      200   {object}  ResellerMailSettingsView
// @Failure      400   {object}  SellerAuthErrorResponse
// @Failure      401   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/mail-settings [put]
func (b *SellerBranding) UpdateMailSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var req UpdateResellerMailSettingsRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	view, err := b.service.UpdateMailSettingsForCurrentReseller(ctx, req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case ErrValidation.Has(err):
			status = http.StatusBadRequest
		case ErrBrandingNotFound.Has(err):
			status = http.StatusNotFound
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// TestMailSMTPRequest is the body for SMTP check-host / test-mail.
// Omit fields to reuse saved seller mail settings; omit password to keep the stored password.
type TestMailSMTPRequest struct {
	UpdateResellerMailSettingsRequest
	To string `json:"to"` // required for test-mail; defaults to reseller email when empty
}

// MailSMTPActionResponse is returned from check-host and test-mail.
type MailSMTPActionResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"SMTP host check succeeded"`
}

// CheckMailHost verifies SMTP dial + TLS + auth using the same sender path as production mail.
//
// @Summary      Check reseller SMTP host
// @Description  **Route:** `POST /api/v0/seller/mail-settings/check-host`. Body may include smtp fields (same as PUT) to test unsaved form values; omitted password reuses saved password. Does not send an email and does not persist settings.
// @Tags         reseller-mail
// @Accept       json
// @Produce      json
// @Param        body  body  TestMailSMTPRequest  false  "Optional SMTP overrides"
// @Success      200   {object}  MailSMTPActionResponse
// @Failure      400   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/mail-settings/check-host [post]
func (b *SellerBranding) CheckMailHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var req TestMailSMTPRequest
	dec := json.NewDecoder(r.Body)
	if err = dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	if err = b.service.CheckMailHostForCurrentReseller(ctx, req.UpdateResellerMailSettingsRequest); err != nil {
		status := http.StatusBadRequest
		if !ErrValidation.Has(err) {
			status = http.StatusBadGateway
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(MailSMTPActionResponse{
		Success: true,
		Message: "SMTP host check succeeded",
	})
}

// SendTestMail sends a real test email using the same CreateSender path as production mail,
// then persists the SMTP settings that were used.
//
// @Summary      Send reseller SMTP test email
// @Description  **Route:** `POST /api/v0/seller/mail-settings/test`. Body may include smtp fields plus optional `to` (defaults to reseller login email). On success, the SMTP settings are saved and used for reseller-domain mail.
// @Tags         reseller-mail
// @Accept       json
// @Produce      json
// @Param        body  body  TestMailSMTPRequest  false  "Optional SMTP overrides and recipient"
// @Success      200   {object}  MailSMTPActionResponse
// @Failure      400   {object}  SellerAuthErrorResponse
// @Security     SellerCookieAuth
// @Security     SellerCSRFAuth
// @Router       /seller/mail-settings/test [post]
func (b *SellerBranding) SendTestMail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var req TestMailSMTPRequest
	dec := json.NewDecoder(r.Body)
	if err = dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		serveJSONError(ctx, w, http.StatusBadRequest, ErrValidation.New("invalid request body"))
		return
	}

	to, err := b.service.SendTestMailForCurrentReseller(ctx, req)
	if err != nil {
		status := http.StatusBadRequest
		if !ErrValidation.Has(err) {
			status = http.StatusBadGateway
		}
		serveJSONError(ctx, w, status, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(MailSMTPActionResponse{
		Success: true,
		Message: "Test email sent to " + to,
	})
}
