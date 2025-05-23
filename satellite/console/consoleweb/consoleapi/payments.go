// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/uuid"
	"storj.io/storj/private/post"
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/mailservice"
	"storj.io/storj/satellite/payments"
	"storj.io/storj/satellite/payments/billing"
	"storj.io/storj/satellite/payments/paymentsconfig"
	"storj.io/storj/satellite/payments/stripe"
)

var (
	// ErrPaymentsAPI - console payments api error type.
	ErrPaymentsAPI = errs.Class("consoleapi payments")
	mon            = monkit.Package()
)

// Payments is an api controller that exposes all payment related functionality.
type Payments struct {
	log                  *zap.Logger
	service              *console.Service
	accountFreezeService *console.AccountFreezeService
	packagePlans         paymentsconfig.PackagePlans
	stripe               *stripe.Service

	mailService *mailservice.Service

	gatewayConfig GatewayConfig
}

type GatewayConfig struct {
	APIKey                  string
	APISecret               string
	Pay_ReqUrl              string
	Pay_StatusUrl           string
	Pay_Success_RedirectUrl string
	Pay_Failed_RedirectUrl  string
}

func NewGatewayConfig(apiKey, apiSecret, payReqUrl, payStatusUrl, paySuccessRedirectUrl, payFailedRedirectUrl string) GatewayConfig {
	return GatewayConfig{
		APIKey:                  apiKey,
		APISecret:               apiSecret,
		Pay_ReqUrl:              payReqUrl,
		Pay_StatusUrl:           payStatusUrl,
		Pay_Success_RedirectUrl: paySuccessRedirectUrl,
		Pay_Failed_RedirectUrl:  payFailedRedirectUrl,
	}
}

type GeneratePaymentLinkRequest struct {
	CryptoMode string `json:"cryptoMode"`
	PlanID     int64  `json:"planId"`
	CouponCode string `json:"couponCode"`
}

type PaymentGatewayRequest struct {
	Nonce        string `json:"nonce"`
	RequestURL   string `json:"requestURL"`
	Email        string `json:"userEmail"`
	GBsize       string `json:"planGBsize"`
	Bandwidth    string `json:"planBandwidth"`
	Amount       string `json:"planPrice"`
	Currency     string `json:"cryptoMode"`
	SuccessURL   string `json:"successUrl"`
	Description  string `json:"description"`
	FailureURL   string `json:"failureUrl"`
	Network      string `json:"network"`
	FiatCurrency string `json:"fiatCurrency"`
}
type PaymentGatewayResponse struct {
	Message    string       `json:"message"`
	Status     bool         `json:"status"`
	StatusCode int          `json:"statusCode"`
	Data       ResponseData `json:"data"`
}
type ResponseData struct {
	RedirectURL string `json:"redirectUrl"`
	PaymentID   string `json:"paymentId"`
}

type PaymentStatusRequest struct {
	Nonce      string `json:"nonce"`
	RequestURL string `json:"requestURL"`
	PaymentId  string `json:"paymentId"`
}
type GetPaymentStatusResponse struct {
	Message    string                    `json:"message"`
	Status     bool                      `json:"status"`
	StatusCode int                       `json:"statusCode"`
	Data       PaymentStatusResponseData `json:"data"`
}
type PaymentStatusResponseData struct {
	PaymentID       string    `json:"id"`
	Amount          string    `json:"amount"`
	Currency        string    `json:"currency"`
	FiatCurrency    string    `json:"fiatCurrency"`
	Network         string    `json:"network"`
	NetworkAmount   string    `json:"networkAmount"`
	Status          string    `json:"status"`
	TransactionHash string    `json:"tx"`
	CreatedAt       string    `json:"createdAt"`
	User            UserEmail `json:"user"`
}
type UserEmail struct {
	Email string `json:"email"`
}

type PaymentGatewayErrResponse struct {
	Error      string `json:"error"`
	Status     bool   `json:"status"`
	StatusCode int    `json:"statusCode"`
}
type PaymentErrResponse struct {
	Error      string `json:"error"`
	Status     bool   `json:"status"`
	StatusCode int    `json:"statusCode"`
}
type RequestUser struct {
	Email string `json:"userEmail"`
}

/*********** boris define end ***************/

// NewPayments is a constructor for api payments controller.
func NewPayments(log *zap.Logger, service *console.Service, accountFreezeService *console.AccountFreezeService,
	packagePlans paymentsconfig.PackagePlans, stripe *stripe.Service, config GatewayConfig, mailService *mailservice.Service) *Payments {
	return &Payments{
		log:                  log,
		service:              service,
		accountFreezeService: accountFreezeService,
		packagePlans:         packagePlans,
		stripe:               stripe,
		gatewayConfig:        config,
		mailService:          mailService,
	}
}

// SetupAccount creates a payment account for the user.
func (p *Payments) SetupAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	couponType, err := p.service.Payments().SetupAccount(ctx)

	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(couponType)
	if err != nil {
		p.log.Error("failed to write json token deposit response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// AccountBalance returns an integer amount in cents that represents the current balance of payment account.
func (p *Payments) AccountBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	balance, err := p.service.Payments().AccountBalance(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(&balance)
	if err != nil {
		p.log.Error("failed to write json balance response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// ProjectsCharges returns how much money current user will be charged for each project which he owns.
func (p *Payments) ProjectsCharges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	var response struct {
		PriceModels map[string]payments.ProjectUsagePriceModel `json:"priceModels"`
		Charges     payments.ProjectChargesResponse            `json:"charges"`
	}

	w.Header().Set("Content-Type", "application/json")

	sinceStamp, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}
	beforeStamp, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	since := time.Unix(sinceStamp, 0).UTC()
	before := time.Unix(beforeStamp, 0).UTC()

	charges, err := p.service.Payments().ProjectsCharges(ctx, since, before)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	response.Charges = charges
	response.PriceModels = make(map[string]payments.ProjectUsagePriceModel)

	seen := make(map[string]struct{})
	for _, partnerCharges := range charges {
		for partner := range partnerCharges {
			if _, ok := seen[partner]; ok {
				continue
			}
			response.PriceModels[partner] = *p.service.Payments().GetProjectUsagePriceModel(partner)
			seen[partner] = struct{}{}
		}
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		p.log.Error("failed to write json project usage and charges response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// triggerAttemptPayment attempts payment and unfreezes/unwarn user if needed.
func (p *Payments) triggerAttemptPayment(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	userID, err := p.service.GetUserID(ctx)
	if err != nil {
		return err
	}

	freezes, err := p.accountFreezeService.GetAll(ctx, userID)
	if err != nil {
		return err
	}

	if freezes.ViolationFreeze != nil {
		return nil
	}

	if freezes.BillingFreeze == nil && freezes.BillingWarning == nil {
		return nil
	}

	err = p.service.Payments().AttemptPayOverdueInvoices(ctx)
	if err != nil {
		return err
	}

	if freezes.BillingFreeze != nil {
		err = p.accountFreezeService.BillingUnfreezeUser(ctx, userID)
		if err != nil {
			return err
		}
	} else if freezes.BillingWarning != nil {
		err = p.accountFreezeService.BillingUnWarnUser(ctx, userID)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddCreditCard is used to save new credit card and attach it to payment account.
func (p *Payments) AddCreditCard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	token := string(bodyBytes)

	_, err = p.service.Payments().AddCreditCard(ctx, token)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			web.ServeCustomJSONError(ctx, p.log, w, http.StatusUnauthorized, err, errs.Unwrap(err).Error())
			return
		}

		if stripe.ErrDuplicateCard.Has(err) {
			web.ServeCustomJSONError(ctx, p.log, w, http.StatusBadRequest, err, errs.Unwrap(err).Error())
			return
		}

		web.ServeCustomJSONError(ctx, p.log, w, http.StatusInternalServerError, err, errs.Unwrap(err).Error())
		return
	}

	err = p.triggerAttemptPayment(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

// AddCardByPaymentMethodID is used to save new credit card and attach it to payment account.
// It uses payment method id instead of token.
func (p *Payments) AddCardByPaymentMethodID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	pmID := string(bodyBytes)

	_, err = p.service.Payments().AddCardByPaymentMethodID(ctx, pmID)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			web.ServeCustomJSONError(ctx, p.log, w, http.StatusUnauthorized, err, errs.Unwrap(err).Error())
			return
		}

		if stripe.ErrDuplicateCard.Has(err) {
			web.ServeCustomJSONError(ctx, p.log, w, http.StatusBadRequest, err, errs.Unwrap(err).Error())
			return
		}

		web.ServeCustomJSONError(ctx, p.log, w, http.StatusInternalServerError, err, errs.Unwrap(err).Error())
		return
	}

	err = p.triggerAttemptPayment(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

// ListCreditCards returns a list of credit cards for a given payment account.
func (p *Payments) ListCreditCards(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	cards, err := p.service.Payments().ListCreditCards(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if cards == nil {
		_, err = w.Write([]byte("[]"))
	} else {
		err = json.NewEncoder(w).Encode(cards)
	}

	if err != nil {
		p.log.Error("failed to write json list cards response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// MakeCreditCardDefault makes a credit card default payment method.
func (p *Payments) MakeCreditCardDefault(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	cardID, err := io.ReadAll(r.Body)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	err = p.service.Payments().MakeCreditCardDefault(ctx, string(cardID))
	if err != nil {
		if stripe.ErrCardNotFound.Has(err) {
			p.serveJSONError(ctx, w, http.StatusNotFound, err)
			return
		}

		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = p.triggerAttemptPayment(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

// RemoveCreditCard is used to detach a credit card from payment account.
func (p *Payments) RemoveCreditCard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	cardID := vars["cardId"]

	if cardID == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	err = p.service.Payments().RemoveCreditCard(ctx, cardID)
	if err != nil {
		if stripe.ErrCardNotFound.Has(err) {
			p.serveJSONError(ctx, w, http.StatusNotFound, err)
			return
		}
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = p.triggerAttemptPayment(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

// BillingHistory returns a list of invoices, transactions and all others billing history items for payment account.
func (p *Payments) BillingHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	billingHistory, err := p.service.Payments().BillingHistory(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if billingHistory == nil {
		_, err = w.Write([]byte("[]"))
	} else {
		err = json.NewEncoder(w).Encode(billingHistory)
	}

	if err != nil {
		p.log.Error("failed to write json billing history response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// InvoiceHistory returns a paged list of invoice history items for payment account.
func (p *Payments) InvoiceHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query()

	limitParam := query.Get("limit")
	if limitParam == "" {
		p.serveJSONError(ctx, w, http.StatusBadRequest, errs.New("parameter 'limit' is required"))
		return
	}

	limit, pErr := strconv.ParseUint(limitParam, 10, 32)
	if pErr != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	startParam := query.Get("starting_after")
	endParam := query.Get("ending_before")

	history, err := p.service.Payments().InvoiceHistory(ctx, payments.InvoiceCursor{
		Limit:         int(limit),
		StartingAfter: startParam,
		EndingBefore:  endParam,
	})
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	err = json.NewEncoder(w).Encode(history)
	if err != nil {
		p.log.Error("failed to write json history response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// ApplyCouponCode applies a coupon code to the user's account.
func (p *Payments) ApplyCouponCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
	couponCode := string(bodyBytes)

	coupon, err := p.service.Payments().ApplyCouponCode(ctx, couponCode)
	if err != nil {
		status := http.StatusInternalServerError
		if payments.ErrInvalidCoupon.Has(err) {
			status = http.StatusBadRequest
		} else if payments.ErrCouponConflict.Has(err) {
			status = http.StatusConflict
		}
		p.serveJSONError(ctx, w, status, err)
		return
	}

	if err = json.NewEncoder(w).Encode(coupon); err != nil {
		p.log.Error("failed to encode coupon", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// GetCoupon returns the coupon applied to the user's account.
func (p *Payments) GetCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	coupon, err := p.service.Payments().GetCoupon(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if err = json.NewEncoder(w).Encode(coupon); err != nil {
		p.log.Error("failed to encode coupon", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// GetWallet returns the wallet address (with balance) already assigned to the user.
func (p *Payments) GetWallet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	walletInfo, err := p.service.Payments().GetWallet(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		if errs.Is(err, billing.ErrNoWallet) {
			p.serveJSONError(ctx, w, http.StatusNotFound, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if err = json.NewEncoder(w).Encode(walletInfo); err != nil {
		p.log.Error("failed to encode wallet info", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// ClaimWallet will claim a new wallet address. Returns with existing if it's already claimed.
func (p *Payments) ClaimWallet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	walletInfo, err := p.service.Payments().ClaimWallet(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if err = json.NewEncoder(w).Encode(walletInfo); err != nil {
		p.log.Error("failed to encode wallet info", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// WalletPayments returns with the list of storjscan transactions for user`s wallet.
func (p *Payments) WalletPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	var walletPayments console.WalletPayments
	walletPayments, err = p.service.Payments().WalletPayments(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		if errs.Is(err, billing.ErrNoWallet) {
			if err = json.NewEncoder(w).Encode(walletPayments); err != nil {
				p.log.Error("failed to encode payments", zap.Error(ErrPaymentsAPI.Wrap(err)))
			}
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if err = json.NewEncoder(w).Encode(walletPayments); err != nil {
		p.log.Error("failed to encode payments", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// WalletPaymentsWithConfirmations returns with the list of storjscan transactions (including confirmations count) for user`s wallet.
func (p *Payments) WalletPaymentsWithConfirmations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	walletPayments, err := p.service.Payments().WalletPaymentsWithConfirmations(ctx)
	if err != nil {
		if console.ErrUnauthorized.Has(err) {
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		if errs.Is(err, billing.ErrNoWallet) {
			if err = json.NewEncoder(w).Encode([]string{}); err != nil {
				p.log.Error("failed to encode payments", zap.Error(ErrPaymentsAPI.Wrap(err)))
			}
			return
		}

		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if err = json.NewEncoder(w).Encode(walletPayments); err != nil {
		p.log.Error("failed to encode wallet payments with confirmations", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// GetProjectUsagePriceModel returns the project usage price model for the user.
func (p *Payments) GetProjectUsagePriceModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	user, err := console.GetUser(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	pricing := p.service.Payments().GetProjectUsagePriceModel(string(user.UserAgent))

	if err = json.NewEncoder(w).Encode(pricing); err != nil {
		p.log.Error("failed to encode project usage price model", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// PurchasePackage purchases one of the configured paymentsconfig.PackagePlans.
func (p *Payments) PurchasePackage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// whether to use payment method id instead of token for adding card.
	usePmID := r.URL.Query().Get("pmID") == "true"

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusBadRequest, err)
		return
	}

	token := string(bodyBytes)

	u, err := console.GetUser(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	pkg, err := p.packagePlans.Get(u.UserAgent)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusNotFound, err)
		return
	}

	var addCardFunc func(context.Context, string) (payments.CreditCard, error)
	if usePmID {
		addCardFunc = p.service.Payments().AddCardByPaymentMethodID
	} else {
		addCardFunc = p.service.Payments().AddCreditCard
	}

	card, err := addCardFunc(ctx, token)
	if err != nil {
		switch {
		case console.ErrUnauthorized.Has(err):
			p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		default:
			p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		}
		return
	}

	description := fmt.Sprintf("%s package plan", string(u.UserAgent))
	err = p.service.Payments().UpdatePackage(ctx, description, time.Now())
	if err != nil {
		if !console.ErrAlreadyHasPackage.Has(err) {
			p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
			return
		}
	}

	err = p.service.Payments().Purchase(ctx, pkg.Price, description, card.ID)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}

	if err = p.service.Payments().ApplyCredit(ctx, pkg.Credit, description); err != nil {
		p.serveJSONError(ctx, w, http.StatusInternalServerError, err)
		return
	}
}

// PackageAvailable returns whether a package plan is configured for the user's partner.
func (p *Payments) PackageAvailable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	u, err := console.GetUser(ctx)
	if err != nil {
		p.serveJSONError(ctx, w, http.StatusUnauthorized, err)
		return
	}

	pkg, err := p.packagePlans.Get(u.UserAgent)
	hasPkg := err == nil && pkg != payments.PackagePlan{}

	if err = json.NewEncoder(w).Encode(hasPkg); err != nil {
		p.log.Error("failed to encode package plan checking response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// serveJSONError writes JSON error to response output stream.
func (p *Payments) serveJSONError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	web.ServeJSONError(ctx, p.log, w, status, err)
}

func (p *Payments) GetCoupons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	coupons, err := p.service.GetActiveCoupons(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, fmt.Sprintf("No coupons found"), http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to get coupons: %v", err), http.StatusInternalServerError)
		return
	}

	if err = json.NewEncoder(w).Encode(coupons); err != nil {
		p.log.Error("failed to encode coupons", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}

// boris
func (p *Payments) GeneratePaymentLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := p.service.GetUserAndAuditLog(ctx, "generate payment link")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get user: %v", err), http.StatusInternalServerError)
		return
	}

	// Decode the JSON payload from the request body
	var generatePaymentLinkRequest GeneratePaymentLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&generatePaymentLinkRequest); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	if generatePaymentLinkRequest.PlanID == 0 {
		http.Error(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	plan, err := p.service.GetPaymentPlansByID(ctx, generatePaymentLinkRequest.PlanID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get payment plan: %v", err), http.StatusInternalServerError)
		return
	}

	if generatePaymentLinkRequest.CouponCode != "" {
		coupon, err := p.service.GetCouponByCode(ctx, generatePaymentLinkRequest.CouponCode)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get coupon: %v", err), http.StatusInternalServerError)
			return
		}

		if coupon.ValidFrom.After(time.Now().UTC()) || coupon.ValidTo.Before(time.Now().UTC()) {
			http.Error(w, fmt.Sprintf("Coupon is not valid"), http.StatusBadRequest)
			return
		}

		if coupon.MinOrderAmount <= plan.Price {
			discountAmount := float64(0)
			if coupon.DiscountType == "percentage" {
				discountAmount = plan.Price * (coupon.Discount / 100)
			} else if coupon.DiscountType == "fixed" {
				discountAmount = coupon.Discount
			}

			if discountAmount > coupon.MaxDiscount {
				discountAmount = coupon.MaxDiscount
			}

			plan.Price = plan.Price - discountAmount

			if plan.Price < 0 {
				plan.Price = 0
			}
		}

	}

	var network string
	// Select the network based on the currency
	switch generatePaymentLinkRequest.CryptoMode {
	case "USDT":
		network = "Ethereum"
	case "XDC", "SRX":
		network = "Xinfin"
	}

	timestamp := strconv.FormatInt(time.Now().UnixNano()/1000000, 10)

	requestData := map[string]interface{}{
		"nonce":        timestamp,
		"requestURL":   "/api/payment",
		"email":        user.Email,
		"amount":       fmt.Sprintf("%0.2f", plan.Price),
		"currency":     generatePaymentLinkRequest.CryptoMode,
		"successUrl":   p.gatewayConfig.Pay_Success_RedirectUrl,
		"description":  "payment is for the new transfer",
		"failureUrl":   p.gatewayConfig.Pay_Failed_RedirectUrl,
		"network":      network,
		"fiatCurrency": "usd",
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal request data: %v", err), http.StatusInternalServerError)
		return
	}

	stringPayload := base64.StdEncoding.EncodeToString(requestBody)

	secretKey := []byte(p.gatewayConfig.APISecret)
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(stringPayload)) // Use the base64 encoded string
	signature := fmt.Sprintf("%x", h.Sum(nil))

	headers := map[string]string{
		"Content-Type":  "application/json",
		"wlc-apikey":    p.gatewayConfig.APIKey,
		"wlc-signature": signature,
		"wlc-payload":   stringPayload,
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", p.gatewayConfig.Pay_ReqUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response body: %v", err), http.StatusInternalServerError)
		return
	}

	// Decode the JSON response
	var upgradingResponse PaymentGatewayResponse

	if err := json.Unmarshal(respBody, &upgradingResponse); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode response body: %v", err), http.StatusInternalServerError)
		return
	}

	// Handle the response from the Payment gateway
	if upgradingResponse.Status {
		fmt.Printf("Received successful response:\nMessage: %s\nStatus: %t\nStatusCode: %d\nData: %+v\n",
			upgradingResponse.Message, upgradingResponse.Status, upgradingResponse.StatusCode, upgradingResponse.Data)
		fmt.Printf("Redirect URL: %s\nPayment ID: %s\n", upgradingResponse.Data.RedirectURL, upgradingResponse.Data.PaymentID)

		// Send the RedirectURL to the frontend
		responseToFrontend := map[string]interface{}{
			"redirectURL": upgradingResponse.Data.RedirectURL,
		}

		jsonResponse, err := json.Marshal(responseToFrontend)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to marshal response data: %v", err), http.StatusInternalServerError)
			return
		}
		// Set appropriate headers
		w.Header().Set("Content-Type", "application/json")

		// Send the response to the frontend
		_, err = w.Write(jsonResponse)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to send response: %v", err), http.StatusInternalServerError)
			return
		}

		// Periodically check the payment status
		go func(paymentID string, plan *billing.PaymentPlans, user *console.User) {

			for i := 0; i < 20; i++ {
				time.Sleep(30 * time.Second)
				paymentStatus := p.getPaymentdetail(paymentID)
				// if paymentStatus == "COMPLETED" {
				if paymentStatus == "COMPLETED" {
					newCtx := context.Background()
					p.updateLimits(newCtx, user.ID, plan.Storage, plan.Bandwidth)

					gbSize := fmt.Sprintf("%0.2f GB", float64(plan.Storage)/float64(memory.GB))
					bandwidth := fmt.Sprintf("%0.2f GB", float64(plan.Bandwidth)/float64(memory.GB))

					p.mailService.SendRenderedAsync(
						newCtx,
						[]post.Address{{Address: user.Email}},
						&console.UpgradeSuccessfullEmail{
							UserName:  user.ShortName,
							Signature: "Storx Team",
							GBsize:    gbSize,
							Bandwidth: bandwidth,
						},
					)
					p.stripe.CreateTokenPaymentBillingTransaction(newCtx, user, "planPrice")
					return
				}
			}
		}(upgradingResponse.Data.PaymentID, plan, user)

		// p.updateLimits(ctx, userEmail, upgradingRequest.GBsize, upgradingRequest.Bandwidth)
		// sendEmail(userEmail, sendBody)
		// p.stripe.CreateTokenPaymentBillingTransaction(ctx, user, planPrice)
	} else {
		http.Error(w, fmt.Sprintf("link generation failed from payment gateway: %v", string(respBody)), http.StatusInternalServerError)
	}
}

func (p *Payments) getPaymentdetail(paidPaymentID string) (paymentStatus string) {
	PaymentGateway_Pay_StatusUrl := p.gatewayConfig.Pay_StatusUrl
	// Decode the JSON payload from the request body
	var paymentStatusRequest PaymentStatusRequest

	timestamp := strconv.FormatInt(time.Now().UnixNano()/1000000, 10)
	paymentStatusRequest.Nonce = timestamp
	paymentStatusRequest.RequestURL = "/api/payment-status"
	paymentStatusRequest.PaymentId = paidPaymentID

	fmt.Printf("*********************** paymentStatusRequest: Nonce: %s, RequestURL: %s, PaymentId: %s\n",
		paymentStatusRequest.Nonce, paymentStatusRequest.RequestURL, paymentStatusRequest.PaymentId)

	requestData := map[string]interface{}{
		"nonce":      paymentStatusRequest.Nonce,
		"requestURL": paymentStatusRequest.RequestURL,
		"paymentId":  paymentStatusRequest.PaymentId,
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("requestBody Marshal Error: ", err)
		return
	}

	stringPayload := base64.StdEncoding.EncodeToString(requestBody)

	secretKey := []byte(p.gatewayConfig.APISecret)
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(stringPayload)) // Use the base64 encoded string
	signature := fmt.Sprintf("%x", h.Sum(nil))

	headers := map[string]string{
		"Content-Type":  "application/json",
		"wlc-apikey":    p.gatewayConfig.APIKey,
		"wlc-signature": signature,
		"wlc-payload":   stringPayload,
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", PaymentGateway_Pay_StatusUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("****************Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("****************Error reading response body:", err)
		return
	}
	fmt.Println("**************************PaymentStatus_Response:", string(respBody))

	// Decode the JSON response
	var getPaymentStatusResponse GetPaymentStatusResponse
	var paymentErrResponse PaymentErrResponse
	if err = json.Unmarshal(respBody, &getPaymentStatusResponse); err != nil {
		fmt.Println("****************Failed to decode response body:", err)
		return
	}

	// Handle the response from the Payment gateway
	if getPaymentStatusResponse.Status {
		fmt.Printf("Received successful getPaymentStatusResponse:\nMessage: %s\nStatus: %t\nStatusCode: %d\nData: %+v\n",
			getPaymentStatusResponse.Message, getPaymentStatusResponse.Status, getPaymentStatusResponse.StatusCode, getPaymentStatusResponse.Data)
		fmt.Printf("*******PaymentStatus: %s\n*******Payment ID: %s\n", getPaymentStatusResponse.Data.Status, getPaymentStatusResponse.Data.PaymentID)

		if getPaymentStatusResponse.Data.Status == "COMPLETED" {
			paymentStatus = "COMPLETED"
		} else if getPaymentStatusResponse.Data.Status == "PENDING" {
			paymentStatus = "PENDING"
		} else if getPaymentStatusResponse.Data.Status == "EXPIRED" {
			paymentStatus = "EXPIRED"
		}
	} else {
		fmt.Printf("******Received error response:\nError: %s\nStatus: %t\nStatusCode: %d\n",
			paymentErrResponse.Error, paymentErrResponse.Status, paymentErrResponse.StatusCode)
		return
	}
	return paymentStatus
}

// updateLimits updates user limits and all project limits for that user (future and existing).
func (p *Payments) updateLimits(ctx context.Context, userID uuid.UUID, storage, bandwidth int64) {

	newLimits := console.UsageLimits{
		Storage:   storage,
		Bandwidth: bandwidth,
	}

	if storage > 0 {
		newLimits.Storage = storage
	}
	if bandwidth > 0 {
		newLimits.Bandwidth = bandwidth
	}

	err := p.service.GetUsers().UpdateUserProjectLimits(ctx, userID, newLimits)
	if err != nil {
		fmt.Println("********************************** failed to update user limits", err)
		return
	}

	userProjects, err := p.service.GetProjects().GetOwn(ctx, userID)
	if err != nil {
		fmt.Println("********************************** failed to get user projects: ", err)
		return
	}

	// free->paid Update function->DB
	err = p.service.GetUsers().UpdatePaidTiers(ctx, userID, true)
	if err != nil {
		fmt.Println("********************************** failed to update user Paid tier: ", err)
		return
	}

	for _, project := range userProjects {
		updateProjectInfo := console.UpsertProjectInfo{
			Name:                    project.Name,
			Description:             project.Description,
			StorageLimit:            *project.StorageLimit,
			BandwidthLimit:          *project.BandwidthLimit,
			CreatedAt:               project.CreatedAt,
			PrevDaysUntilExpiration: project.PrevDaysUntilExpiration,
		}

		updateProjectInfo.StorageLimit = memory.Size(storage)
		updateProjectInfo.BandwidthLimit = memory.Size(bandwidth)
		updateProjectInfo.CreatedAt = time.Now().UTC()
		updateProjectInfo.PrevDaysUntilExpiration = int(0)

		_, err = p.service.UpdatingProjects(ctx, userID, project.ID, updateProjectInfo)
		if err != nil {
			fmt.Println("********************************** failed to update p.service.UpdateProjects : ", err)
		}
	}
}

// MonitorUserProjects function
func (p *Payments) MonitorUserProjects(ctx context.Context) error {

	now := time.Now()
	users, err := p.GetAllUsers(ctx)
	if err != nil {
		return err
	}

	//all users from the database
	for _, user := range users {
		userProjects, err := p.service.GetProjects().GetOwn(ctx, user.ID)
		if err != nil {
			return err
		}

		for _, project := range userProjects {

			if project.StorageLimit.GB() > 2 {
				daysUntilExpiration_Temp := now.Sub(project.CreatedAt).Hours() / 24
				daysUntilExpiration := int(daysUntilExpiration_Temp)

				if daysUntilExpiration >= 23 && daysUntilExpiration < 30 {
					if daysUntilExpiration > project.PrevDaysUntilExpiration {

						updateProjectInfo := console.UpsertProjectInfo{
							Name:                    project.Name,
							Description:             project.Description,
							StorageLimit:            *project.StorageLimit,
							BandwidthLimit:          *project.BandwidthLimit,
							CreatedAt:               project.CreatedAt,
							PrevDaysUntilExpiration: project.PrevDaysUntilExpiration,
						}
						updateProjectInfo.PrevDaysUntilExpiration = daysUntilExpiration
						_, err = p.service.UpdatingProjects(ctx, user.ID, project.ID, updateProjectInfo)
						if err != nil {
							fmt.Println("failed to update project:", err)
							continue
						}
						// Send warning email
						expirationDate := project.CreatedAt.AddDate(0, 0, 30)
						p.mailService.SendRenderedAsync(ctx, []post.Address{{Address: user.Email}},
							&console.UpgradeExpiringEmail{
								UserName:  user.ShortName,
								Signature: "Storx Team",
								ExpireOn:  expirationDate.Format("2006-01-02"),
							})
					}
				}
				if daysUntilExpiration >= 30 && project.PrevDaysUntilExpiration < 30 {
					p.mailService.SendRenderedAsync(ctx, []post.Address{{Address: user.Email}}, &console.UpgradeExpiredEmail{
						Signature: "Storx Team",
						UserName:  user.ShortName,
					})

					p.updateLimits(ctx, user.ID, 2*int64(memory.GB), 2*int64(memory.GB))
					err = p.service.GetUsers().UpdatePaidTiers(ctx, user.ID, false)
					if err != nil {
						fmt.Println("failed to update user Paid tier:", err)
						return err
					}
				}
			}
		}

	}
	return nil
}

// getAllUsers retrieves all users from the database.
func (p *Payments) GetAllUsers(ctx context.Context) ([]console.User, error) {
	usersFromDB, err := p.service.GetUsers().GetAllUsers(ctx)

	if err != nil {
		return nil, err
	}

	var users []console.User
	for _, u := range usersFromDB {
		users = append(users, *u)
	}

	return users, nil
}

// StartMonitoringUserProjects starts monitoring user projects as a goroutine.
func (p *Payments) StartMonitoringUserProjects(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				err := p.MonitorUserProjects(ctx)
				if err != nil {
					p.log.Error("Error occurred while monitoring user projects", zap.Error(err))
				}
				// time.Sleep(1 * time.Minute)
				time.Sleep(24 * time.Hour)
			}
		}
	}()
}

func (p *Payments) HandlePaymentPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	plans, err := p.service.GetPaymentPlans(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get payment plans: %v", err), http.StatusInternalServerError)
		return
	}

	planMap := make(map[string][]interface{})
	for _, plan := range plans {
		planMap[plan.Group] = append(planMap[plan.Group], plan)
	}

	output := map[string]interface{}{
		"crypto_modes": []string{"SRX", "XDC", "USDT"},
	}

	group := []map[string]interface{}{}

	for name, plans := range planMap {
		group = append(group, map[string]interface{}{
			"name":  name,
			"plans": plans,
		})
	}

	output["group"] = group

	json.NewEncoder(w).Encode(output)
}

// payment history request and response
func (p *Payments) BillingTransactionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	query := r.URL.Query()
	limitStr := query.Get("limit")
	startingAfterStr := query.Get("starting_after")
	endingBeforeStr := query.Get("ending_before")
	var limit int
	var startingAfter int64
	var endingBefore int64

	// Convert string parameters to appropriate types

	if limitStr != "" {
		limit, _ = strconv.Atoi(limitStr)
	}

	if startingAfterStr != "" {
		startingAfter, _ = strconv.ParseInt(startingAfterStr, 10, 64)
	}

	if endingBeforeStr != "" {
		endingBefore, _ = strconv.ParseInt(endingBeforeStr, 10, 64)
	}

	user, err := p.service.GetUserAndAuditLog(ctx, "get billing history")
	if err != nil {
		fmt.Println("GetUserAndAuditLog err: ", err)
		return
	}

	billingHistory, err := p.stripe.GetBillingHistory(ctx, user.ID)
	if err != nil {
		fmt.Println("billingHistory err: ", err)
		return
	}

	if billingHistory == nil {
		_, err = w.Write([]byte("[]"))
	} else {
		if limit >= len(billingHistory) {
			err = json.NewEncoder(w).Encode(billingHistory)
		} else {
			if startingAfter > 0 {
				index := -1
				for i, item := range billingHistory {
					if item.ID == startingAfter {
						index = i
						break
					}
				}
				if index == -1 || index == len(billingHistory)-1 {
					_, err = w.Write([]byte("[]"))
				} else {
					endIndex := index + limit + 1
					if endIndex >= len(billingHistory) {
						endIndex = len(billingHistory)
					}
					err = json.NewEncoder(w).Encode(billingHistory[index+1 : endIndex])
				}
			} else if endingBefore > 0 {
				index := -1
				for i, item := range billingHistory {
					if item.ID == endingBefore {
						index = i
						break
					}
				}

				if index == -1 || index == 0 {
					err = json.NewEncoder(w).Encode(billingHistory[:limit])
				} else {
					startIndex := index - limit
					if startIndex < 0 {
						startIndex = 0
					}
					err = json.NewEncoder(w).Encode(billingHistory[startIndex:index])
				}
			} else {
				err = json.NewEncoder(w).Encode(billingHistory[:limit])
			}
		}
	}

	if err != nil {
		p.log.Error("failed to write json billing history response", zap.Error(ErrPaymentsAPI.Wrap(err)))
	}
}
