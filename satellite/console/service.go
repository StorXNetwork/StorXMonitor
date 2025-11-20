// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/spf13/pflag"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
	"storj.io/common/cfgstruct"
	"storj.io/common/currency"
	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/http/requestid"
	"storj.io/common/macaroon"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/uuid"
	"storj.io/storj/private/api"
	"storj.io/storj/private/blockchain"
	"storj.io/storj/private/post"
	"storj.io/storj/satellite/accounting"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/buckets"
	"storj.io/storj/satellite/console/configs"
	"storj.io/storj/satellite/console/consoleauth"
	"storj.io/storj/satellite/console/pushnotifications"
	"storj.io/storj/satellite/emission"
	"storj.io/storj/satellite/mailservice"
	"storj.io/storj/satellite/nodeselection"
	"storj.io/storj/satellite/payments"
	"storj.io/storj/satellite/payments/billing"
	"storj.io/storj/satellite/satellitedb/dbx"
	"storj.io/storj/satellite/smartcontract"
)

var mon = monkit.Package()

const (
	// maxLimit specifies the limit for all paged queries.
	maxLimit = 300

	// TestPasswordCost is the hashing complexity to use for testing.
	TestPasswordCost = bcrypt.MinCost
)

// Error messages.
const (
	unauthorizedErrMsg                   = "You are not authorized to perform this action"
	emailUsedErrMsg                      = "This email is already in use, try another"
	emailNotFoundErrMsg                  = "There are no users with the specified email"
	passwordRecoveryTokenIsExpiredErrMsg = "Your password recovery link has expired, please request another one"
	credentialsErrMsg                    = "Your login credentials are incorrect, please try again"
	generateSessionTokenErrMsg           = "Failed to generate session token"
	failedToRetrieveUserErrMsg           = "Failed to retrieve user from database"
	apiKeyCredentialsErrMsg              = "Your API Key is incorrect"
	changePasswordErrMsg                 = "Your old password is incorrect, please try again"
	passwordTooShortErrMsg               = "Your password needs to be at least %d characters long"
	passwordTooLongErrMsg                = "Your password must be no longer than %d characters"
	projectOwnerDeletionForbiddenErrMsg  = "%s is a project owner and can not be deleted"
	apiKeyWithNameExistsErrMsg           = "An API Key with this name already exists in this project, please use a different name"
	apiKeyWithNameDoesntExistErrMsg      = "An API Key with this name doesn't exist in this project."
	teamMemberDoesNotExistErrMsg         = "There are no team members with the email '%s'. Please try again."
	activationTokenExpiredErrMsg         = "This activation token has expired, please request another one"
	usedRegTokenErrMsg                   = "This registration token has already been used"
	projLimitErrMsg                      = "Sorry, project creation is limited for your account. Please contact support!"
	projNameErrMsg                       = "The new project must have a name you haven't used before!"
	projInviteInvalidErrMsg              = "The invitation has expired or is invalid"
	projInviteAlreadyMemberErrMsg        = "You are already a member of the project"
	projInviteResponseInvalidErrMsg      = "Invalid project member invitation response"
	activeProjInviteExistsErrMsg         = "An active invitation for '%s' already exists"
	projInviteExistsErrMsg               = "An invitation for '%s' already exists"
	projInviteDoesntExistErrMsg          = "An invitation for '%s' does not exist"
	varPartnerInviteErr                  = "Your partner does not support inviting users"
	paidTierInviteErrMsg                 = "Only paid tier users can invite project members"
	contactSupportErrMsg                 = "Please contact support"
)

var (
	// Error describes internal console error.
	Error = errs.Class("console service")

	// ErrUnauthorized is error class for authorization related errors.
	ErrUnauthorized = errs.Class("unauthorized")

	// ErrNoMembership is error type of not belonging to a specific project.
	ErrNoMembership = errs.Class("no membership")

	// ErrTokenExpiration is error type of token reached expiration time.
	ErrTokenExpiration = errs.Class("token expiration")

	// ErrTokenInvalid is error type of tokens which are invalid.
	ErrTokenInvalid = errs.Class("invalid token")

	// ErrProjLimit is error type of project limit.
	ErrProjLimit = errs.Class("project limit")

	// ErrUsage is error type of project usage.
	ErrUsage = errs.Class("project usage")

	// ErrLoginCredentials occurs when provided invalid login credentials.
	ErrLoginCredentials = errs.Class("login credentials")

	// ErrActivationCode is error class for failed signup code activation.
	ErrActivationCode = errs.Class("activation code")

	// ErrChangePassword occurs when provided old password is incorrect.
	ErrChangePassword = errs.Class("change password")

	// ErrEmailUsed is error type that occurs on repeating auth attempts with email.
	ErrEmailUsed = errs.Class("email used")

	// ErrEmailNotFound occurs when no users have the specified email.
	ErrEmailNotFound = errs.Class("email not found")

	// ErrNoAPIKey is error type that occurs when there is no api key found.
	ErrNoAPIKey = errs.Class("no api key found")

	// ErrAPIKeyRequest is returned when there is an error parsing a request for api keys.
	ErrAPIKeyRequest = errs.Class("api key request")

	// ErrRegToken describes registration token errors.
	ErrRegToken = errs.Class("registration token")

	// ErrCaptcha describes captcha validation errors.
	ErrCaptcha = errs.Class("captcha validation")

	// ErrRecoveryToken describes account recovery token errors.
	ErrRecoveryToken = errs.Class("recovery token")

	// ErrProjName is error that occurs with reused project names.
	ErrProjName = errs.Class("project name")

	// ErrPurchaseDesc is error that occurs when something is wrong with Purchase description.
	ErrPurchaseDesc = errs.Class("purchase description")

	// ErrAlreadyHasPackage is error that occurs when a user tries to update package, but already has one.
	ErrAlreadyHasPackage = errs.Class("user already has package")

	// ErrAlreadyMember occurs when a user tries to reject an invitation to a project they're already a member of.
	ErrAlreadyMember = errs.Class("already a member")

	// ErrProjectInviteInvalid occurs when a user tries to act upon an invitation that doesn't exist
	// or has expired.
	ErrProjectInviteInvalid = errs.Class("invalid project invitation")

	// ErrAlreadyInvited occurs when trying to invite a user who has already been invited.
	ErrAlreadyInvited = errs.Class("user is already invited")

	// ErrInvalidProjectLimit occurs when the requested project limit is not a non-negative integer and/or greater than the current project limit.
	ErrInvalidProjectLimit = errs.Class("requested project limit is invalid")

	// ErrNotPaidTier occurs when a user must be paid tier in order to complete an operation.
	ErrNotPaidTier = errs.Class("user is not paid tier")

	// ErrHasVarPartner occurs when a user's user agent is a var partner for which an operation is not allowed.
	ErrHasVarPartner = errs.Class("VAR Partner")

	// ErrBotUser occurs when a user must be verified by admin first in order to complete operation.
	ErrBotUser = errs.Class("user has to be verified by admin first")

	// ErrLoginRestricted occurs when a user with PendingBotVerification or LegalHold status tries to log in.
	ErrLoginRestricted = errs.Class("user can't be authenticated")

	// ErrInvalidUserDetails occurs when basic detail of the users are not as per expectation.
	ErrInvalidUserDetails = errs.Class("invalid user details")
)

// Validation Regex
var (
	Regex_EmailValidation = regexp.MustCompile(`^([a-zA-Z0-9._%-+]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`)
	Regex_NameValidation  = regexp.MustCompile(`^(?:(?:[a-zA-z,\.-]+)\s*){2,6}$`)
)

// Service is handling accounts related logic.
//
// architecture: Service
type Service struct {
	log, auditLogger           *zap.Logger
	store                      DB
	restKeys                   RESTKeys
	projectAccounting          accounting.ProjectAccounting
	projectUsage               *accounting.Service
	buckets                    buckets.DB
	placements                 nodeselection.PlacementDefinitions
	accounts                   payments.Accounts
	depositWallets             payments.DepositWallets
	billing                    billing.TransactionsDB
	registrationCaptchaHandler CaptchaHandler
	loginCaptchaHandler        CaptchaHandler
	analytics                  *analytics.Service
	tokens                     *consoleauth.Service
	mailService                *mailservice.Service
	accountFreezeService       *AccountFreezeService
	emission                   *emission.Service
	pushNotificationService    *pushnotifications.Service

	satelliteAddress string
	satelliteName    string

	SatelliteNodeAddress string

	config            Config
	maxProjectBuckets int

	varPartners map[string]struct{}

	versioningConfig  VersioningConfig
	socialShareHelper smartcontract.SocialShareHelper

	nowFn func() time.Time
}

// boris
func (s *Service) GetUsers() Users {
	return s.store.Users()
}

// boris
func (s *Service) GetProjects() Projects {
	return s.store.Projects()
}

// GetFCMTokens returns the FCM tokens database interface.
func (s *Service) GetFCMTokens() pushnotifications.DB {
	return s.store.FCMTokens()
}

// SendPushNotification sends a push notification to a user.
func (s *Service) SendPushNotification(ctx context.Context, userID uuid.UUID, notification pushnotifications.Notification) error {
	if s.pushNotificationService == nil {
		return Error.New("push notification service is not initialized")
	}
	return s.pushNotificationService.SendNotification(ctx, userID, notification)
}

// SendPushNotificationWithPreferences sends a push notification after checking user preferences.
// Gets config by category, verifies it's a push template, and checks user preferences.
// If user preference level > config level, the notification is not sent.
func (s *Service) SendPushNotificationWithPreferences(ctx context.Context, userID uuid.UUID, category string, notification pushnotifications.Notification) error {
	// Get configs by category
	configsDB := s.GetConfigs()
	configsService := configs.NewService(configsDB)

	// Filter to find config with ConfigType == ConfigTypeNotificationTemplate (which is "push")
	pushConfigType := configs.ConfigTypeNotificationTemplate
	filters := configs.ListConfigFilters{
		ConfigType: &pushConfigType,
		Category:   &category,
	}

	configsList, err := configsService.ListConfigs(ctx, filters)
	if err != nil {
		// If we can't get configs, allow notification by default
		return s.SendPushNotification(ctx, userID, notification)
	}

	// Find the first active push config for this category
	var pushConfig *configs.Config
	for i := range configsList {
		if configsList[i].IsActive && configsList[i].ConfigType == pushConfigType {
			pushConfig = &configsList[i]
			break
		}
	}

	// If no push config found, allow notification by default
	if pushConfig == nil {
		return s.SendPushNotification(ctx, userID, notification)
	}

	// Extract level from ConfigData
	configLevel := configs.GetConfigLevel(pushConfig.ConfigData)

	// Check preferences using ShouldSendNotification
	preferenceDB := s.GetUserNotificationPreferences()
	preferenceService := configs.NewPreferenceService(preferenceDB)

	shouldSend, err := preferenceService.ShouldSendNotification(ctx, userID, category, string(configs.NotificationTypePush), configLevel)
	if err != nil {
		// If we can't check preferences, allow notification by default
		return s.SendPushNotification(ctx, userID, notification)
	}

	// If should not send, return nil (no error, just filtered)
	if !shouldSend {
		return nil
	}

	// If should send, call SendPushNotification
	return s.SendPushNotification(ctx, userID, notification)
}

// GetPushNotifications returns the push notifications database interface.
func (s *Service) GetPushNotifications() pushnotifications.PushNotificationDB {
	return s.store.PushNotifications()
}

// GetConfigs returns the configs database interface.
func (s *Service) GetConfigs() configs.DB {
	return s.store.Configs()
}

// GetUserNotificationPreferences returns the user notification preferences database interface.
func (s *Service) GetUserNotificationPreferences() configs.UserPreferenceDB {
	return s.store.UserNotificationPreferences()
}

// boris
func (s *Service) IsProjectOwner(ctx context.Context, userID uuid.UUID, projectID uuid.UUID) (isOwner bool, project *Project, err error) {
	return s.isProjectOwner(ctx, userID, projectID)
}
func (s *Service) UpdatingProjects(ctx context.Context, userID uuid.UUID, projectID uuid.UUID, updatedProject UpsertProjectInfo) (p *Project, err error) {
	return s.UpdatingProject(ctx, userID, projectID, updatedProject)
}

func (s *Service) GetPaymentPlans(ctx context.Context) (plans []billing.PaymentPlans, err error) {
	return s.billing.GetPaymentPlans(ctx)
}

func (s *Service) GetPaymentPlansByID(ctx context.Context, id int64) (plans *billing.PaymentPlans, err error) {
	return s.billing.GetPaymentPlansByID(ctx, id)
}

func (s *Service) GetActiveCoupons(ctx context.Context) (coupons []billing.Coupons, err error) {
	return s.billing.GetActiveCoupons(ctx)
}

func (s *Service) GetCouponByCode(ctx context.Context, code string) (coupon *billing.Coupons, err error) {
	return s.billing.GetCouponByCode(ctx, code)
}

func (s *Service) GetCoupons(ctx context.Context) (coupons []billing.Coupons, err error) {
	return s.billing.GetCoupons(ctx)
}

func (s *Service) GetBackupShare(ctx context.Context, backupID string) (share []byte, err error) {
	return s.store.Web3Auth().GetBackupShare(ctx, backupID)
}

func (s *Service) UploadBackupShare(ctx context.Context, backupID string, share []byte) (err error) {
	return s.store.Web3Auth().UploadBackupShare(ctx, backupID, share)
}

func (s *Service) CreateAccessGrantForProject(ctx context.Context, projectID uuid.UUID, passphrase string,
	prefix []grant.SharePrefix, permission *grant.Permission, apiKey *macaroon.APIKey) (string, error) {

	salt, err := s.GetSalt(ctx, projectID)
	if err != nil {
		return "", err
	}

	key, err := encryption.DeriveRootKey([]byte(passphrase), salt, "", 8)
	if err != nil {
		return "", err
	}

	encAccess := grant.NewEncryptionAccessWithDefaultKey(key)
	encAccess.SetDefaultPathCipher(storj.EncAESGCM)
	// if config.disableObjectKeyEncryption {
	// 	encAccess.SetDefaultPathCipher(storj.EncNull)
	// }
	encAccess.LimitTo(apiKey)

	g := &grant.Access{
		SatelliteAddress: s.SatelliteNodeAddress,
		APIKey:           apiKey,
		EncAccess:        encAccess,
	}

	fmt.Println("TESTING CODE FOR SATELLITE ADDRESS", g)

	if len(prefix) == 0 && permission == nil {
		return g.Serialize()
	}

	if permission == nil {
		return "", fmt.Errorf("permission is required when prefix is provided")
	}

	restricted, err := g.Restrict(
		*permission,
		prefix...,
	)
	if err != nil {
		return "", fmt.Errorf("failed to restrict access: %v", err)
	}

	return restricted.Serialize()

}

func init() {
	var c Config
	cfgstruct.Bind(pflag.NewFlagSet("", pflag.PanicOnError), &c, cfgstruct.UseTestDefaults())
	if c.PasswordCost != TestPasswordCost {
		panic("invalid test constant defined in struct tag")
	}
	cfgstruct.Bind(pflag.NewFlagSet("", pflag.PanicOnError), &c, cfgstruct.UseReleaseDefaults())
	if c.PasswordCost != 0 {
		panic("invalid release constant defined in struct tag. should be 0 (=automatic)")
	}
}

// Payments separates all payment related functionality.
type Payments struct {
	service *Service
}

// NewService returns new instance of Service.
func NewService(log *zap.Logger, store DB, restKeys RESTKeys, projectAccounting accounting.ProjectAccounting,
	projectUsage *accounting.Service, buckets buckets.DB, accounts payments.Accounts, depositWallets payments.DepositWallets,
	billing billing.TransactionsDB, analytics *analytics.Service, tokens *consoleauth.Service, mailService *mailservice.Service,
	accountFreezeService *AccountFreezeService, emission *emission.Service, satelliteAddress string, satelliteName string, satelliteNodeAddress string,
	maxProjectBuckets int, placements nodeselection.PlacementDefinitions, versioning VersioningConfig, config Config,
	socialShareHelper smartcontract.SocialShareHelper) (*Service, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if store == nil {
		return nil, errs.New("store can't be nil")
	}
	if config.PasswordCost == 0 {
		config.PasswordCost = bcrypt.DefaultCost
	}

	// We have two separate captcha handlers for login and registration.
	// We want to easily swap between captchas independently.
	// For example, google recaptcha for login screen and hcaptcha for registration screen.
	var registrationCaptchaHandler CaptchaHandler
	if config.Captcha.Registration.Recaptcha.Enabled {
		registrationCaptchaHandler = NewDefaultCaptcha(Recaptcha, config.Captcha.Registration.Recaptcha.SecretKey)
	} else if config.Captcha.Registration.Hcaptcha.Enabled {
		registrationCaptchaHandler = NewDefaultCaptcha(Hcaptcha, config.Captcha.Registration.Hcaptcha.SecretKey)
	}

	var loginCaptchaHandler CaptchaHandler
	if config.Captcha.Login.Recaptcha.Enabled {
		loginCaptchaHandler = NewDefaultCaptcha(Recaptcha, config.Captcha.Login.Recaptcha.SecretKey)
	} else if config.Captcha.Login.Hcaptcha.Enabled {
		loginCaptchaHandler = NewDefaultCaptcha(Hcaptcha, config.Captcha.Login.Hcaptcha.SecretKey)
	}

	partners := make(map[string]struct{}, len(config.VarPartners))
	for _, partner := range config.VarPartners {
		partners[partner] = struct{}{}
	}

	versioning.projectMap = make(map[uuid.UUID]struct{}, len(versioning.UseBucketLevelObjectVersioningProjects))
	for _, id := range versioning.UseBucketLevelObjectVersioningProjects {
		projectID, err := uuid.FromString(id)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		versioning.projectMap[projectID] = struct{}{}
	}

	// Initialize push notification service
	pushNotificationService, err := pushnotifications.NewService(log.Named("pushnotifications"), store.FCMTokens(), store.PushNotifications(), config.PushNotifications)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &Service{
		log:                        log,
		auditLogger:                log.Named("auditlog"),
		store:                      store,
		restKeys:                   restKeys,
		projectAccounting:          projectAccounting,
		projectUsage:               projectUsage,
		buckets:                    buckets,
		placements:                 placements,
		accounts:                   accounts,
		depositWallets:             depositWallets,
		billing:                    billing,
		registrationCaptchaHandler: registrationCaptchaHandler,
		loginCaptchaHandler:        loginCaptchaHandler,
		analytics:                  analytics,
		tokens:                     tokens,
		mailService:                mailService,
		accountFreezeService:       accountFreezeService,
		emission:                   emission,
		satelliteAddress:           satelliteAddress,
		SatelliteNodeAddress:       satelliteNodeAddress,
		satelliteName:              satelliteName,
		maxProjectBuckets:          maxProjectBuckets,
		config:                     config,
		varPartners:                partners,
		versioningConfig:           versioning,
		socialShareHelper:          socialShareHelper,
		pushNotificationService:    pushNotificationService,
		nowFn:                      time.Now,
	}, nil
}

func getRequestingIP(ctx context.Context) (source, forwardedFor string) {
	if req := GetRequest(ctx); req != nil {
		return req.RemoteAddr, req.Header.Get("X-Forwarded-For")
	}
	return "", ""
}

// extractIPFromRequest extracts IP address from HTTP request
func extractIPFromRequest(req *http.Request) string {
	// Check X-Forwarded-For header (first IP in the chain)
	forwarded := req.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	realIP := req.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Fall back to RemoteAddr
	ip := req.RemoteAddr
	// Remove port if present (format: "IP:port")
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func (s *Service) auditLog(ctx context.Context, operation string, userID *uuid.UUID, email string, extra ...zap.Field) {
	sourceIP, forwardedForIP := getRequestingIP(ctx)
	fields := append(
		make([]zap.Field, 0, len(extra)+6),
		zap.String("operation", operation),
		zap.String("source-ip", sourceIP),
		zap.String("forwarded-for-ip", forwardedForIP),
	)
	if userID != nil {
		fields = append(fields, zap.String("userID", userID.String()))
	}
	if email != "" {
		fields = append(fields, zap.String("email", email))
	}
	if requestID := requestid.FromContext(ctx); requestID != "" {
		fields = append(fields, zap.String("requestID", requestID))
	}

	fields = append(fields, extra...)
	s.auditLogger.Info("console activity", fields...)
}

func (s *Service) getUserAndAuditLog(ctx context.Context, operation string, extra ...zap.Field) (*User, error) {
	user, err := GetUser(ctx)
	if err != nil {
		sourceIP, forwardedForIP := getRequestingIP(ctx)
		s.auditLogger.Info("console activity unauthorized",
			append(append(
				make([]zap.Field, 0, len(extra)+4),
				zap.String("operation", operation),
				zap.Error(err),
				zap.String("source-ip", sourceIP),
				zap.String("forwarded-for-ip", forwardedForIP),
			), extra...)...)
		return nil, err
	}
	s.auditLog(ctx, operation, &user.ID, user.Email, extra...)
	return user, nil
}

// boris
func (s *Service) GetUserAndAuditLog(ctx context.Context, operation string, extra ...zap.Field) (*User, error) {
	user, err := GetUser(ctx)
	if err != nil {
		sourceIP, forwardedForIP := getRequestingIP(ctx)
		s.auditLogger.Info("console activity unauthorized",
			append(append(
				make([]zap.Field, 0, len(extra)+4),
				zap.String("operation", operation),
				zap.Error(err),
				zap.String("source-ip", sourceIP),
				zap.String("forwarded-for-ip", forwardedForIP),
			), extra...)...)
		return nil, err
	}
	s.auditLog(ctx, operation, &user.ID, user.Email, extra...)
	return user, nil
}

// Payments separates all payment related functionality.
func (s *Service) Payments() Payments {
	return Payments{service: s}
}

// SetupAccount creates payment account for authorized user.
func (payment Payments) SetupAccount(ctx context.Context) (_ payments.CouponType, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "setup payment account")
	if err != nil {
		return payments.NoCoupon, Error.Wrap(err)
	}

	return payment.service.accounts.Setup(ctx, user.ID, user.Email, user.SignupPromoCode)
}

// AccountBalance return account balance.
func (payment Payments) AccountBalance(ctx context.Context) (balance payments.Balance, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "get account balance")
	if err != nil {
		return payments.Balance{}, Error.Wrap(err)
	}

	return payment.service.accounts.Balances().Get(ctx, user.ID)
}

// AddCreditCard is used to save new credit card and attach it to payment account.
func (payment Payments) AddCreditCard(ctx context.Context, creditCardToken string) (card payments.CreditCard, err error) {
	defer mon.Task()(&ctx, creditCardToken)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "add credit card")
	if err != nil {
		return payments.CreditCard{}, Error.Wrap(err)
	}

	card, err = payment.service.accounts.CreditCards().Add(ctx, user.ID, creditCardToken)
	if err != nil {
		return payments.CreditCard{}, Error.Wrap(err)
	}

	payment.service.analytics.TrackCreditCardAdded(user.ID, user.Email)

	if !user.PaidTier {
		err = payment.upgradeToPaidTier(ctx, user)
		if err != nil {
			return payments.CreditCard{}, Error.Wrap(err)
		}
	}

	// Send push notification for credit card added
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		lastFour := ""
		cardType := ""
		if card.Last4 != "" {
			lastFour = card.Last4
		}
		if card.Brand != "" {
			cardType = card.Brand
		}
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title: "Payment Method Added",
			Body: fmt.Sprintf("A credit card%s%s has been added to your account at %s", func() string {
				if cardType != "" {
					return fmt.Sprintf(" (%s)", cardType)
				}
				return ""
			}(), func() string {
				if lastFour != "" {
					return fmt.Sprintf(" ending in %s", lastFour)
				}
				return ""
			}(), timestamp),
			Data:     map[string]string{"event": "credit_card_added", "last_four": lastFour, "card_type": cardType, "timestamp": timestamp},
			Priority: "normal", // level 3
		}
		if err := payment.service.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "billing", notification); err != nil {
			payment.service.log.Warn("Failed to send push notification for credit card added",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			payment.service.log.Debug("Successfully sent push notification for credit card added",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return card, nil
}

// AddCardByPaymentMethodID is used to save new credit card and attach it to payment account.
func (payment Payments) AddCardByPaymentMethodID(ctx context.Context, pmID string) (card payments.CreditCard, err error) {
	defer mon.Task()(&ctx, pmID)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "add credit card")
	if err != nil {
		return payments.CreditCard{}, Error.Wrap(err)
	}

	card, err = payment.service.accounts.CreditCards().AddByPaymentMethodID(ctx, user.ID, pmID)
	if err != nil {
		return payments.CreditCard{}, Error.Wrap(err)
	}

	payment.service.analytics.TrackCreditCardAdded(user.ID, user.Email)

	if !user.PaidTier {
		err = payment.upgradeToPaidTier(ctx, user)
		if err != nil {
			return payments.CreditCard{}, Error.Wrap(err)
		}
	}

	// Send push notification for credit card added (by payment method ID)
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		lastFour := ""
		cardType := ""
		if card.Last4 != "" {
			lastFour = card.Last4
		}
		if card.Brand != "" {
			cardType = card.Brand
		}
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title: "Payment Method Added",
			Body: fmt.Sprintf("A credit card%s%s has been added to your account at %s", func() string {
				if cardType != "" {
					return fmt.Sprintf(" (%s)", cardType)
				}
				return ""
			}(), func() string {
				if lastFour != "" {
					return fmt.Sprintf(" ending in %s", lastFour)
				}
				return ""
			}(), timestamp),
			Data:     map[string]string{"event": "credit_card_added", "last_four": lastFour, "card_type": cardType, "timestamp": timestamp},
			Priority: "normal", // level 3
		}
		if err := payment.service.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "billing", notification); err != nil {
			payment.service.log.Warn("Failed to send push notification for credit card added",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			payment.service.log.Debug("Successfully sent push notification for credit card added",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return card, nil
}

func (payment Payments) upgradeToPaidTier(ctx context.Context, user *User) (err error) {
	// put this user into the paid tier and convert projects to upgraded limits.
	now := payment.service.nowFn()

	freeze, err := payment.service.accountFreezeService.Get(ctx, user.ID, TrialExpirationFreeze)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return Error.Wrap(err)
		}
	}
	if freeze != nil {
		err = payment.service.accountFreezeService.TrialExpirationUnfreezeUser(ctx, user.ID)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	err = payment.service.store.Users().UpdatePaidTier(ctx, user.ID, true,
		payment.service.config.UsageLimits.Bandwidth.Paid,
		payment.service.config.UsageLimits.Storage.Paid,
		payment.service.config.UsageLimits.Segment.Paid,
		payment.service.config.UsageLimits.Project.Paid,
		&now,
	)
	if err != nil {
		return Error.Wrap(err)
	}
	payment.service.analytics.TrackUserUpgraded(user.ID, user.Email, user.TrialExpiration)

	projects, err := payment.service.store.Projects().GetOwn(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}
	for _, project := range projects {
		if project.StorageLimit == nil || *project.StorageLimit < payment.service.config.UsageLimits.Storage.Paid {
			project.StorageLimit = new(memory.Size)
			*project.StorageLimit = payment.service.config.UsageLimits.Storage.Paid
		}
		if project.BandwidthLimit == nil || *project.BandwidthLimit < payment.service.config.UsageLimits.Bandwidth.Paid {
			project.BandwidthLimit = new(memory.Size)
			*project.BandwidthLimit = payment.service.config.UsageLimits.Bandwidth.Paid
		}
		if project.SegmentLimit == nil || *project.SegmentLimit < payment.service.config.UsageLimits.Segment.Paid {
			*project.SegmentLimit = payment.service.config.UsageLimits.Segment.Paid
		}
		err = payment.service.store.Projects().Update(ctx, &project)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	return nil
}

// MakeCreditCardDefault makes a credit card default payment method.
func (payment Payments) MakeCreditCardDefault(ctx context.Context, cardID string) (err error) {
	defer mon.Task()(&ctx, cardID)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "make credit card default")
	if err != nil {
		return Error.Wrap(err)
	}

	err = payment.service.accounts.CreditCards().MakeDefault(ctx, user.ID, cardID)
	if err != nil {
		return Error.Wrap(err)
	}

	// Send push notification for default credit card changed
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Default Credit Card Changed",
			Body:     fmt.Sprintf("Your default credit card has been updated at %s", timestamp),
			Data:     map[string]string{"event": "default_credit_card_changed", "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := payment.service.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "billing", notification); err != nil {
			payment.service.log.Warn("Failed to send push notification for default credit card changed",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			payment.service.log.Debug("Successfully sent push notification for default credit card changed",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return nil
}

// ProjectsCharges returns how much money current user will be charged for each project which he owns.
func (payment Payments) ProjectsCharges(ctx context.Context, since, before time.Time) (_ payments.ProjectChargesResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "project charges")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return payment.service.accounts.ProjectCharges(ctx, user.ID, since, before)
}

// ListCreditCards returns a list of credit cards for a given payment account.
func (payment Payments) ListCreditCards(ctx context.Context) (_ []payments.CreditCard, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "list credit cards")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return payment.service.accounts.CreditCards().List(ctx, user.ID)
}

// RemoveCreditCard is used to detach a credit card from payment account.
func (payment Payments) RemoveCreditCard(ctx context.Context, cardID string) (err error) {
	defer mon.Task()(&ctx, cardID)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "remove credit card")
	if err != nil {
		return Error.Wrap(err)
	}

	err = payment.service.accounts.CreditCards().Remove(ctx, user.ID, cardID)
	if err != nil {
		return Error.Wrap(err)
	}

	// Send push notification for credit card removed
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Payment Method Removed",
			Body:     fmt.Sprintf("A credit card has been removed from your account at %s", timestamp),
			Data:     map[string]string{"event": "credit_card_removed", "timestamp": timestamp},
			Priority: "normal", // level 3
		}
		if err := payment.service.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "billing", notification); err != nil {
			payment.service.log.Warn("Failed to send push notification for credit card removed",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			payment.service.log.Debug("Successfully sent push notification for credit card removed",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return nil
}

// BillingHistory returns a list of billing history items for payment account.
func (payment Payments) BillingHistory(ctx context.Context) (billingHistory []*BillingHistoryItem, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "get billing history")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	invoices, couponUsages, err := payment.service.accounts.Invoices().ListWithDiscounts(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for _, invoice := range invoices {
		billingHistory = append(billingHistory, &BillingHistoryItem{
			ID:          invoice.ID,
			Description: invoice.Description,
			Amount:      invoice.Amount,
			Status:      invoice.Status,
			Link:        invoice.Link,
			End:         invoice.End,
			Start:       invoice.Start,
			Type:        Invoice,
		})
	}

	txsInfos, err := payment.service.accounts.StorjTokens().ListTransactionInfos(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for _, info := range txsInfos {
		billingHistory = append(billingHistory, &BillingHistoryItem{
			ID:          info.ID.String(),
			Description: "STORJ Token Deposit",
			Amount:      info.AmountCents,
			Received:    info.ReceivedCents,
			Status:      info.Status.String(),
			Link:        info.Link,
			Start:       info.CreatedAt,
			End:         info.ExpiresAt,
			Type:        Transaction,
		})
	}

	charges, err := payment.service.accounts.Charges(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for _, charge := range charges {
		desc := fmt.Sprintf("Payment(%s %s)", charge.CardInfo.Brand, charge.CardInfo.LastFour)

		billingHistory = append(billingHistory, &BillingHistoryItem{
			ID:          charge.ID,
			Description: desc,
			Amount:      charge.Amount,
			Start:       charge.CreatedAt,
			Type:        Charge,
		})
	}

	for _, usage := range couponUsages {
		desc := "Coupon"
		if usage.Coupon.Name != "" {
			desc = usage.Coupon.Name
		}
		if usage.Coupon.PromoCode != "" {
			desc += " (" + usage.Coupon.PromoCode + ")"
		}

		billingHistory = append(billingHistory, &BillingHistoryItem{
			Description: desc,
			Amount:      usage.Amount,
			Start:       usage.PeriodStart,
			End:         usage.PeriodEnd,
			Type:        Coupon,
		})
	}

	bonuses, err := payment.service.accounts.StorjTokens().ListDepositBonuses(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for _, bonus := range bonuses {
		billingHistory = append(billingHistory,
			&BillingHistoryItem{
				Description: fmt.Sprintf("%d%% Bonus for STORJ Token Deposit", bonus.Percentage),
				Amount:      bonus.AmountCents,
				Status:      "Added to balance",
				Start:       bonus.CreatedAt,
				Type:        DepositBonus,
			},
		)
	}

	sort.SliceStable(billingHistory,
		func(i, j int) bool {
			return billingHistory[i].Start.After(billingHistory[j].Start)
		},
	)

	return billingHistory, nil
}

// InvoiceHistory returns a paged list of invoices for payment account.
func (payment Payments) InvoiceHistory(ctx context.Context, cursor payments.InvoiceCursor) (history *BillingHistoryPage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "get invoice history")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	page, err := payment.service.accounts.Invoices().ListPaged(ctx, user.ID, cursor)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var historyItems []BillingHistoryItem
	for _, invoice := range page.Invoices {
		historyItems = append(historyItems, BillingHistoryItem{
			ID:          invoice.ID,
			Description: invoice.Description,
			Amount:      invoice.Amount,
			Status:      invoice.Status,
			Link:        invoice.Link,
			End:         invoice.End,
			Start:       invoice.Start,
			Type:        Invoice,
		})
	}

	return &BillingHistoryPage{
		Items:    historyItems,
		Next:     page.Next,
		Previous: page.Previous,
	}, nil
}

// checkProjectInvoicingStatus returns error if for the given project there are outstanding project records and/or usage
// which have not been applied/invoiced yet (meaning sent over to stripe).
func (payment Payments) checkProjectInvoicingStatus(ctx context.Context, projectID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = payment.service.getUserAndAuditLog(ctx, "project invoicing status")
	if err != nil {
		return Error.Wrap(err)
	}

	return payment.service.accounts.CheckProjectInvoicingStatus(ctx, projectID)
}

// checkProjectUsageStatus returns error if for the given project there is some usage for current or previous month.
func (payment Payments) checkProjectUsageStatus(ctx context.Context, projectID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = payment.service.getUserAndAuditLog(ctx, "project usage status")
	if err != nil {
		return Error.Wrap(err)
	}

	return payment.service.accounts.CheckProjectUsageStatus(ctx, projectID)
}

// ApplyCoupon applies a coupon to an account based on couponID.
func (payment Payments) ApplyCoupon(ctx context.Context, couponID string) (coupon *payments.Coupon, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "apply coupon")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	coupon, err = payment.service.accounts.Coupons().ApplyCoupon(ctx, user.ID, couponID)
	if err != nil {
		return coupon, Error.Wrap(err)
	}
	return coupon, nil
}

// ApplyFreeTierCoupon applies the default free tier coupon to an account.
func (payment Payments) ApplyFreeTierCoupon(ctx context.Context) (coupon *payments.Coupon, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	coupon, err = payment.service.accounts.Coupons().ApplyFreeTierCoupon(ctx, user.ID)
	if err != nil {
		return coupon, Error.Wrap(err)
	}

	return coupon, nil
}

// ApplyCouponCode applies a coupon code to a Stripe customer
// and returns the coupon corresponding to the code.
func (payment Payments) ApplyCouponCode(ctx context.Context, couponCode string) (coupon *payments.Coupon, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "apply coupon code")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	coupon, err = payment.service.accounts.Coupons().ApplyCouponCode(ctx, user.ID, couponCode)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return coupon, nil
}

// GetCoupon returns the coupon applied to the user's account.
func (payment Payments) GetCoupon(ctx context.Context) (coupon *payments.Coupon, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "get coupon")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	coupon, err = payment.service.accounts.Coupons().GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return coupon, nil
}

// AttemptPayOverdueInvoices attempts to pay a user's open, overdue invoices.
func (payment Payments) AttemptPayOverdueInvoices(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "attempt to pay overdue invoices")
	if err != nil {
		return Error.Wrap(err)
	}

	err = payment.service.accounts.Invoices().AttemptPayOverdueInvoices(ctx, user.ID)
	if err != nil {
		payment.service.log.Warn("error attempting to pay overdue invoices for user", zap.String("user id", user.ID.String()), zap.Error(err))
		return Error.Wrap(err)
	}

	return nil
}

// checkRegistrationSecret returns a RegistrationToken if applicable (nil if not), and an error
// if and only if the registration shouldn't proceed.
func (s *Service) checkRegistrationSecret(ctx context.Context, tokenSecret RegistrationSecret) (*RegistrationToken, error) {
	if s.config.OpenRegistrationEnabled && tokenSecret.IsZero() {
		// in this case we're going to let the registration happen without a token
		return nil, nil
	}

	// in all other cases, require a registration token
	registrationToken, err := s.store.RegistrationTokens().GetBySecret(ctx, tokenSecret)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	// if a registration token is already associated with an user ID, that means the token is already used
	// we should terminate the account creation process and return an error
	if registrationToken.OwnerID != nil {
		return nil, ErrValidation.New(usedRegTokenErrMsg)
	}

	return registrationToken, nil
}

// CreateUser gets password hash value and creates new inactive User.
func (s *Service) CreateUser(ctx context.Context, user CreateUser, tokenSecret RegistrationSecret, socialsign bool) (u *User, err error) {
	defer mon.Task()(&ctx)(&err)

	var captchaScore *float64

	mon.Counter("create_user_attempt").Inc(1) //mon:locked

	if s.config.Captcha.Registration.Recaptcha.Enabled || s.config.Captcha.Registration.Hcaptcha.Enabled {
		valid, score, err := s.registrationCaptchaHandler.Verify(ctx, user.CaptchaResponse, user.IP)
		if err != nil {
			mon.Counter("create_user_captcha_error").Inc(1) //mon:locked
			s.log.Error("captcha authorization failed", zap.Error(err))
			return nil, ErrCaptcha.Wrap(err)
		}
		if !valid {
			mon.Counter("create_user_captcha_unsuccessful").Inc(1) //mon:locked
			return nil, ErrCaptcha.New("captcha validation unsuccessful")
		}
		captchaScore = score
	}

	if !socialsign {
		if err := user.IsValid(user.AllowNoName); err != nil {
			// NOTE: error is already wrapped with an appropriated class.
			return nil, err
		}
	}

	registrationToken, err := s.checkRegistrationSecret(ctx, tokenSecret)
	if err != nil {
		return nil, ErrRegToken.Wrap(err)
	}

	// verified, unverified, err := s.store.Users().GetByEmailWithUnverified(ctx, user.Email)
	if !socialsign {
		verified, unverified, err := s.store.Users().GetByEmailWithUnverified(ctx, user.Email)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		if verified != nil {
			mon.Counter("create_user_duplicate_verified").Inc(1) //mon:locked
			return nil, ErrEmailUsed.New(emailUsedErrMsg)
		} else if len(unverified) != 0 {
			mon.Counter("create_user_duplicate_unverified").Inc(1) //mon:locked
			return nil, ErrEmailUsed.New(emailUsedErrMsg)
		}
	} else {
		verified, unverified, err := s.store.Users().GetByEmailWithUnverified_google(ctx, user.Email)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		if verified != nil {
			mon.Counter("create_user_duplicate_verified").Inc(1) //mon:locked
			return nil, ErrEmailUsed.New(emailUsedErrMsg)
		} else if len(unverified) != 0 {
			mon.Counter("create_user_duplicate_unverified").Inc(1) //mon:locked
			return nil, ErrEmailUsed.New(emailUsedErrMsg)
		}
	}

	// if err != nil {
	// 	return nil, Error.Wrap(err)
	// }

	// if verified != nil {
	// 	mon.Counter("create_user_duplicate_verified").Inc(1) //mon:locked
	// 	return nil, ErrEmailUsed.New(emailUsedErrMsg)
	// } else if len(unverified) != 0 {
	// 	mon.Counter("create_user_duplicate_unverified").Inc(1) //mon:locked
	// 	return nil, ErrEmailUsed.New(emailUsedErrMsg)
	// }

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), s.config.PasswordCost)
	if !socialsign {
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}

	// patern validation for user details
	if !Regex_NameValidation.Match([]byte(user.FullName)) {
		return nil, ErrInvalidUserDetails.New("invalid full name " + user.FullName)
	}

	if !Regex_EmailValidation.Match([]byte(user.Email)) {
		return nil, ErrInvalidUserDetails.New("invalid user email")
	}

	status := Inactive
	if socialsign {
		status = Active
	}

	// store data
	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) error {
		userID, err := uuid.New()
		if err != nil {
			return err
		}

		newUser := &User{
			ID:               userID,
			Email:            user.Email,
			FullName:         user.FullName,
			ShortName:        user.ShortName,
			PasswordHash:     hash,
			Status:           status,
			IsProfessional:   user.IsProfessional,
			Position:         user.Position,
			CompanyName:      user.CompanyName,
			EmployeeCount:    user.EmployeeCount,
			HaveSalesContact: user.HaveSalesContact,
			SignupPromoCode:  user.SignupPromoCode,
			SignupCaptcha:    captchaScore,
			ActivationCode:   user.ActivationCode,
			SignupId:         user.SignupId,
			Source:           user.Source,
			WalletId:         user.WalletId,
		}

		if user.UtmParams != nil {
			newUser.UtmSource = user.UtmParams.UtmSource
			newUser.UtmMedium = user.UtmParams.UtmMedium
			newUser.UtmCampaign = user.UtmParams.UtmCampaign
			newUser.UtmTerm = user.UtmParams.UtmTerm
			newUser.UtmContent = user.UtmParams.UtmContent
		}

		if user.UserAgent != nil {
			newUser.UserAgent = user.UserAgent
		}

		if registrationToken != nil {
			newUser.ProjectLimit = registrationToken.ProjectLimit
		} else {
			newUser.ProjectLimit = s.config.UsageLimits.Project.Free
		}

		if s.config.FreeTrialDuration != 0 {
			expiration := s.nowFn().Add(s.config.FreeTrialDuration)
			newUser.TrialExpiration = &expiration
		}

		// TODO: move the project limits into the registration token.
		newUser.ProjectStorageLimit = s.config.UsageLimits.Storage.Free.Int64()
		newUser.ProjectBandwidthLimit = s.config.UsageLimits.Bandwidth.Free.Int64()
		newUser.ProjectSegmentLimit = s.config.UsageLimits.Segment.Free

		u, err = tx.Users().Insert(ctx,
			newUser,
		)
		if err != nil {
			return err
		}

		// Send push notification for user sign up (after transaction commits)
		// Note: This will be sent after the transaction completes

		if !socialsign {
			verified, unverified, err := tx.Users().GetByEmailWithUnverified(ctx, user.Email)
			if err != nil {
				return err
			}

			if verified != nil {
				err = tx.Users().Delete(ctx, u.ID)
				if err != nil {
					return err
				}
				mon.Counter("create_user_duplicate_verified").Inc(1) //mon:locked
				return ErrEmailUsed.New(emailUsedErrMsg)
			}

			for _, other := range unverified {
				// We compare IDs because a parallel user creation transaction for the same
				// email could have created a record at the same time as ours.
				if other.CreatedAt.Before(u.CreatedAt) || other.ID.Less(u.ID) {
					err = tx.Users().Delete(ctx, u.ID)
					if err != nil {
						return err
					}
					mon.Counter("create_user_duplicate_unverified").Inc(1) //mon:locked
					return ErrEmailUsed.New(emailUsedErrMsg)
				}
			}

		}

		if registrationToken != nil {
			err = tx.RegistrationTokens().UpdateOwner(ctx, registrationToken.Secret, u.ID)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.auditLog(ctx, "create user", nil, user.Email)
	mon.Counter("create_user_success").Inc(1) //mon:locked

	// Send push notification for user sign up
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Welcome to StorX",
			Body:     fmt.Sprintf("Welcome! Your account has been created successfully at %s", timestamp),
			Data:     map[string]string{"event": "user_sign_up", "email": notifyEmail, "timestamp": timestamp},
			Priority: "normal", // level 1
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for user sign up",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for user sign up",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	// Send push notification for registered successfully
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := u.ID   // Capture user ID before closure
		notifyEmail := u.Email // Capture email before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Registration Successful",
			Body:     fmt.Sprintf("Your account has been registered successfully at %s", timestamp),
			Data:     map[string]string{"event": "registered_successfully", "email": notifyEmail, "timestamp": timestamp},
			Priority: "high", // level 4
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for registered successfully",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for registered successfully",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	return u, nil
}

// TestSwapCaptchaHandler replaces the existing handler for captchas with
// the one specified for use in testing.
func (s *Service) TestSwapCaptchaHandler(h CaptchaHandler) {
	s.registrationCaptchaHandler = h
	s.loginCaptchaHandler = h
}

// GenerateActivationToken - is a method for generating activation token.
func (s *Service) GenerateActivationToken(ctx context.Context, id uuid.UUID, email string) (token string, err error) {
	defer mon.Task()(&ctx)(&err)

	return s.tokens.CreateToken(ctx, id, email)
}

// GeneratePasswordRecoveryToken - is a method for generating password recovery token.
func (s *Service) GeneratePasswordRecoveryToken(ctx context.Context, id uuid.UUID) (token string, err error) {
	defer mon.Task()(&ctx)(&err)

	resetPasswordToken, err := s.store.ResetPasswordTokens().GetByOwnerID(ctx, id)
	if err == nil {
		err := s.store.ResetPasswordTokens().Delete(ctx, resetPasswordToken.Secret)
		if err != nil {
			return "", Error.Wrap(err)
		}
	}

	resetPasswordToken, err = s.store.ResetPasswordTokens().Create(ctx, id)
	if err != nil {
		return "", Error.Wrap(err)
	}

	s.auditLog(ctx, "generate password recovery token", &id, "")

	return resetPasswordToken.Secret.String(), nil
}

// GenerateSessionToken creates a new session and returns the string representation of its token.
func (s *Service) GenerateSessionToken(ctx context.Context, userID uuid.UUID, email, ip, userAgent string, customDuration *time.Duration) (_ *TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	sessionID, err := uuid.New()
	if err != nil {
		return nil, Error.Wrap(err)
	}

	duration := s.config.Session.Duration
	if customDuration != nil {
		duration = *customDuration
	} else if s.config.Session.InactivityTimerEnabled {
		settings, err := s.store.Users().GetSettings(ctx, userID)
		if err != nil && !errs.Is(err, sql.ErrNoRows) {
			return nil, Error.Wrap(err)
		}
		if settings != nil && settings.SessionDuration != nil {
			duration = *settings.SessionDuration
		} else {
			duration = time.Duration(s.config.Session.InactivityTimerDuration) * time.Second
		}
	}
	expiresAt := time.Now().Add(duration)

	_, err = s.store.WebappSessions().Create(ctx, sessionID, userID, ip, userAgent, expiresAt)
	if err != nil {
		return nil, err
	}

	token := consoleauth.Token{Payload: sessionID.Bytes()}

	signature, err := s.tokens.SignToken(token)
	if err != nil {
		return nil, err
	}
	token.Signature = signature

	s.auditLog(ctx, "login", &userID, email)

	s.analytics.TrackSignedIn(userID, email)

	return &TokenInfo{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// ActivateAccount - is a method for activating user account after registration.
func (s *Service) ActivateAccount(ctx context.Context, activationToken string) (user *User, err error) {
	defer mon.Task()(&ctx)(&err)

	parsedActivationToken, err := consoleauth.FromBase64URLString(activationToken)
	if err != nil {
		return nil, ErrTokenInvalid.Wrap(err)
	}

	valid, err := s.tokens.ValidateToken(parsedActivationToken)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if !valid {
		return nil, ErrTokenInvalid.New("incorrect signature")
	}

	claims, err := consoleauth.FromJSON(parsedActivationToken.Payload)
	if err != nil {
		return nil, ErrTokenInvalid.New("JSON decoder: %w", err)
	}

	if time.Now().After(claims.Expiration) {
		return nil, ErrTokenExpiration.New(activationTokenExpiredErrMsg)
	}

	_, err = s.store.Users().GetByEmail(ctx, claims.Email)
	if err == nil {
		return nil, ErrEmailUsed.New(emailUsedErrMsg)
	}

	user, err = s.store.Users().Get(ctx, claims.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	err = s.SetAccountActive(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// SetAccountActive - is a method for setting user account status to Active and sending
// event to hubspot.
func (s *Service) SetAccountActive(ctx context.Context, user *User) (err error) {
	defer mon.Task()(&ctx)(&err)

	if s.config.Captcha.FlagBotsEnabled && user.SignupCaptcha != nil && *user.SignupCaptcha >= s.config.Captcha.ScoreCutoffThreshold {
		minDelay := s.config.Captcha.MinFlagBotDelay
		maxDelay := s.config.Captcha.MaxFlagBotDelay
		rng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		days := rng.Intn(maxDelay-minDelay+1) + minDelay

		err = s.accountFreezeService.DelayedBotFreezeUser(ctx, user.ID, &days)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	activeStatus := Active
	err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		Status: &activeStatus,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "activate account", &user.ID, user.Email)
	s.analytics.TrackAccountVerified(user.ID, user.Email)

	// Send push notification for account activated
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID   // Capture user ID before closure
		notifyEmail := user.Email // Capture email before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Account Activated",
			Body:     fmt.Sprintf("Your account has been successfully activated at %s", timestamp),
			Data:     map[string]string{"event": "account_activated", "email": notifyEmail, "timestamp": timestamp},
			Priority: "high", // level 4
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for account activated",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for account activated",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	return nil
}

// SetActivationCodeAndSignupID - generates and updates a new code for user's signup verification.
// It updates the request ID associated with the signup as well.
func (s *Service) SetActivationCodeAndSignupID(ctx context.Context, user User) (_ User, err error) {
	defer mon.Task()(&ctx)(&err)

	randNum, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return User{}, Error.Wrap(err)
	}
	randNum = randNum.Add(randNum, big.NewInt(100000))
	code := randNum.String()

	requestID := requestid.FromContext(ctx)
	err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		ActivationCode: &code,
		SignupId:       &requestID,
	})
	if err != nil {
		return User{}, Error.Wrap(err)
	}

	user.SignupId = requestID
	user.ActivationCode = code

	return user, nil
}

// ResetPassword - is a method for resetting user password.
func (s *Service) ResetPassword(ctx context.Context, resetPasswordToken, password string, passcode string, recoveryCode string, t time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	secret, err := ResetPasswordSecretFromBase64(resetPasswordToken)
	if err != nil {
		return ErrRecoveryToken.Wrap(err)
	}
	token, err := s.store.ResetPasswordTokens().GetBySecret(ctx, secret)
	if err != nil {
		return ErrRecoveryToken.Wrap(err)
	}

	user, err := s.store.Users().Get(ctx, *token.OwnerID)
	if err != nil {
		return Error.Wrap(err)
	}

	if user.MFAEnabled {
		if recoveryCode != "" {
			found := false
			for _, code := range user.MFARecoveryCodes {
				if code == recoveryCode {
					found = true
					break
				}
			}
			if !found {
				return ErrUnauthorized.Wrap(ErrMFARecoveryCode.New(mfaRecoveryInvalidErrMsg))
			}
		} else if passcode != "" {
			valid, err := ValidateMFAPasscode(passcode, user.MFASecretKey, t)
			if err != nil {
				return ErrValidation.Wrap(ErrMFAPasscode.Wrap(err))
			}
			if !valid {
				return ErrValidation.Wrap(ErrMFAPasscode.New(mfaPasscodeInvalidErrMsg))
			}
		} else {
			return ErrMFAMissing.New(mfaRequiredErrMsg)
		}
	}

	if err := ValidateNewPassword(password); err != nil {
		return ErrValidation.Wrap(err)
	}

	if s.tokens.IsExpired(t, token.CreatedAt) {
		return ErrRecoveryToken.Wrap(ErrTokenExpiration.New(passwordRecoveryTokenIsExpiredErrMsg))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	updateRequest := UpdateUserRequest{
		PasswordHash: hash,
	}

	if user.FailedLoginCount != 0 {
		resetFailedLoginCount := 0
		resetLoginLockoutExpirationPtr := &time.Time{}
		updateRequest.FailedLoginCount = &resetFailedLoginCount
		updateRequest.LoginLockoutExpiration = &resetLoginLockoutExpirationPtr
	}

	err = s.store.Users().Update(ctx, user.ID, updateRequest)
	if err != nil {
		return Error.Wrap(err)
	}

	s.auditLog(ctx, "password reset", &user.ID, user.Email)

	if err = s.store.ResetPasswordTokens().Delete(ctx, token.Secret); err != nil {
		return Error.Wrap(err)
	}

	_, err = s.store.WebappSessions().DeleteAllByUserID(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// RevokeResetPasswordToken - is a method to revoke reset password token.
func (s *Service) RevokeResetPasswordToken(ctx context.Context, resetPasswordToken string) (err error) {
	defer mon.Task()(&ctx)(&err)

	secret, err := ResetPasswordSecretFromBase64(resetPasswordToken)
	if err != nil {
		return Error.Wrap(err)
	}

	return s.store.ResetPasswordTokens().Delete(ctx, secret)
}

// Token authenticates User by credentials and returns session token.
func (s *Service) Token(ctx context.Context, request AuthUser) (response *TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	mon.Counter("login_attempt").Inc(1) //mon:locked

	if s.config.Captcha.Login.Recaptcha.Enabled || s.config.Captcha.Login.Hcaptcha.Enabled {
		valid, _, err := s.loginCaptchaHandler.Verify(ctx, request.CaptchaResponse, request.IP)
		if err != nil {
			mon.Counter("login_user_captcha_error").Inc(1) //mon:locked
			return nil, ErrCaptcha.Wrap(err)
		}
		if !valid {
			mon.Counter("login_user_captcha_unsuccessful").Inc(1) //mon:locked
			return nil, ErrCaptcha.New("captcha validation unsuccessful")
		}
	}

	user, nonActiveUsers, err := s.store.Users().GetByEmailWithUnverified(ctx, request.Email)
	if user == nil {
		shouldProceed := false
		for _, usr := range nonActiveUsers {
			if usr.Status == PendingBotVerification || usr.Status == LegalHold {
				shouldProceed = true
				botAccount := usr
				user = &botAccount
				break
			}
		}

		if !shouldProceed {
			if len(nonActiveUsers) > 0 {
				mon.Counter("login_email_unverified").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed email unverified", nil, request.Email)
			} else {
				mon.Counter("login_email_invalid").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed invalid email", nil, request.Email)
			}
			return nil, ErrLoginCredentials.New(credentialsErrMsg)
		}
	}

	now := time.Now()

	if user.LoginLockoutExpiration.After(now) {
		mon.Counter("login_locked_out").Inc(1) //mon:locked
		s.auditLog(ctx, "login: failed account locked out", &user.ID, request.Email)
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	handleLockAccount := func() error {
		lockoutDuration, err := s.UpdateUsersFailedLoginState(ctx, user)
		if err != nil {
			return err
		}
		if lockoutDuration > 0 {
			address := s.satelliteAddress
			if !strings.HasSuffix(address, "/") {
				address += "/"
			}

			s.mailService.SendRenderedAsync(
				ctx,
				[]post.Address{{Address: user.Email, Name: user.FullName}},
				&LoginLockAccountEmail{
					LockoutDuration:   lockoutDuration,
					ResetPasswordLink: address + "forgot-password",
				},
			)
		}

		mon.Counter("login_failed").Inc(1)                                          //mon:locked
		mon.IntVal("login_user_failed_count").Observe(int64(user.FailedLoginCount)) //mon:locked

		if user.FailedLoginCount == s.config.LoginAttemptsWithoutPenalty {
			mon.Counter("login_lockout_initiated").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed login count reached maximum attempts", &user.ID, request.Email)
		}

		if user.FailedLoginCount > s.config.LoginAttemptsWithoutPenalty {
			mon.Counter("login_lockout_reinitiated").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed locked account", &user.ID, request.Email)
		}

		return nil
	}

	err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(request.Password))
	if err != nil {
		err = handleLockAccount()
		if err != nil {
			return nil, err
		}
		mon.Counter("login_invalid_password").Inc(1) //mon:locked
		s.auditLog(ctx, "login: failed password invalid", &user.ID, user.Email)
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if user.MFAEnabled {
		if request.MFARecoveryCode != "" && request.MFAPasscode != "" {
			mon.Counter("login_mfa_conflict").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed mfa conflict", &user.ID, user.Email)
			return nil, ErrMFAConflict.New(mfaConflictErrMsg)
		}

		if request.MFARecoveryCode != "" {
			found := false
			codeIndex := -1
			for i, code := range user.MFARecoveryCodes {
				if code == request.MFARecoveryCode {
					found = true
					codeIndex = i
					break
				}
			}
			if !found {
				err = handleLockAccount()
				if err != nil {
					return nil, err
				}
				mon.Counter("login_mfa_recovery_failure").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed mfa recovery", &user.ID, user.Email)
				return nil, ErrMFARecoveryCode.New(mfaRecoveryInvalidErrMsg)
			}

			mon.Counter("login_mfa_recovery_success").Inc(1) //mon:locked

			user.MFARecoveryCodes = append(user.MFARecoveryCodes[:codeIndex], user.MFARecoveryCodes[codeIndex+1:]...)

			err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
				MFARecoveryCodes: &user.MFARecoveryCodes,
			})
			if err != nil {
				return nil, err
			}
		} else if request.MFAPasscode != "" {
			valid, err := ValidateMFAPasscode(request.MFAPasscode, user.MFASecretKey, now)
			if err != nil {
				err = handleLockAccount()
				if err != nil {
					return nil, err
				}

				return nil, ErrMFAPasscode.Wrap(err)
			}
			if !valid {
				err = handleLockAccount()
				if err != nil {
					return nil, err
				}
				mon.Counter("login_mfa_passcode_failure").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed mfa passcode invalid", &user.ID, user.Email)
				return nil, ErrMFAPasscode.New(mfaPasscodeInvalidErrMsg)
			}
			mon.Counter("login_mfa_passcode_success").Inc(1) //mon:locked
		} else {
			mon.Counter("login_mfa_missing").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed mfa missing", &user.ID, user.Email)
			return nil, ErrMFAMissing.New(mfaRequiredErrMsg)
		}
	}

	if user.FailedLoginCount != 0 {
		err = s.ResetAccountLock(ctx, user)
		if err != nil {
			return nil, err
		}
	}

	if user.Status == PendingBotVerification || user.Status == LegalHold {
		return nil, ErrLoginRestricted.New("")
	}

	var customDurationPtr *time.Duration
	if request.RememberForOneWeek {
		weekDuration := 7 * 24 * time.Hour
		customDurationPtr = &weekDuration
	}
	response, err = s.GenerateSessionToken(ctx, user.ID, user.Email, request.IP, request.UserAgent, customDurationPtr)
	if err != nil {
		return nil, err
	}

	// Send push notification for successful login
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		ipAddress := request.IP
		if ipAddress == "" {
			ipAddress = "0.0.0.0"
		}
		location := "Unknown Location"
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Login Successful",
			Body:     fmt.Sprintf("You have successfully logged in at %s from %s (%s)", timestamp, location, ipAddress),
			Data:     map[string]string{"event": "logged_in_successfully", "timestamp": timestamp, "ip_address": ipAddress, "location": location},
			Priority: "high", // level 4
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for login",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for login",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	mon.Counter("login_success").Inc(1) //mon:locked

	return response, nil
}

// TokenWithoutPassword authenticates User without credentials and returns session token.
func (s *Service) TokenWithoutPassword(ctx context.Context, request AuthWithoutPassword) (response *TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	mon.Counter("login_attempt").Inc(1) //mon:locked

	user, err := s.store.Users().GetByEmail(ctx, request.Email)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	if user.LoginLockoutExpiration.After(now) {
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if user.Status == PendingBotVerification || user.Status == LegalHold {
		return nil, ErrLoginRestricted.New("")
	}

	if user.MFAEnabled {
		if request.MFARecoveryCode != "" && request.MFAPasscode != "" {
			mon.Counter("login_mfa_conflict").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed mfa conflict", &user.ID, user.Email)
			return nil, ErrMFAConflict.New(mfaConflictErrMsg)
		}

		handleLockAccount := func() error {
			lockoutDuration, err := s.UpdateUsersFailedLoginState(ctx, user)
			if err != nil {
				return err
			}
			if lockoutDuration > 0 {
				address := s.satelliteAddress
				if !strings.HasSuffix(address, "/") {
					address += "/"
				}

				s.mailService.SendRenderedAsync(
					ctx,
					[]post.Address{{Address: user.Email, Name: user.FullName}},
					&LoginLockAccountEmail{
						LockoutDuration:   lockoutDuration,
						ResetPasswordLink: address + "forgot-password",
					},
				)
			}

			mon.Counter("login_failed").Inc(1)                                          //mon:locked
			mon.IntVal("login_user_failed_count").Observe(int64(user.FailedLoginCount)) //mon:locked

			if user.FailedLoginCount == s.config.LoginAttemptsWithoutPenalty {
				mon.Counter("login_lockout_initiated").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed login count reached maximum attempts", &user.ID, request.Email)
			}

			if user.FailedLoginCount > s.config.LoginAttemptsWithoutPenalty {
				mon.Counter("login_lockout_reinitiated").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed locked account", &user.ID, request.Email)
			}

			return nil
		}

		if request.MFARecoveryCode != "" {
			found := false
			codeIndex := -1

			for i, code := range user.MFARecoveryCodes {
				if code == request.MFARecoveryCode {
					found = true
					codeIndex = i
					break
				}
			}
			if !found {
				err = handleLockAccount()
				if err != nil {
					return nil, err
				}
				mon.Counter("login_mfa_recovery_failure").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed mfa recovery", &user.ID, user.Email)
				return nil, ErrMFARecoveryCode.New(mfaRecoveryInvalidErrMsg)
			}

			mon.Counter("login_mfa_recovery_success").Inc(1) //mon:locked

			user.MFARecoveryCodes = append(user.MFARecoveryCodes[:codeIndex], user.MFARecoveryCodes[codeIndex+1:]...)

			err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
				MFARecoveryCodes: &user.MFARecoveryCodes,
			})
			if err != nil {
				return nil, err
			}
		} else if request.MFAPasscode != "" {

			valid, err := ValidateMFAPasscode(request.MFAPasscode, user.MFASecretKey, now)
			if err != nil {
				err = handleLockAccount()
				if err != nil {
					return nil, err
				}

				return nil, ErrMFAPasscode.Wrap(err)
			}
			if !valid {
				err = handleLockAccount()
				if err != nil {
					return nil, err
				}
				mon.Counter("login_mfa_passcode_failure").Inc(1) //mon:locked
				s.auditLog(ctx, "login: failed mfa passcode invalid", &user.ID, user.Email)
				return nil, ErrMFAPasscode.New(mfaPasscodeInvalidErrMsg)
			}
			mon.Counter("login_mfa_passcode_success").Inc(1) //mon:locked
		} else {
			mon.Counter("login_mfa_missing").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed mfa missing", &user.ID, user.Email)
			return nil, ErrMFAMissing.New(mfaRequiredErrMsg)
		}
	}

	response, err = s.GenerateSessionToken(ctx, user.ID, user.Email, request.IP, request.UserAgent, nil)
	if err != nil {
		return nil, err
	}

	// Send push notification for successful login (MFA flow)
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		ipAddress := request.IP
		if ipAddress == "" {
			ipAddress = "0.0.0.0"
		}
		location := "Unknown Location"
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Login Successful",
			Body:     fmt.Sprintf("You have successfully logged in at %s from %s (%s)", timestamp, location, ipAddress),
			Data:     map[string]string{"event": "logged_in_successfully", "timestamp": timestamp, "ip_address": ipAddress, "location": location},
			Priority: "high", // level 4
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for login",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for login",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return response, nil
}

func (s *Service) Token_google(ctx context.Context, request AuthUser) (response *TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	mon.Counter("login_attempt").Inc(1) //mon:locked

	user, unverified, err := s.store.Users().GetByEmailWithUnverified_google(ctx, request.Email)

	if user == nil {
		if len(unverified) > 0 {
			mon.Counter("login_email_unverified").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed email unverified", nil, request.Email)
		} else {
			mon.Counter("login_email_invalid").Inc(1) //mon:locked
			s.auditLog(ctx, "login: failed invalid email", nil, request.Email)
		}
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	now := time.Now()

	if user.LoginLockoutExpiration.After(now) {
		mon.Counter("login_locked_out").Inc(1) //mon:locked
		s.auditLog(ctx, "login: failed account locked out", &user.ID, request.Email)
		return nil, ErrLoginCredentials.New(credentialsErrMsg)
	}

	if user.FailedLoginCount != 0 {
		user.FailedLoginCount = 0
		loginLockoutExpirationPtr := &time.Time{}
		err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
			FailedLoginCount:       &user.FailedLoginCount,
			LoginLockoutExpiration: &loginLockoutExpirationPtr,
		})
		if err != nil {
			return nil, err
		}
	}

	customeExpiry := time.Duration(7*24) * time.Hour

	response, err = s.GenerateSessionToken(ctx, user.ID, user.Email, request.IP, request.UserAgent, &customeExpiry)
	if err != nil {
		return nil, err
	}

	// Send push notification for successful login (Google OAuth)
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		ipAddress := request.IP
		if ipAddress == "" {
			ipAddress = "0.0.0.0"
		}
		location := "Unknown Location"
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Login Successful",
			Body:     fmt.Sprintf("You have successfully logged in at %s from %s (%s)", timestamp, location, ipAddress),
			Data:     map[string]string{"event": "logged_in_successfully", "timestamp": timestamp, "ip_address": ipAddress, "location": location},
			Priority: "high", // level 4
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for Google login",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for Google login",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	mon.Counter("login_success").Inc(1) //mon:locked

	return response, nil
}

// TokenByAPIKey authenticates User by API Key and returns session token.
func (s *Service) TokenByAPIKey(ctx context.Context, userAgent string, ip string, apiKey string) (response *TokenInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	userID, _, err := s.restKeys.GetUserAndExpirationFromKey(ctx, apiKey)
	if err != nil {
		return nil, ErrUnauthorized.New(apiKeyCredentialsErrMsg)
	}

	user, err := s.store.Users().Get(ctx, userID)
	if err != nil {
		return nil, Error.New(failedToRetrieveUserErrMsg)
	}

	response, err = s.GenerateSessionToken(ctx, user.ID, user.Email, ip, userAgent, nil)
	if err != nil {
		return nil, Error.New(generateSessionTokenErrMsg)
	}

	return response, nil
}

// UpdateUsersFailedLoginState updates User's failed login state.
func (s *Service) UpdateUsersFailedLoginState(ctx context.Context, user *User) (lockoutDuration time.Duration, err error) {
	defer mon.Task()(&ctx)(&err)

	var failedLoginPenalty *float64
	if user.FailedLoginCount >= s.config.LoginAttemptsWithoutPenalty-1 {
		lockoutDuration = time.Duration(math.Pow(s.config.FailedLoginPenalty, float64(user.FailedLoginCount-1))) * time.Minute
		failedLoginPenalty = &s.config.FailedLoginPenalty
	}

	return lockoutDuration, s.store.Users().UpdateFailedLoginCountAndExpiration(ctx, failedLoginPenalty, user.ID)
}

// GetLoginAttemptsWithoutPenalty returns LoginAttemptsWithoutPenalty config value.
func (s *Service) GetLoginAttemptsWithoutPenalty() int {
	return s.config.LoginAttemptsWithoutPenalty
}

// ResetAccountLock resets a user's failed login count and lockout duration.
func (s *Service) ResetAccountLock(ctx context.Context, user *User) (err error) {
	defer mon.Task()(&ctx)(&err)

	user.FailedLoginCount = 0
	loginLockoutExpirationPtr := &time.Time{}
	return s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		FailedLoginCount:       &user.FailedLoginCount,
		LoginLockoutExpiration: &loginLockoutExpirationPtr,
	})
}

// GetUser returns User by id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (u *User, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.store.Users().Get(ctx, id)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return user, nil
}

// GenGetUser returns ResponseUser by request context for generated api.
func (s *Service) GenGetUser(ctx context.Context) (*ResponseUser, api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get user")
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	respUser := &ResponseUser{
		ID:                   user.ID,
		FullName:             user.FullName,
		ShortName:            user.ShortName,
		Email:                user.Email,
		UserAgent:            user.UserAgent,
		ProjectLimit:         user.ProjectLimit,
		IsProfessional:       user.IsProfessional,
		Position:             user.Position,
		CompanyName:          user.CompanyName,
		EmployeeCount:        user.EmployeeCount,
		HaveSalesContact:     user.HaveSalesContact,
		PaidTier:             user.PaidTier,
		MFAEnabled:           user.MFAEnabled,
		MFARecoveryCodeCount: len(user.MFARecoveryCodes),
	}

	return respUser, api.HTTPError{}
}

// GetUserID returns the User ID from the session.
func (s *Service) GetUserID(ctx context.Context) (id uuid.UUID, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get user ID")
	if err != nil {
		return uuid.UUID{}, Error.Wrap(err)
	}
	return user.ID, nil
}

// GetUserByEmailWithUnverified returns Users by email.
func (s *Service) GetUserByEmailWithUnverified(ctx context.Context, email string) (verified *User, unverified []User, err error) {
	defer mon.Task()(&ctx)(&err)

	verified, unverified, err = s.store.Users().GetByEmailWithUnverified(ctx, email)
	if err != nil {
		return verified, unverified, err
	}

	if verified == nil && len(unverified) == 0 {
		err = ErrEmailNotFound.New(emailNotFoundErrMsg)
	}

	return verified, unverified, err
}

func (s *Service) GetUserByEmailWithUnverified_google(ctx context.Context, email string) (verified *User, unverified []User, err error) {
	defer mon.Task()(&ctx)(&err)

	if email == "" {
		return nil, nil, ErrEmailNotFound.New("email is empty")
	}

	verified, unverified, err = s.store.Users().GetByEmailWithUnverified_google(ctx, email)
	if err != nil {
		return verified, unverified, err
	}

	if verified == nil && len(unverified) == 0 {
		err = ErrEmailNotFound.New(emailNotFoundErrMsg)
	}

	return verified, unverified, err
}

// GetUserHasVarPartner returns whether the user in context is associated with a VAR partner.
func (s *Service) GetUserHasVarPartner(ctx context.Context) (has bool, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get user has VAR partner")
	if err != nil {
		return false, Error.Wrap(err)
	}

	if _, has = s.varPartners[string(user.UserAgent)]; has {
		return has, nil
	}
	return false, nil
}

// UpdateAccount updates User.
func (s *Service) UpdateAccount(ctx context.Context, fullName string, shortName string) (err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "update account")
	if err != nil {
		return Error.Wrap(err)
	}

	// validate fullName
	err = ValidateFullName(fullName)
	if err != nil {
		return ErrValidation.Wrap(err)
	}

	user.FullName = fullName
	user.ShortName = shortName
	shortNamePtr := &user.ShortName
	err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		FullName:  &user.FullName,
		ShortName: &shortNamePtr,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	// Send push notification for name change
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		oldName := ""
		if user.FullName != fullName {
			oldName = user.FullName
		}
		notification := pushnotifications.Notification{
			Title: "Name Updated",
			Body: fmt.Sprintf("Your account name has been successfully changed%s to %s", func() string {
				if oldName != "" {
					return fmt.Sprintf(" from %s", oldName)
				}
				return ""
			}(), fullName),
			Data:     map[string]string{"event": "name_changed_successfully", "old_name": oldName, "new_name": fullName},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for name change",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for name change",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return nil
}

// UpdateAccountInfo updates User's basic infor'
func (s *Service) UpdateAccountInfo(ctx context.Context, updateinfo *UpdateUserSocialMediaLinks) (err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "update account")
	if err != nil {
		return Error.Wrap(err)
	}

	err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		SocialLinkedin: updateinfo.SocialLinkedin,
		SocialTwitter:  updateinfo.SocialTwitter,
		SocialFacebook: updateinfo.SocialFacebook,
		SocialGithub:   updateinfo.SocialGithub,
		WalletID:       updateinfo.WalletID,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	// Send push notification for profile update
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Profile Updated",
			Body:     fmt.Sprintf("Your profile has been successfully updated at %s", timestamp),
			Data:     map[string]string{"event": "profile_updated", "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for profile update",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for profile update",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return nil
}

// SetupAccount completes User's information.
func (s *Service) SetupAccount(ctx context.Context, requestData SetUpAccountRequest) (err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "update account")
	if err != nil {
		return Error.Wrap(err)
	}

	// validate fullName
	err = ValidateFullName(requestData.FullName)
	if err != nil {
		return ErrValidation.Wrap(err)
	}

	err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		FullName:         &requestData.FullName,
		IsProfessional:   &requestData.IsProfessional,
		HaveSalesContact: &requestData.HaveSalesContact,
		Position:         requestData.Position,
		CompanyName:      requestData.CompanyName,
		EmployeeCount:    requestData.EmployeeCount,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	onboardingFields := analytics.TrackOnboardingInfoFields{
		ID:       user.ID,
		FullName: requestData.FullName,
		Email:    user.Email,
	}

	if requestData.StorageUseCase != nil {
		onboardingFields.StorageUseCase = *requestData.StorageUseCase
	}

	if requestData.IsProfessional {
		onboardingFields.Type = analytics.Professional
		onboardingFields.HaveSalesContact = requestData.HaveSalesContact
		if requestData.CompanyName != nil {
			onboardingFields.CompanyName = *requestData.CompanyName
		}
		if requestData.EmployeeCount != nil {
			onboardingFields.EmployeeCount = *requestData.EmployeeCount
		}
		if requestData.StorageNeeds != nil {
			onboardingFields.StorageNeeds = *requestData.StorageNeeds
		}
		if requestData.Position != nil {
			onboardingFields.JobTitle = *requestData.Position
		}
		if requestData.FunctionalArea != nil {
			onboardingFields.FunctionalArea = *requestData.FunctionalArea
		}
	} else {
		onboardingFields.Type = analytics.Personal
	}
	s.analytics.TrackUserOnboardingInfo(onboardingFields)

	return nil
}

func (s *Service) DeleteAccountRequest(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "delete account request")
	if err != nil {
		return Error.Wrap(err)
	}

	deleteAt := time.Now().AddDate(0, 1, 0)

	err = s.store.Users().CreateDeleteRequest(ctx, user.ID, deleteAt)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// ChangePassword updates password for a given user.
func (s *Service) ChangePassword(ctx context.Context, pass, newPass string) (err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "change password")
	if err != nil {
		return Error.Wrap(err)
	}

	err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(pass))
	if err != nil {
		return ErrChangePassword.New(changePasswordErrMsg)
	}

	if err := ValidateNewPassword(newPass); err != nil {
		return ErrValidation.Wrap(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), s.config.PasswordCost)
	if err != nil {
		return Error.Wrap(err)
	}

	user.PasswordHash = hash
	err = s.store.Users().Update(ctx, user.ID, UpdateUserRequest{
		PasswordHash: hash,
	})
	if err != nil {
		return Error.Wrap(err)
	}

	resetPasswordToken, err := s.store.ResetPasswordTokens().GetByOwnerID(ctx, user.ID)
	if err == nil {
		err := s.store.ResetPasswordTokens().Delete(ctx, resetPasswordToken.Secret)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	_, err = s.store.WebappSessions().DeleteAllByUserID(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	// Send push notification for password changed successfully
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		timestamp := time.Now().Format(time.RFC3339)
		ipAddress := extractIPFromRequest(GetRequest(ctx))
		location := "Unknown Location" // Placeholder
		notification := pushnotifications.Notification{
			Title:    "Password Changed",
			Body:     fmt.Sprintf("Your password has been successfully changed at %s from %s (%s)", timestamp, location, ipAddress),
			Data:     map[string]string{"event": "password_changed_successfully", "timestamp": timestamp, "ip_address": ipAddress, "location": location},
			Priority: "high", // level 4
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for password changed",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for password changed",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return nil
}

// GetProject is a method for querying project by internal or public ID.
func (s *Service) GetProject(ctx context.Context, projectID uuid.UUID) (p *Project, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get project", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	p = isMember.project

	return
}

// GetProjectNoAuth is a method for querying project by ID or public ID.
// This is for internal use only as it ignores whether a user is authorized to perform this action.
// If authorization checking is required, use GetProject.
func (s *Service) GetProjectNoAuth(ctx context.Context, projectID uuid.UUID) (p *Project, err error) {
	defer mon.Task()(&ctx)(&err)

	p, err = s.store.Projects().GetByPublicID(ctx, projectID)
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			p, err = s.store.Projects().Get(ctx, projectID)
			if err != nil {
				return nil, Error.Wrap(err)
			}
		} else {
			return nil, Error.Wrap(err)
		}
	}

	return p, nil
}

// GetSalt is a method for querying project salt by id.
// id may be project.ID or project.PublicID.
func (s *Service) GetSalt(ctx context.Context, projectID uuid.UUID) (salt []byte, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get project salt", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return s.store.Projects().GetSalt(ctx, isMember.project.ID)
}

// EmissionImpactResponse represents emission impact response to be returned to client.
type EmissionImpactResponse struct {
	StorjImpact       float64 `json:"storjImpact"`
	HyperscalerImpact float64 `json:"hyperscalerImpact"`
	SavedTrees        int64   `json:"savedTrees"`
}

// GetEmissionImpact is a method for querying project emission impact by id.
func (s *Service) GetEmissionImpact(ctx context.Context, projectID uuid.UUID) (*EmissionImpactResponse, error) {
	var err error
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get project emission impact", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrNoMembership.Wrap(err)
	}

	storageUsed, err := s.projectUsage.GetProjectStorageTotals(ctx, isMember.project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	now := s.nowFn()
	period := now.Sub(isMember.project.CreatedAt)
	dataInTB := memory.Size(storageUsed).TB()

	impact, err := s.emission.CalculateImpact(&emission.CalculationInput{
		AmountOfDataInTB: dataInTB,
		Duration:         period,
		IsTBDuration:     false,
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	savedValue := impact.EstimatedKgCO2eHyperscaler - impact.EstimatedKgCO2eStorj
	if savedValue < 0 {
		savedValue = 0
	}

	savedTrees := s.emission.CalculateSavedTrees(savedValue)

	return &EmissionImpactResponse{
		StorjImpact:       impact.EstimatedKgCO2eStorj,
		HyperscalerImpact: impact.EstimatedKgCO2eHyperscaler,
		SavedTrees:        savedTrees,
	}, nil
}

// GetProjectConfig is a method for querying project config.
func (s *Service) GetProjectConfig(ctx context.Context, projectID uuid.UUID) (*ProjectConfig, error) {
	var err error
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get project config", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrNoMembership.Wrap(err)
	}

	versioningUIEnabled := true
	if !s.versioningConfig.UseBucketLevelObjectVersioning {
		_, versioningUIEnabled = s.versioningConfig.projectMap[isMember.project.ID]
	}

	return &ProjectConfig{
		VersioningUIEnabled: versioningUIEnabled,
	}, nil
}

// GetUsersProjects is a method for querying all projects.
func (s *Service) GetUsersProjects(ctx context.Context) (ps []Project, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get users projects")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	ps, err = s.store.Projects().GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for i, project := range ps {
		project.StorageUsed, project.BandwidthUsed, err = s.getStorageAndBandwidthUse(ctx, project.ID)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		ps[i] = project
	}

	return
}

// GetMinimalProject returns a ProjectInfo copy of a project.
func (s *Service) GetMinimalProject(project *Project) ProjectInfo {
	info := ProjectInfo{
		ID:            project.PublicID,
		Name:          project.Name,
		OwnerID:       project.OwnerID,
		Description:   project.Description,
		MemberCount:   project.MemberCount,
		CreatedAt:     project.CreatedAt,
		StorageUsed:   project.StorageUsed,
		BandwidthUsed: project.BandwidthUsed,
		Versioning:    project.DefaultVersioning,
	}

	// if edgeURLs, ok := s.config.PlacementEdgeURLOverrides.Get(project.DefaultPlacement); ok {
	// 	info.EdgeURLOverrides = &edgeURLs
	// }

	return info
}

// GenGetUsersProjects is a method for querying all projects for generated api.
func (s *Service) GenGetUsersProjects(ctx context.Context) (ps []Project, httpErr api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get users projects")
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	ps, err = s.store.Projects().GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	return
}

// GetUsersOwnedProjectsPage is a method for querying paged projects.
func (s *Service) GetUsersOwnedProjectsPage(ctx context.Context, cursor ProjectsCursor) (_ ProjectsPage, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "get user's owned projects page")
	if err != nil {
		return ProjectsPage{}, Error.Wrap(err)
	}

	projects, err := s.store.Projects().ListByOwnerID(ctx, user.ID, cursor)
	if err != nil {
		return ProjectsPage{}, Error.Wrap(err)
	}

	return projects, nil
}

// CreateProject is a method for creating new project.
func (s *Service) CreateProject(ctx context.Context, projectInfo UpsertProjectInfo) (p *Project, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "create project")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if user.Status == PendingBotVerification {
		return nil, ErrBotUser.New(contactSupportErrMsg)
	}

	currentProjectCount, err := s.checkProjectLimit(ctx, user.ID)
	if err != nil {
		s.analytics.TrackProjectLimitError(user.ID, user.Email)
		return nil, ErrProjLimit.Wrap(err)
	}

	passesNameCheck, err := s.checkProjectName(ctx, projectInfo, user.ID)
	if err != nil || !passesNameCheck {
		return nil, ErrProjName.Wrap(err)
	}

	newProjectLimits, err := s.getUserProjectLimits(ctx, user.ID)
	if err != nil {
		return nil, ErrProjLimit.Wrap(err)
	}

	var projectID uuid.UUID
	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) error {
		storageLimit := memory.Size(newProjectLimits.Storage)
		bandwidthLimit := memory.Size(newProjectLimits.Bandwidth)
		p, err = tx.Projects().Insert(ctx,
			&Project{
				Description:             projectInfo.Description,
				Name:                    projectInfo.Name,
				OwnerID:                 user.ID,
				UserAgent:               user.UserAgent,
				StorageLimit:            &storageLimit,
				BandwidthLimit:          &bandwidthLimit,
				SegmentLimit:            &newProjectLimits.Segment,
				DefaultPlacement:        user.DefaultPlacement,
				PrevDaysUntilExpiration: 0,
			},
		)
		if err != nil {
			return Error.Wrap(err)
		}

		limit, err := tx.Users().GetProjectLimit(ctx, user.ID)
		if err != nil {
			return err
		}

		projects, err := tx.Projects().GetOwn(ctx, user.ID)
		if err != nil {
			return err
		}

		// We check again for project name duplication and whether the project limit
		// has been exceeded in case a parallel project creation transaction created
		// a project at the same time as this one.
		var numBefore int
		for _, other := range projects {
			if other.CreatedAt.Before(p.CreatedAt) || (other.CreatedAt.Equal(p.CreatedAt) && other.ID.Less(p.ID)) {
				if other.Name == p.Name {
					return errs.Combine(ErrProjName.New(projNameErrMsg), tx.Projects().Delete(ctx, p.ID))
				}
				numBefore++
			}
		}
		if numBefore >= limit {
			s.analytics.TrackProjectLimitError(user.ID, user.Email)
			// Send push notification for project limit error (before returning error)
			go func() {
				// Use background context to avoid cancellation when HTTP request completes
				notifyCtx := context.Background()
				notifyUserID := user.ID // Capture user ID before closure
				timestamp := time.Now().Format(time.RFC3339)
				notification := pushnotifications.Notification{
					Title:    "Project Limit Exceeded",
					Body:     fmt.Sprintf("Project limit error: You have reached your project limit at %s", timestamp),
					Data:     map[string]string{"event": "project_limit_error", "limit_type": "project", "timestamp": timestamp},
					Priority: "high", // level 4
				}
				if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
					s.log.Warn("Failed to send push notification for project limit error",
						zap.Stringer("user_id", notifyUserID),
						zap.String("email", user.Email),
						zap.Error(err))
				} else {
					s.log.Debug("Successfully sent push notification for project limit error",
						zap.Stringer("user_id", notifyUserID),
						zap.String("email", user.Email))
				}
			}()
			return errs.Combine(ErrProjLimit.New(projLimitErrMsg), tx.Projects().Delete(ctx, p.ID))
		}

		_, err = tx.ProjectMembers().Insert(ctx, user.ID, p.ID)
		if err != nil {
			return Error.Wrap(err)
		}

		projectID = p.ID

		return nil
	})

	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.analytics.TrackProjectCreated(user.ID, user.Email, projectID, currentProjectCount+1)

	// Send push notification for project created
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		projectName := p.Name   // Capture project name before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Project Created",
			Body:     fmt.Sprintf("A new project '%s' has been created at %s", projectName, timestamp),
			Data:     map[string]string{"event": "project_created", "project_name": projectName, "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for project created",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for project created",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return p, nil
}

// GenCreateProject is a method for creating new project for generated api.
func (s *Service) GenCreateProject(ctx context.Context, projectInfo UpsertProjectInfo) (p *Project, httpError api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	p, err = s.CreateProject(ctx, projectInfo)
	if err != nil {
		status := http.StatusInternalServerError
		if _, ctxErr := GetUser(ctx); ctxErr != nil {
			status = http.StatusUnauthorized
		}
		return nil, api.HTTPError{
			Status: status,
			Err:    err,
		}
	}

	return p, httpError
}

// DeleteProject is a method for deleting project by id.
func (s *Service) DeleteProject(ctx context.Context, projectID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "delete project", zap.String("projectID", projectID.String()))
	if err != nil {
		return Error.Wrap(err)
	}

	_, p, err := s.isProjectOwner(ctx, user.ID, projectID)
	if err != nil {
		return Error.Wrap(err)
	}

	projectName := p.Name // Save project name before deletion

	err = s.checkProjectCanBeDeleted(ctx, user, projectID)
	if err != nil {
		return Error.Wrap(err)
	}

	err = s.store.Projects().Delete(ctx, projectID)
	if err != nil {
		return Error.Wrap(err)
	}

	// Send push notification for project deleted
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID // Capture user ID before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Project Deleted",
			Body:     fmt.Sprintf("Project '%s' has been deleted at %s", projectName, timestamp),
			Data:     map[string]string{"event": "project_deleted", "project_name": projectName, "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for project deleted",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for project deleted",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", user.Email))
		}
	}()

	return nil
}

// GenDeleteProject is a method for deleting project by id for generated API.
func (s *Service) GenDeleteProject(ctx context.Context, projectID uuid.UUID) (httpError api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "delete project", zap.String("projectID", projectID.String()))
	if err != nil {
		return api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	_, p, err := s.isProjectOwner(ctx, user.ID, projectID)
	if err != nil {
		status := http.StatusInternalServerError
		if ErrUnauthorized.Has(err) {
			status = http.StatusUnauthorized
		}
		return api.HTTPError{
			Status: status,
			Err:    Error.Wrap(err),
		}
	}

	projectID = p.ID

	err = s.checkProjectCanBeDeleted(ctx, user, projectID)
	if err != nil {
		return api.HTTPError{
			Status: http.StatusConflict,
			Err:    Error.Wrap(err),
		}
	}

	err = s.store.Projects().Delete(ctx, projectID)
	if err != nil {
		return api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	return httpError
}

// UpdateProject is a method for updating project name and description by id.
// projectID here may be project.PublicID or project.ID.

// boris --userID added as parameter.
func (s *Service) UpdatingProject(ctx context.Context, userID, projectID uuid.UUID, updatedProject UpsertProjectInfo) (p *Project, err error) {
	defer mon.Task()(&ctx)(&err)

	err = ValidateNameAndDescription(updatedProject.Name, updatedProject.Description)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, project, err := s.isProjectOwner(ctx, userID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if updatedProject.Name != project.Name {
		passesNameCheck, err := s.checkProjectName(ctx, updatedProject, userID)
		if err != nil || !passesNameCheck {
			return nil, ErrProjName.Wrap(err)
		}
	}
	project.Name = updatedProject.Name
	project.Description = updatedProject.Description
	//boris
	project.CreatedAt = updatedProject.CreatedAt
	project.PrevDaysUntilExpiration = updatedProject.PrevDaysUntilExpiration

	if project.BandwidthLimit != nil && *project.BandwidthLimit == 0 {
		return nil, Error.New("current bandwidth limit for project is set to 0 (updating disabled)")
	}
	if project.StorageLimit != nil && *project.StorageLimit == 0 {
		return nil, Error.New("current storage limit for project is set to 0 (updating disabled)")
	}
	if updatedProject.StorageLimit <= 0 || updatedProject.BandwidthLimit <= 0 {
		return nil, Error.New("project limits must be greater than 0")
	}

	if updatedProject.StorageLimit > s.config.UsageLimits.Storage.Paid && updatedProject.StorageLimit > *project.StorageLimit {
		return nil, Error.New("specified storage limit exceeds allowed maximum for current tier")
	}

	if updatedProject.BandwidthLimit > s.config.UsageLimits.Bandwidth.Paid && updatedProject.BandwidthLimit > *project.BandwidthLimit {
		return nil, Error.New("specified bandwidth limit exceeds allowed maximum for current tier")
	}

	storageUsed, err := s.projectUsage.GetProjectStorageTotals(ctx, project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if updatedProject.StorageLimit.Int64() < storageUsed {
		return nil, Error.New("cannot set storage limit below current usage")
	}

	bandwidthUsed, err := s.projectUsage.GetProjectBandwidthTotals(ctx, project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	if updatedProject.BandwidthLimit.Int64() < bandwidthUsed {
		return nil, Error.New("cannot set bandwidth limit below current usage")
	}
	/*
		The purpose of userSpecifiedBandwidthLimit and userSpecifiedStorageLimit is to know if a user has set a bandwidth
		or storage limit in the UI (to ensure their limits are not unintentionally modified by the satellite admin),
		the BandwidthLimit and StorageLimit is still used for verifying limits during uploads and downloads.
	*/
	if project.StorageLimit != nil && updatedProject.StorageLimit != *project.StorageLimit {
		project.UserSpecifiedStorageLimit = new(memory.Size)
		*project.UserSpecifiedStorageLimit = updatedProject.StorageLimit
	}
	if project.BandwidthLimit != nil && updatedProject.BandwidthLimit != *project.BandwidthLimit {
		project.UserSpecifiedBandwidthLimit = new(memory.Size)
		*project.UserSpecifiedBandwidthLimit = updatedProject.BandwidthLimit
	}

	oldStorageLimit := project.StorageLimit
	oldBandwidthLimit := project.BandwidthLimit
	project.StorageLimit = new(memory.Size)
	*project.StorageLimit = updatedProject.StorageLimit
	project.BandwidthLimit = new(memory.Size)
	*project.BandwidthLimit = updatedProject.BandwidthLimit

	err = s.store.Projects().Update(ctx, project)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// Send push notifications for project limit updates
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := userID      // Capture userID before closure
		projectName := project.Name // Capture project name before closure
		timestamp := time.Now().Format(time.RFC3339)
		if oldStorageLimit != nil && *oldStorageLimit != updatedProject.StorageLimit {
			notification := pushnotifications.Notification{
				Title:    "Storage Limit Updated",
				Body:     fmt.Sprintf("Storage limit for project %s has been updated from %s to %s at %s", projectName, oldStorageLimit.String(), updatedProject.StorageLimit.String(), timestamp),
				Data:     map[string]string{"event": "project_storage_limit_updated", "project_name": projectName, "old_limit": oldStorageLimit.String(), "new_limit": updatedProject.StorageLimit.String(), "timestamp": timestamp},
				Priority: "normal", // level 3
			}
			if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
				s.log.Warn("Failed to send push notification for project storage limit updated",
					zap.Stringer("user_id", notifyUserID),
					zap.Error(err))
			} else {
				s.log.Debug("Successfully sent push notification for project storage limit updated",
					zap.Stringer("user_id", notifyUserID))
			}
		}
		if oldBandwidthLimit != nil && *oldBandwidthLimit != updatedProject.BandwidthLimit {
			notification := pushnotifications.Notification{
				Title:    "Bandwidth Limit Updated",
				Body:     fmt.Sprintf("Bandwidth limit for project %s has been updated from %s to %s at %s", projectName, oldBandwidthLimit.String(), updatedProject.BandwidthLimit.String(), timestamp),
				Data:     map[string]string{"event": "project_bandwidth_limit_updated", "project_name": projectName, "old_limit": oldBandwidthLimit.String(), "new_limit": updatedProject.BandwidthLimit.String(), "timestamp": timestamp},
				Priority: "normal", // level 3
			}
			if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
				s.log.Warn("Failed to send push notification for project bandwidth limit updated",
					zap.Stringer("user_id", notifyUserID),
					zap.Error(err))
			} else {
				s.log.Debug("Successfully sent push notification for project bandwidth limit updated",
					zap.Stringer("user_id", notifyUserID))
			}
		}
	}()

	return project, nil
}

func (s *Service) UpdateProject(ctx context.Context, projectID uuid.UUID, updatedProject UpsertProjectInfo) (p *Project, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "update project name and description", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	err = ValidateNameAndDescription(updatedProject.Name, updatedProject.Description)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, project, err := s.isProjectOwner(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if updatedProject.Name != project.Name {
		passesNameCheck, err := s.checkProjectName(ctx, updatedProject, user.ID)
		if err != nil || !passesNameCheck {
			return nil, ErrProjName.Wrap(err)
		}
	}
	oldName := project.Name
	project.Name = updatedProject.Name
	project.Description = updatedProject.Description
	//boris
	project.CreatedAt = updatedProject.CreatedAt
	project.PrevDaysUntilExpiration = updatedProject.PrevDaysUntilExpiration

	// Send push notifications for project name/description updates
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID   // Capture user ID before closure
		notifyEmail := user.Email // Capture email before closure
		timestamp := time.Now().Format(time.RFC3339)
		if oldName != updatedProject.Name {
			notification := pushnotifications.Notification{
				Title:    "Project Name Updated",
				Body:     fmt.Sprintf("Project name has been updated from %s to %s at %s", oldName, updatedProject.Name, timestamp),
				Data:     map[string]string{"event": "project_name_updated", "old_name": oldName, "new_name": updatedProject.Name, "timestamp": timestamp},
				Priority: "normal", // level 2
			}
			if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
				s.log.Warn("Failed to send push notification for project name updated",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail),
					zap.Error(err))
			} else {
				s.log.Debug("Successfully sent push notification for project name updated",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail))
			}
		}
		if project.Description != updatedProject.Description {
			notification := pushnotifications.Notification{
				Title:    "Project Description Updated",
				Body:     fmt.Sprintf("Project description for %s has been updated at %s", updatedProject.Name, timestamp),
				Data:     map[string]string{"event": "project_description_updated", "project_name": updatedProject.Name, "timestamp": timestamp},
				Priority: "normal", // level 2
			}
			if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
				s.log.Warn("Failed to send push notification for project description updated",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail),
					zap.Error(err))
			} else {
				s.log.Debug("Successfully sent push notification for project description updated",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail))
			}
		}
	}()

	if user.PaidTier {
		if project.BandwidthLimit != nil && *project.BandwidthLimit == 0 {
			return nil, Error.New("current bandwidth limit for project is set to 0 (updating disabled)")
		}
		if project.StorageLimit != nil && *project.StorageLimit == 0 {
			return nil, Error.New("current storage limit for project is set to 0 (updating disabled)")
		}
		if updatedProject.StorageLimit <= 0 || updatedProject.BandwidthLimit <= 0 {
			return nil, ErrInvalidProjectLimit.New("Project limits must be greater than 0")
		}

		if updatedProject.StorageLimit > s.config.UsageLimits.Storage.Paid && updatedProject.StorageLimit > *project.StorageLimit {
			return nil, ErrInvalidProjectLimit.New("Specified storage limit exceeds allowed maximum for current tier")
		}

		if updatedProject.BandwidthLimit > s.config.UsageLimits.Bandwidth.Paid && updatedProject.BandwidthLimit > *project.BandwidthLimit {
			return nil, ErrInvalidProjectLimit.New("Specified bandwidth limit exceeds allowed maximum for current tier")
		}

		storageUsed, err := s.projectUsage.GetProjectStorageTotals(ctx, project.ID)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		if updatedProject.StorageLimit.Int64() < storageUsed {
			return nil, ErrInvalidProjectLimit.New("Cannot set storage limit below current usage")
		}

		bandwidthUsed, err := s.projectUsage.GetProjectBandwidthTotals(ctx, project.ID)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		if updatedProject.BandwidthLimit.Int64() < bandwidthUsed {
			return nil, ErrInvalidProjectLimit.New("Cannot set bandwidth limit below current usage")
		}
		/*
			The purpose of userSpecifiedBandwidthLimit and userSpecifiedStorageLimit is to know if a user has set a bandwidth
			or storage limit in the UI (to ensure their limits are not unintentionally modified by the satellite admin),
			the BandwidthLimit and StorageLimit is still used for verifying limits during uploads and downloads.
		*/
		if project.StorageLimit != nil && updatedProject.StorageLimit != *project.StorageLimit {
			project.UserSpecifiedStorageLimit = new(memory.Size)
			*project.UserSpecifiedStorageLimit = updatedProject.StorageLimit
		}
		if project.BandwidthLimit != nil && updatedProject.BandwidthLimit != *project.BandwidthLimit {
			project.UserSpecifiedBandwidthLimit = new(memory.Size)
			*project.UserSpecifiedBandwidthLimit = updatedProject.BandwidthLimit
		}

		project.StorageLimit = new(memory.Size)
		*project.StorageLimit = updatedProject.StorageLimit
		project.BandwidthLimit = new(memory.Size)
		*project.BandwidthLimit = updatedProject.BandwidthLimit
	}

	err = s.store.Projects().Update(ctx, project)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return project, nil
}

// RequestLimitIncrease is a method for requesting limit increase for a project.
func (s *Service) RequestLimitIncrease(ctx context.Context, projectID uuid.UUID, info LimitRequestInfo) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "request limit increase", zap.String("projectID", projectID.String()))
	if err != nil {
		return Error.Wrap(err)
	}

	_, project, err := s.isProjectOwner(ctx, user.ID, projectID)
	if err != nil {
		return Error.Wrap(err)
	}

	s.analytics.TrackRequestLimitIncrease(user.ID, user.Email, analytics.LimitRequestInfo{
		ProjectName:  project.Name,
		LimitType:    info.LimitType,
		CurrentLimit: info.CurrentLimit.String(),
		DesiredLimit: info.DesiredLimit.String(),
	})

	// Send push notification for limit increase requested
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID     // Capture user ID before closure
		notifyEmail := user.Email   // Capture email before closure
		projectName := project.Name // Capture project name before closure
		timestamp := time.Now().Format(time.RFC3339)
		requestedLimit := info.DesiredLimit.String()
		notification := pushnotifications.Notification{
			Title:    "Limit Increase Requested",
			Body:     fmt.Sprintf("Limit increase request for %s to %s for project %s has been submitted at %s", info.LimitType, requestedLimit, projectName, timestamp),
			Data:     map[string]string{"event": "limit_increase_requested", "project_name": projectName, "limit_type": info.LimitType, "requested_limit": requestedLimit, "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for limit increase requested",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for limit increase requested",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	return nil
}

// RequestProjectLimitIncrease is a method for requesting to increase max number of projects for a user.
func (s *Service) RequestProjectLimitIncrease(ctx context.Context, limit string) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "request project limit increase")
	if err != nil {
		return Error.Wrap(err)
	}

	if !user.PaidTier {
		return ErrNotPaidTier.New("Only Pro users may request project limit increases")
	}

	limitInt, err := strconv.Atoi(limit)
	if err != nil {
		return ErrInvalidProjectLimit.New("Requested project limit must be an integer")
	}

	if limitInt <= user.ProjectLimit {
		return ErrInvalidProjectLimit.New("Requested project limit (%d) must be greater than current limit (%d)", limitInt, user.ProjectLimit)
	}

	s.analytics.TrackRequestLimitIncrease(user.ID, user.Email, analytics.LimitRequestInfo{
		LimitType:    "projects",
		CurrentLimit: fmt.Sprint(user.ProjectLimit),
		DesiredLimit: limit,
	})

	// Send push notification for project limit increase requested
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID   // Capture user ID before closure
		notifyEmail := user.Email // Capture email before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Limit Increase Requested",
			Body:     fmt.Sprintf("Limit increase request for projects to %s has been submitted at %s", limit, timestamp),
			Data:     map[string]string{"event": "limit_increase_requested", "limit_type": "projects", "requested_limit": limit, "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for project limit increase requested",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for project limit increase requested",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	return nil
}

// GenUpdateProject is a method for updating project name and description by id for generated api.
func (s *Service) GenUpdateProject(ctx context.Context, projectID uuid.UUID, projectInfo UpsertProjectInfo) (p *Project, httpError api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "update project name and description", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}
	err = ValidateNameAndDescription(projectInfo.Name, projectInfo.Description)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusBadRequest,
			Err:    Error.Wrap(err),
		}
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}
	project := isMember.project
	project.Name = projectInfo.Name
	project.Description = projectInfo.Description

	if user.PaidTier {
		if project.BandwidthLimit != nil && *project.BandwidthLimit == 0 {
			return nil, api.HTTPError{
				Status: http.StatusInternalServerError,
				Err:    Error.New("current bandwidth limit for project is set to 0 (updating disabled)"),
			}
		}
		if project.StorageLimit != nil && *project.StorageLimit == 0 {
			return nil, api.HTTPError{
				Status: http.StatusInternalServerError,
				Err:    Error.New("current storage limit for project is set to 0 (updating disabled)"),
			}
		}
		if projectInfo.StorageLimit <= 0 || projectInfo.BandwidthLimit <= 0 {
			return nil, api.HTTPError{
				Status: http.StatusBadRequest,
				Err:    Error.New("project limits must be greater than 0"),
			}
		}

		if projectInfo.StorageLimit > s.config.UsageLimits.Storage.Paid && projectInfo.StorageLimit > *project.StorageLimit {
			return nil, api.HTTPError{
				Status: http.StatusBadRequest,
				Err:    Error.New("specified storage limit exceeds allowed maximum for current tier"),
			}
		}

		if projectInfo.BandwidthLimit > s.config.UsageLimits.Bandwidth.Paid && projectInfo.BandwidthLimit > *project.BandwidthLimit {
			return nil, api.HTTPError{
				Status: http.StatusBadRequest,
				Err:    Error.New("specified bandwidth limit exceeds allowed maximum for current tier"),
			}
		}

		storageUsed, err := s.projectUsage.GetProjectStorageTotals(ctx, projectID)
		if err != nil {
			return nil, api.HTTPError{
				Status: http.StatusInternalServerError,
				Err:    Error.Wrap(err),
			}
		}
		if projectInfo.StorageLimit.Int64() < storageUsed {
			return nil, api.HTTPError{
				Status: http.StatusBadRequest,
				Err:    Error.New("cannot set storage limit below current usage"),
			}
		}

		bandwidthUsed, err := s.projectUsage.GetProjectBandwidthTotals(ctx, projectID)
		if err != nil {
			return nil, api.HTTPError{
				Status: http.StatusInternalServerError,
				Err:    Error.Wrap(err),
			}
		}
		if projectInfo.BandwidthLimit.Int64() < bandwidthUsed {
			return nil, api.HTTPError{
				Status: http.StatusBadRequest,
				Err:    Error.New("cannot set bandwidth limit below current usage"),
			}
		}

		project.StorageLimit = new(memory.Size)
		*project.StorageLimit = projectInfo.StorageLimit
		project.BandwidthLimit = new(memory.Size)
		*project.BandwidthLimit = projectInfo.BandwidthLimit
	}

	err = s.store.Projects().Update(ctx, project)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	return project, httpError
}

// AddProjectMembers adds users by email to given project.
// Email addresses not belonging to a user are ignored.
// projectID here may be project.PublicID or project.ID.
func (s *Service) AddProjectMembers(ctx context.Context, projectID uuid.UUID, emails []string) (users []*User, err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "add project members", zap.String("projectID", projectID.String()), zap.Strings("emails", emails))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// collect user querying errors
	for _, email := range emails {
		user, err := s.store.Users().GetByEmail(ctx, email)
		if err == nil {
			users = append(users, user)
		} else if !errs.Is(err, sql.ErrNoRows) {
			return nil, Error.Wrap(err)
		}

	}

	// add project members in transaction scope
	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) error {
		for _, user := range users {
			if _, err := tx.ProjectMembers().Insert(ctx, user.ID, isMember.project.ID); err != nil {
				if dbx.IsConstraintError(err) {
					return errs.New("%s is already on the project", user.Email)
				}
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	s.analytics.TrackProjectMemberAddition(user.ID, user.Email)

	// Send push notifications for project members added
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		projectName := isMember.project.Name // Capture project name before closure
		for _, addedUser := range users {
			notifyUserID := addedUser.ID   // Capture user ID for each iteration
			notifyEmail := addedUser.Email // Capture email for each iteration
			timestamp := time.Now().Format(time.RFC3339)
			notification := pushnotifications.Notification{
				Title:    "Project Member Added",
				Body:     fmt.Sprintf("A new member (%s) has been added to project %s at %s", notifyEmail, projectName, timestamp),
				Data:     map[string]string{"event": "project_member_added", "project_name": projectName, "member_email": notifyEmail, "timestamp": timestamp},
				Priority: "normal", // level 3
			}
			if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
				s.log.Warn("Failed to send push notification for project member added",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail),
					zap.Error(err))
			} else {
				s.log.Debug("Successfully sent push notification for project member added",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail))
			}
		}
	}()

	return users, nil
}

// DeleteProjectMembersAndInvitations removes users and invitations by email from given project.
// projectID here may be project.PublicID or project.ID.
func (s *Service) DeleteProjectMembersAndInvitations(ctx context.Context, projectID uuid.UUID, emails []string) (err error) {
	defer mon.Task()(&ctx)(&err)
	user, err := s.getUserAndAuditLog(ctx, "delete project members", zap.String("projectID", projectID.String()), zap.Strings("emails", emails))
	if err != nil {
		return Error.Wrap(err)
	}

	var isMember isProjectMember
	if isMember, err = s.isProjectMember(ctx, user.ID, projectID); err != nil {
		return Error.Wrap(err)
	}

	projectID = isMember.project.ID

	var userIDs []uuid.UUID
	var invitedEmails []string

	for _, email := range emails {
		invite, err := s.store.ProjectInvitations().Get(ctx, projectID, email)
		if err == nil {
			invitedEmails = append(invitedEmails, email)
			continue
		}
		if !errs.Is(err, sql.ErrNoRows) {
			return Error.Wrap(err)
		}

		user, err := s.store.Users().GetByEmail(ctx, email)
		if err != nil {
			if invite == nil {
				return ErrValidation.New(teamMemberDoesNotExistErrMsg, email)
			}
			invitedEmails = append(invitedEmails, email)
			continue
		}

		isOwner, _, err := s.isProjectOwner(ctx, user.ID, projectID)
		if isOwner {
			return ErrValidation.New(projectOwnerDeletionForbiddenErrMsg, user.Email)
		}
		if err != nil && !ErrUnauthorized.Has(err) {
			return Error.Wrap(err)
		}

		userIDs = append(userIDs, user.ID)
	}

	// delete project members in transaction scope
	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) (err error) {
		for _, uID := range userIDs {
			err = tx.ProjectMembers().Delete(ctx, uID, projectID)
			if err != nil {
				return err
			}
		}
		for _, email := range invitedEmails {
			err = tx.ProjectInvitations().Delete(ctx, projectID, email)
			if err != nil {
				return err
			}
		}
		return nil
	})

	s.analytics.TrackProjectMemberDeletion(user.ID, user.Email)

	// Send push notifications for project members deleted
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		projectName := isMember.project.Name // Capture project name before closure
		for _, email := range emails {
			// Try to get user to send notification
			deletedUser, err := s.store.Users().GetByEmail(notifyCtx, email)
			if err == nil {
				notifyUserID := deletedUser.ID   // Capture user ID
				notifyEmail := deletedUser.Email // Capture email
				timestamp := time.Now().Format(time.RFC3339)
				notification := pushnotifications.Notification{
					Title:    "Project Member Removed",
					Body:     fmt.Sprintf("Member %s has been removed from project %s at %s", notifyEmail, projectName, timestamp),
					Data:     map[string]string{"event": "project_member_deleted", "project_name": projectName, "member_email": notifyEmail, "timestamp": timestamp},
					Priority: "normal", // level 3
				}
				if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
					s.log.Warn("Failed to send push notification for project member deleted",
						zap.Stringer("user_id", notifyUserID),
						zap.String("email", notifyEmail),
						zap.Error(err))
				} else {
					s.log.Debug("Successfully sent push notification for project member deleted",
						zap.Stringer("user_id", notifyUserID),
						zap.String("email", notifyEmail))
				}
			}
		}
	}()

	return Error.Wrap(err)
}

// GetProjectMembersAndInvitations returns the project members and invitations for a given project.
func (s *Service) GetProjectMembersAndInvitations(ctx context.Context, projectID uuid.UUID, cursor ProjectMembersCursor) (pmp *ProjectMembersPage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get project members", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, err = s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if cursor.Limit > maxLimit {
		cursor.Limit = maxLimit
	}

	pmp, err = s.store.ProjectMembers().GetPagedWithInvitationsByProjectID(ctx, projectID, cursor)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return
}

// CreateAPIKey creates new api key.
// projectID here may be project.PublicID or project.ID.
func (s *Service) CreateAPIKey(ctx context.Context, projectID uuid.UUID, name string) (_ *APIKeyInfo, _ *macaroon.APIKey, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "create api key", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	_, err = s.store.APIKeys().GetByNameAndProjectID(ctx, name, isMember.project.ID)
	if err == nil {
		return nil, nil, ErrValidation.New(apiKeyWithNameExistsErrMsg)
	}

	secret, err := macaroon.NewSecret()
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	key, err := macaroon.NewAPIKey(secret)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	apikey := APIKeyInfo{
		Name:      name,
		ProjectID: isMember.project.ID,
		CreatedBy: user.ID,
		Secret:    secret,
		UserAgent: user.UserAgent,
	}

	info, err := s.store.APIKeys().Create(ctx, key.Head(), apikey)
	if err != nil {
		return nil, nil, Error.Wrap(err)
	}

	return info, key, nil
}

// GenCreateAPIKey creates new api key for generated api.
func (s *Service) GenCreateAPIKey(ctx context.Context, requestInfo CreateAPIKeyRequest) (*CreateAPIKeyResponse, api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "create api key", zap.String("projectID", requestInfo.ProjectID))
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	reqProjectID, err := uuid.FromString(requestInfo.ProjectID)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusBadRequest,
			Err:    Error.Wrap(err),
		}
	}

	isMember, err := s.isProjectMember(ctx, user.ID, reqProjectID)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	projectID := isMember.project.ID

	_, err = s.store.APIKeys().GetByNameAndProjectID(ctx, requestInfo.Name, projectID)
	if err == nil {
		return nil, api.HTTPError{
			Status: http.StatusConflict,
			Err:    ErrValidation.New(apiKeyWithNameExistsErrMsg),
		}
	}

	secret, err := macaroon.NewSecret()
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	key, err := macaroon.NewAPIKey(secret)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	apikey := APIKeyInfo{
		Name:      requestInfo.Name,
		ProjectID: projectID,
		Secret:    secret,
		UserAgent: user.UserAgent,
	}

	info, err := s.store.APIKeys().Create(ctx, key.Head(), apikey)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	// in case the project ID from the request is the public ID, replace projectID with reqProjectID
	info.ProjectID = reqProjectID

	return &CreateAPIKeyResponse{
		Key:     key.Serialize(),
		KeyInfo: info,
	}, api.HTTPError{}
}

// GenDeleteAPIKey deletes api key for generated api.
func (s *Service) GenDeleteAPIKey(ctx context.Context, keyID uuid.UUID) (httpError api.HTTPError) {
	err := s.DeleteAPIKeys(ctx, []uuid.UUID{keyID})
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return httpError
		}

		status := http.StatusInternalServerError
		if ErrUnauthorized.Has(err) {
			status = http.StatusUnauthorized
		} else if ErrAPIKeyRequest.Has(err) {
			status = http.StatusBadRequest
		}

		return api.HTTPError{
			Status: status,
			Err:    Error.Wrap(err),
		}
	}

	return httpError
}

// GenGetAPIKeys returns api keys belonging to a project for generated api.
func (s *Service) GenGetAPIKeys(ctx context.Context, projectID uuid.UUID, search string, limit, page uint, order APIKeyOrder, orderDirection OrderDirection) (*APIKeyPage, api.HTTPError) {
	akp, err := s.GetAPIKeys(ctx, projectID, APIKeyCursor{
		Search:         search,
		Limit:          limit,
		Page:           page,
		Order:          order,
		OrderDirection: orderDirection,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if ErrUnauthorized.Has(err) {
			status = http.StatusUnauthorized
		} else if ErrAPIKeyRequest.Has(err) {
			status = http.StatusBadRequest
		}

		return nil, api.HTTPError{
			Status: status,
			Err:    Error.Wrap(err),
		}
	}

	return akp, api.HTTPError{}
}

// GetAPIKeyInfoByName retrieves an api key by its name and project id.
func (s *Service) GetAPIKeyInfoByName(ctx context.Context, projectID uuid.UUID, name string) (_ *APIKeyInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get api key info",
		zap.String("projectID", projectID.String()),
		zap.String("name", name))
	if err != nil {
		return nil, err
	}

	key, err := s.store.APIKeys().GetByNameAndProjectID(ctx, name, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, err = s.isProjectMember(ctx, user.ID, key.ProjectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return key, nil
}

// GetAPIKeyInfo retrieves api key by id.
func (s *Service) GetAPIKeyInfo(ctx context.Context, id uuid.UUID) (_ *APIKeyInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get api key info", zap.String("apiKeyID", id.String()))
	if err != nil {
		return nil, err
	}

	key, err := s.store.APIKeys().Get(ctx, id)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, err = s.isProjectMember(ctx, user.ID, key.ProjectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return key, nil
}

// DeleteAPIKeys deletes api key by id.
func (s *Service) DeleteAPIKeys(ctx context.Context, ids []uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	idStrings := make([]string, 0, len(ids))
	for _, id := range ids {
		idStrings = append(idStrings, id.String())
	}

	user, err := s.getUserAndAuditLog(ctx, "delete api keys", zap.Strings("apiKeyIDs", idStrings))
	if err != nil {
		return Error.Wrap(err)
	}

	var keysErr errs.Group

	for _, keyID := range ids {
		key, err := s.store.APIKeys().Get(ctx, keyID)
		if err != nil {
			keysErr.Add(err)
			continue
		}

		_, err = s.isProjectMember(ctx, user.ID, key.ProjectID)
		if err != nil {
			keysErr.Add(ErrUnauthorized.Wrap(err))
			continue
		}
	}

	if err = keysErr.Err(); err != nil {
		return Error.Wrap(err)
	}

	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) error {
		for _, keyToDeleteID := range ids {
			err = tx.APIKeys().Delete(ctx, keyToDeleteID)
			if err != nil {
				return err
			}
		}

		return nil
	})
	return Error.Wrap(err)
}

// GetAllAPIKeyNamesByProjectID returns all api key names by project ID.
func (s *Service) GetAllAPIKeyNamesByProjectID(ctx context.Context, projectID uuid.UUID) (names []string, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get all api key names by project ID", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	names, err = s.store.APIKeys().GetAllNamesByProjectID(ctx, isMember.project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return names, nil
}

// DeleteAPIKeyByNameAndProjectID deletes api key by name and project ID.
// ID here may be project.publicID or project.ID.
func (s *Service) DeleteAPIKeyByNameAndProjectID(ctx context.Context, name string, projectID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "delete api key by name and project ID", zap.String("apiKeyName", name), zap.String("projectID", projectID.String()))
	if err != nil {
		return Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return ErrUnauthorized.Wrap(err)
	}

	key, err := s.store.APIKeys().GetByNameAndProjectID(ctx, name, isMember.project.ID)
	if err != nil {
		return ErrNoAPIKey.New(apiKeyWithNameDoesntExistErrMsg)
	}

	err = s.store.APIKeys().Delete(ctx, key.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// GetAPIKeys returns paged api key list for given Project.
func (s *Service) GetAPIKeys(ctx context.Context, reqProjectID uuid.UUID, cursor APIKeyCursor) (page *APIKeyPage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get api keys", zap.String("projectID", reqProjectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, reqProjectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	projectID := isMember.project.ID

	if cursor.Limit > maxLimit {
		cursor.Limit = maxLimit
	}

	page, err = s.store.APIKeys().GetPagedByProjectID(ctx, projectID, cursor)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// if project ID from request is public ID, replace api key's project IDs with public ID
	if projectID != reqProjectID {
		for i := range page.APIKeys {
			page.APIKeys[i].ProjectID = reqProjectID
		}
	}

	return page, err
}

// CreateRESTKey creates a satellite rest key.
func (s *Service) CreateRESTKey(ctx context.Context, expiration time.Duration) (apiKey string, expiresAt time.Time, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "create rest key")
	if err != nil {
		return "", time.Time{}, Error.Wrap(err)
	}

	apiKey, expiresAt, err = s.restKeys.Create(ctx, user.ID, expiration)
	if err != nil {
		return "", time.Time{}, Error.Wrap(err)
	}
	return apiKey, expiresAt, nil
}

// RevokeRESTKey revokes a satellite REST key.
func (s *Service) RevokeRESTKey(ctx context.Context, apiKey string) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = s.getUserAndAuditLog(ctx, "revoke rest key")
	if err != nil {
		return Error.Wrap(err)
	}

	err = s.restKeys.Revoke(ctx, apiKey)
	if err != nil {
		return Error.Wrap(err)
	}
	return nil
}

// GetProjectUsage retrieves project usage for a given period.
func (s *Service) GetProjectUsage(ctx context.Context, projectID uuid.UUID, since, before time.Time) (_ *accounting.ProjectUsage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get project usage", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	_, err = s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	projectUsage, err := s.projectAccounting.GetProjectTotal(ctx, projectID, since, before)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return projectUsage, nil
}

// GetBucketTotals retrieves paged bucket total usages since project creation.
func (s *Service) GetBucketTotals(ctx context.Context, projectID uuid.UUID, cursor accounting.BucketUsageCursor, before time.Time) (_ *accounting.BucketUsagePage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get bucket totals", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	usage, err := s.projectAccounting.GetBucketTotals(ctx, isMember.project.ID, cursor, before)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if usage == nil {
		return usage, nil
	}

	for i := range usage.BucketUsages {
		placementID := usage.BucketUsages[i].DefaultPlacement
		usage.BucketUsages[i].Location = s.placements[placementID].Name
	}

	return usage, nil
}

// GetBucketTotals retrieves paged bucket total usages since project creation.
func (s *Service) GetBucketTotalsForReserveBucket(ctx context.Context, projectID uuid.UUID) (_ []accounting.BucketUsage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get bucket totals", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	usage, err := s.projectAccounting.GetBucketTotalsForReservedBuckets(ctx, isMember.project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if usage == nil {
		return usage, nil
	}

	for i := range usage {
		placementID := usage[i].DefaultPlacement
		usage[i].Location = s.placements[placementID].Name
	}

	return usage, nil
}

// UpdateBucketMigrationStatus updates the migration status of a bucket.
func (s *Service) UpdateBucketMigrationStatus(ctx context.Context, bucketName []byte, projectID uuid.UUID, status int) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "update bucket migration status", zap.String("bucketName", string(bucketName)), zap.String("projectID", projectID.String()))
	if err != nil {
		return Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return ErrUnauthorized.Wrap(err)
	}

	err = s.buckets.UpdateBucketMigrationStatus(ctx, bucketName, isMember.project.ID, status)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// GetAllBucketNames retrieves all bucket names of a specific project.
// projectID here may be Project.ID or Project.PublicID.
func (s *Service) GetAllBucketNames(ctx context.Context, projectID uuid.UUID) (_ []string, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get all bucket names", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	listOptions := buckets.ListOptions{
		Direction: buckets.DirectionForward,
	}

	allowedBuckets := macaroon.AllowedBuckets{
		All: true,
	}

	bucketsList, err := s.buckets.ListBuckets(ctx, isMember.project.ID, listOptions, allowedBuckets)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var list []string
	for _, bucket := range bucketsList.Items {
		list = append(list, bucket.Name)
	}

	return list, nil
}

// GetBucketMetadata retrieves all bucket names of a specific project and related metadata, e.g. placement and versioning.
// projectID here may be Project.ID or Project.PublicID.
func (s *Service) GetBucketMetadata(ctx context.Context, projectID uuid.UUID) (list []BucketMetadata, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get all bucket names and metadata", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	listOptions := buckets.ListOptions{
		Direction: buckets.DirectionForward,
	}

	allowedBuckets := macaroon.AllowedBuckets{
		All: true,
	}

	bucketsList, err := s.buckets.ListBuckets(ctx, isMember.project.ID, listOptions, allowedBuckets)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for _, bucket := range bucketsList.Items {
		list = append(list, BucketMetadata{
			Name:       bucket.Name,
			Versioning: bucket.Versioning,
			Placement: Placement{
				DefaultPlacement: bucket.Placement,
				Location:         s.placements[bucket.Placement].Name,
			},
		})
	}

	return list, nil
}

// GetUsageReport retrieves usage rollups for every bucket of a single or all the user owned projects for a given period.
func (s *Service) GetUsageReport(ctx context.Context, since, before time.Time, projectID uuid.UUID) ([]accounting.ProjectReportItem, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get usage report")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var projects []Project

	if projectID.IsZero() {
		pr, err := s.store.Projects().GetOwn(ctx, user.ID)
		if err != nil {
			return nil, Error.Wrap(err)
		}

		projects = append(projects, pr...)
	} else {
		_, pr, err := s.isProjectOwner(ctx, user.ID, projectID)
		if err != nil {
			return nil, ErrUnauthorized.Wrap(err)
		}

		projects = append(projects, *pr)
	}

	usage := make([]accounting.ProjectReportItem, 0)

	for _, p := range projects {
		rollups, err := s.projectAccounting.GetBucketUsageRollups(ctx, p.ID, since, before)
		if err != nil {
			return nil, Error.Wrap(err)
		}

		for _, r := range rollups {
			usage = append(usage, accounting.ProjectReportItem{
				ProjectName:  p.Name,
				ProjectID:    p.PublicID,
				BucketName:   r.BucketName,
				Storage:      r.TotalStoredData,
				Egress:       r.GetEgress,
				ObjectCount:  r.ObjectCount,
				SegmentCount: r.TotalSegments,
				Since:        r.Since,
				Before:       r.Before,
			})
		}
	}

	return usage, nil
}

// GenGetBucketUsageRollups retrieves summed usage rollups for every bucket of particular project for a given period for generated api.
func (s *Service) GenGetBucketUsageRollups(ctx context.Context, reqProjectID uuid.UUID, since, before time.Time) (rollups []accounting.BucketUsageRollup, httpError api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get bucket usage rollups", zap.String("projectID", reqProjectID.String()))
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	isMember, err := s.isProjectMember(ctx, user.ID, reqProjectID)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	projectID := isMember.project.ID

	rollups, err = s.projectAccounting.GetBucketUsageRollups(ctx, projectID, since, before)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	// if project ID from request is public ID, replace rollup's project ID with public ID
	if reqProjectID != projectID {
		for i := range rollups {
			rollups[i].ProjectID = reqProjectID
		}
	}

	return rollups, httpError
}

// GenGetSingleBucketUsageRollup retrieves usage rollup for single bucket of particular project for a given period for generated api.
func (s *Service) GenGetSingleBucketUsageRollup(ctx context.Context, reqProjectID uuid.UUID, bucket string, since, before time.Time) (rollup *accounting.BucketUsageRollup, httpError api.HTTPError) {
	var err error
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get single bucket usage rollup", zap.String("projectID", reqProjectID.String()))
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	isMember, err := s.isProjectMember(ctx, user.ID, reqProjectID)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusUnauthorized,
			Err:    Error.Wrap(err),
		}
	}

	projectID := isMember.project.ID

	rollup, err = s.projectAccounting.GetSingleBucketUsageRollup(ctx, projectID, bucket, since, before)
	if err != nil {
		return nil, api.HTTPError{
			Status: http.StatusInternalServerError,
			Err:    Error.Wrap(err),
		}
	}

	// make sure to replace rollup project ID with reqProjectID in case it is the public ID
	rollup.ProjectID = reqProjectID

	return rollup, httpError
}

// GetDailyProjectUsage returns daily usage by project ID.
// ID here may be project.ID or project.PublicID.
func (s *Service) GetDailyProjectUsage(ctx context.Context, projectID uuid.UUID, from, to time.Time) (_ *accounting.ProjectDailyUsage, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get daily usage by project ID")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	usage, err := s.projectAccounting.GetProjectDailyUsageByDateRange(ctx, isMember.project.ID, from, to, s.config.AsOfSystemTimeDuration)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return usage, nil
}

// GetProjectUsageLimits returns project limits and current usage.
//
// Among others,it can return one of the following errors returned by
// storj.io/storj/satellite/accounting.Service, wrapped Error.
func (s *Service) GetProjectUsageLimits(ctx context.Context, projectID uuid.UUID) (_ *ProjectUsageLimits, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get project usage limits", zap.String("projectID", projectID.String()))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	prUsageLimits, err := s.getProjectUsageLimits(ctx, isMember.project.ID, false)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	prObjectsSegments, err := s.projectAccounting.GetProjectObjectsSegments(ctx, isMember.project.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &ProjectUsageLimits{
		StorageLimit:   prUsageLimits.StorageLimit,
		BandwidthLimit: prUsageLimits.BandwidthLimit,
		StorageUsed:    prUsageLimits.StorageUsed,
		BandwidthUsed:  prUsageLimits.BandwidthUsed,
		ObjectCount:    prObjectsSegments.ObjectCount,
		SegmentCount:   prObjectsSegments.SegmentCount,
		SegmentLimit:   prUsageLimits.SegmentLimit,
		SegmentUsed:    prUsageLimits.SegmentUsed,
		BucketsUsed:    prUsageLimits.BucketsUsed,
		BucketsLimit:   prUsageLimits.BucketsLimit,
	}, nil
}

// GetTotalUsageLimits returns total limits and current usage for all the projects.
func (s *Service) GetTotalUsageLimits(ctx context.Context) (_ *ProjectUsageLimits, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get total usage and limits for all the projects")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	projects, err := s.store.Projects().GetOwn(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var totalStorageLimit int64
	var totalBandwidthLimit int64
	var totalStorageUsed int64
	var totalBandwidthUsed int64

	for _, pr := range projects {
		prUsageLimits, err := s.getProjectUsageLimits(ctx, pr.ID, true)
		if err != nil {
			return nil, Error.Wrap(err)
		}

		totalStorageLimit += prUsageLimits.StorageLimit
		totalBandwidthLimit += prUsageLimits.BandwidthLimit
		totalStorageUsed += prUsageLimits.StorageUsed
		totalBandwidthUsed += prUsageLimits.BandwidthUsed
	}

	return &ProjectUsageLimits{
		StorageLimit:   totalStorageLimit,
		BandwidthLimit: totalBandwidthLimit,
		StorageUsed:    totalStorageUsed,
		BandwidthUsed:  totalBandwidthUsed,
	}, nil
}

func (s *Service) getStorageAndBandwidthUse(ctx context.Context, projectID uuid.UUID) (storage, bandwidth int64, err error) {
	defer mon.Task()(&ctx)(&err)

	storage, err = s.projectUsage.GetProjectStorageTotals(ctx, projectID)
	if err != nil {
		return 0, 0, err
	}

	now := s.nowFn()
	bandwidth, err = s.projectUsage.GetProjectBandwidth(ctx, projectID, now.Year(), now.Month(), now.Day())
	if err != nil {
		return 0, 0, err
	}

	return storage, bandwidth, nil
}

func (s *Service) getProjectUsageLimits(ctx context.Context, projectID uuid.UUID, getBandwidthTotals bool) (_ *ProjectUsageLimits, err error) {
	defer mon.Task()(&ctx)(&err)

	storageLimit, err := s.projectUsage.GetProjectStorageLimit(ctx, projectID)
	if err != nil {
		return nil, err
	}
	bandwidthLimit, err := s.projectUsage.GetProjectBandwidthLimit(ctx, projectID)
	if err != nil {
		return nil, err
	}
	segmentLimit, err := s.projectUsage.GetProjectSegmentLimit(ctx, projectID)
	if err != nil {
		return nil, err
	}

	storageUsed, err := s.projectUsage.GetProjectStorageTotals(ctx, projectID)
	if err != nil {
		return nil, err
	}

	var bandwidthUsed int64
	if getBandwidthTotals {
		bandwidthUsed, err = s.projectUsage.GetProjectBandwidthTotals(ctx, projectID)
	} else {
		now := s.nowFn()
		bandwidthUsed, err = s.projectUsage.GetProjectBandwidth(ctx, projectID, now.Year(), now.Month(), now.Day())
	}
	if err != nil {
		return nil, err
	}

	segmentUsed, err := s.projectUsage.GetProjectSegmentTotals(ctx, projectID)
	if err != nil {
		return nil, err
	}

	bucketsUsed, err := s.buckets.CountBuckets(ctx, projectID)
	if err != nil {
		return nil, err
	}

	bucketsLimit, err := s.store.Projects().GetMaxBuckets(ctx, projectID)
	if err != nil {
		return nil, err
	}

	if bucketsLimit == nil {
		bucketsLimit = &s.maxProjectBuckets
	}

	return &ProjectUsageLimits{
		StorageLimit:   storageLimit.Int64(),
		BandwidthLimit: bandwidthLimit.Int64(),
		StorageUsed:    storageUsed,
		BandwidthUsed:  bandwidthUsed,
		SegmentLimit:   segmentLimit.Int64(),
		SegmentUsed:    segmentUsed,
		BucketsUsed:    int64(bucketsUsed),
		BucketsLimit:   int64(*bucketsLimit),
	}, nil
}

// TokenAuth returns an authenticated context by session token.
func (s *Service) TokenAuth(ctx context.Context, token consoleauth.Token, authTime time.Time) (_ context.Context, err error) {
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

	session, err := s.store.WebappSessions().GetBySessionID(ctx, sessionID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	ctx, err = s.authorize(ctx, session.UserID, session.ExpiresAt, authTime)
	if err != nil {
		err := errs.Combine(err, s.store.WebappSessions().DeleteBySessionID(ctx, sessionID))
		if err != nil {
			return nil, Error.Wrap(err)
		}
		return nil, err
	}

	return ctx, nil
}

// KeyAuth returns an authenticated context by api key.
func (s *Service) KeyAuth(ctx context.Context, apikey string, authTime time.Time) (_ context.Context, err error) {
	defer mon.Task()(&ctx)(&err)

	ctx = consoleauth.WithAPIKey(ctx, []byte(apikey))

	userID, exp, err := s.restKeys.GetUserAndExpirationFromKey(ctx, apikey)
	if err != nil {
		return nil, err
	}

	ctx, err = s.authorize(ctx, userID, exp, authTime)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

// checkProjectCanBeDeleted ensures that all data, api-keys and buckets are deleted and usage has been accounted.
// no error means the project status is clean.
func (s *Service) checkProjectCanBeDeleted(ctx context.Context, user *User, projectID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	buckets, err := s.buckets.CountBuckets(ctx, projectID)
	if err != nil {
		return err
	}
	if buckets > 0 {
		return ErrUsage.New("some buckets still exist")
	}

	keys, err := s.store.APIKeys().GetPagedByProjectID(ctx, projectID, APIKeyCursor{Limit: 1, Page: 1})
	if err != nil {
		return err
	}
	if keys.TotalCount > 0 {
		return ErrUsage.New("some api keys still exist")
	}

	if user.PaidTier {
		err = s.Payments().checkProjectUsageStatus(ctx, projectID)
		if err != nil {
			return ErrUsage.Wrap(err)
		}
	}

	err = s.Payments().checkProjectInvoicingStatus(ctx, projectID)
	if err != nil {
		return ErrUsage.Wrap(err)
	}

	return nil
}

// checkProjectLimit is used to check if user is able to create a new project.
func (s *Service) checkProjectLimit(ctx context.Context, userID uuid.UUID) (currentProjects int, err error) {
	defer mon.Task()(&ctx)(&err)

	limit, err := s.store.Users().GetProjectLimit(ctx, userID)
	if err != nil {
		return 0, Error.Wrap(err)
	}

	projects, err := s.store.Projects().GetOwn(ctx, userID)
	if err != nil {
		return 0, Error.Wrap(err)
	}

	if len(projects) >= limit {
		return 0, ErrProjLimit.New(projLimitErrMsg)
	}

	return len(projects), nil
}

// checkProjectName is used to check if user has used project name before.
func (s *Service) checkProjectName(ctx context.Context, projectInfo UpsertProjectInfo, userID uuid.UUID) (passesNameCheck bool, err error) {
	defer mon.Task()(&ctx)(&err)
	passesCheck := true

	projects, err := s.store.Projects().GetOwn(ctx, userID)
	if err != nil {
		return false, Error.Wrap(err)
	}

	for _, project := range projects {
		if project.Name == projectInfo.Name {
			return false, ErrProjName.New(projNameErrMsg)
		}
	}

	return passesCheck, nil
}

// getUserProjectLimits is a method to get the users storage and bandwidth limits for new projects.
func (s *Service) getUserProjectLimits(ctx context.Context, userID uuid.UUID) (_ *UsageLimits, err error) {
	defer mon.Task()(&ctx)(&err)

	result, err := s.store.Users().GetUserProjectLimits(ctx, userID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &UsageLimits{
		Storage:   result.ProjectStorageLimit.Int64(),
		Bandwidth: result.ProjectBandwidthLimit.Int64(),
		Segment:   result.ProjectSegmentLimit,
	}, nil
}

// CreateRegToken creates new registration token. Needed for testing.
func (s *Service) CreateRegToken(ctx context.Context, projLimit int) (_ *RegistrationToken, err error) {
	defer mon.Task()(&ctx)(&err)
	result, err := s.store.RegistrationTokens().Create(ctx, projLimit)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return result, nil
}

// authorize returns an authorized context by user ID.
func (s *Service) authorize(ctx context.Context, userID uuid.UUID, expiration time.Time, authTime time.Time) (_ context.Context, err error) {
	defer mon.Task()(&ctx)(&err)
	if !expiration.IsZero() && expiration.Before(authTime) {
		return nil, ErrTokenExpiration.New("authorization failed. expiration reached.")
	}

	user, err := s.store.Users().Get(ctx, userID)
	if err != nil {
		return nil, Error.New("authorization failed. no user with id: %s", userID.String())
	}

	// if user.Status != Active && user.Status != PendingBotVerification {
	// 	return nil, Error.New("authorization failed. no active user with id: %s", userID.String())
	// }
	return WithUser(ctx, user), nil
}

// isProjectMember is return type of isProjectMember service method.
type isProjectMember struct {
	project    *Project
	membership *ProjectMember
}

// isProjectOwner checks if the user is an owner of a project.
func (s *Service) isProjectOwner(ctx context.Context, userID uuid.UUID, projectID uuid.UUID) (isOwner bool, project *Project, err error) {
	defer mon.Task()(&ctx)(&err)

	project, err = s.GetProjectNoAuth(ctx, projectID)
	if err != nil {
		return false, nil, err
	}

	if project.OwnerID != userID {
		return false, nil, ErrUnauthorized.New(unauthorizedErrMsg)
	}

	return true, project, nil
}

// isProjectMember checks if the user is a member of given project.
// projectID can be either private ID or public ID (project.ID/project.PublicID).
func (s *Service) isProjectMember(ctx context.Context, userID uuid.UUID, projectID uuid.UUID) (_ isProjectMember, err error) {
	defer mon.Task()(&ctx)(&err)

	project, err := s.GetProjectNoAuth(ctx, projectID)
	if err != nil {
		return isProjectMember{}, err
	}

	memberships, err := s.store.ProjectMembers().GetByMemberID(ctx, userID)
	if err != nil {
		return isProjectMember{}, Error.Wrap(err)
	}

	membership, ok := findMembershipByProjectID(memberships, project.ID)
	if ok {
		return isProjectMember{
			project:    project,
			membership: &membership,
		}, nil
	}

	return isProjectMember{}, ErrNoMembership.New(unauthorizedErrMsg)
}

// WalletInfo contains all the information about a destination wallet assigned to a user.
type WalletInfo struct {
	Address blockchain.Address `json:"address"`
	Balance currency.Amount    `json:"balance"`
}

// PaymentInfo includes token payment information required by GUI.
type PaymentInfo struct {
	ID        string
	Type      string
	Wallet    string
	Amount    currency.Amount
	Received  currency.Amount
	Status    string
	Link      string
	Timestamp time.Time
}

// WalletPayments represents the list of ERC-20 token payments.
type WalletPayments struct {
	Payments []PaymentInfo `json:"payments"`
}

// EtherscanURL creates etherscan transaction URI.
func (payment Payments) EtherscanURL(tx string) string {
	url := payment.service.config.BlockExplorerURL
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}

	return url + "tx/" + tx
}

// ErrWalletNotClaimed shows that no address is claimed by the user.
var ErrWalletNotClaimed = errs.Class("wallet is not claimed")

// TestSwapDepositWallets replaces the existing handler for deposit wallets with
// the one specified for use in testing.
func (payment Payments) TestSwapDepositWallets(dw payments.DepositWallets) {
	payment.service.depositWallets = dw
}

// ClaimWallet requests a new wallet for the users to be used for payments. If wallet is already claimed,
// it will return with the info without error.
func (payment Payments) ClaimWallet(ctx context.Context) (_ WalletInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := payment.service.getUserAndAuditLog(ctx, "claim wallet")
	if err != nil {
		return WalletInfo{}, Error.Wrap(err)
	}
	address, err := payment.service.depositWallets.Claim(ctx, user.ID)
	if err != nil {
		return WalletInfo{}, Error.Wrap(err)
	}
	balance, err := payment.service.billing.GetBalance(ctx, user.ID)
	if err != nil {
		return WalletInfo{}, Error.Wrap(err)
	}
	return WalletInfo{
		Address: address,
		Balance: balance,
	}, nil
}

// GetWallet returns with the assigned wallet, or with ErrWalletNotClaimed if not yet claimed.
func (payment Payments) GetWallet(ctx context.Context) (_ WalletInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return WalletInfo{}, Error.Wrap(err)
	}
	address, err := payment.service.depositWallets.Get(ctx, user.ID)
	if err != nil {
		return WalletInfo{}, Error.Wrap(err)
	}
	balance, err := payment.service.billing.GetBalance(ctx, user.ID)
	if err != nil {
		return WalletInfo{}, Error.Wrap(err)
	}
	return WalletInfo{
		Address: address,
		Balance: balance,
	}, nil
}

// WalletPayments returns with all the native blockchain payments for a user's wallet.
func (payment Payments) WalletPayments(ctx context.Context) (_ WalletPayments, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return WalletPayments{}, Error.Wrap(err)
	}
	address, err := payment.service.depositWallets.Get(ctx, user.ID)
	if err != nil {
		return WalletPayments{}, Error.Wrap(err)
	}

	walletPayments, err := payment.service.depositWallets.Payments(ctx, address, 3000, 0)
	if err != nil {
		return WalletPayments{}, Error.Wrap(err)
	}
	txInfos, err := payment.service.accounts.StorjTokens().ListTransactionInfos(ctx, user.ID)
	if err != nil {
		return WalletPayments{}, Error.Wrap(err)
	}
	txns, err := payment.service.billing.ListSource(ctx, user.ID, billing.StorjScanBonusSource)
	if err != nil {
		return WalletPayments{}, Error.Wrap(err)
	}

	var paymentInfos []PaymentInfo
	for _, walletPayment := range walletPayments {
		paymentInfos = append(paymentInfos, PaymentInfo{
			ID:        fmt.Sprintf("%s#%d", walletPayment.Transaction.Hex(), walletPayment.LogIndex),
			Type:      "storjscan",
			Wallet:    walletPayment.To.Hex(),
			Amount:    walletPayment.USDValue,
			Status:    string(walletPayment.Status),
			Link:      payment.EtherscanURL(walletPayment.Transaction.Hex()),
			Timestamp: walletPayment.Timestamp,
		})
	}
	for _, txInfo := range txInfos {
		paymentInfos = append(paymentInfos, PaymentInfo{
			ID:        txInfo.ID.String(),
			Type:      "coinpayments",
			Wallet:    txInfo.Address,
			Amount:    currency.AmountFromBaseUnits(txInfo.AmountCents, currency.USDollars),
			Received:  currency.AmountFromBaseUnits(txInfo.ReceivedCents, currency.USDollars),
			Status:    txInfo.Status.String(),
			Link:      txInfo.Link,
			Timestamp: txInfo.CreatedAt.UTC(),
		})
	}
	for _, txn := range txns {
		var meta struct {
			ReferenceID string
			LogIndex    int
		}
		err = json.NewDecoder(bytes.NewReader(txn.Metadata)).Decode(&meta)
		if err != nil {
			return WalletPayments{}, Error.Wrap(err)
		}
		paymentInfos = append(paymentInfos, PaymentInfo{
			ID:        fmt.Sprint(txn.ID),
			Type:      txn.Source,
			Wallet:    address.Hex(),
			Amount:    txn.Amount,
			Status:    string(txn.Status),
			Link:      payment.EtherscanURL(meta.ReferenceID),
			Timestamp: txn.Timestamp,
		})
	}

	return WalletPayments{
		Payments: paymentInfos,
	}, nil
}

// WalletPaymentsWithConfirmations returns with all the native blockchain payments (including pending) for a user's wallet.
func (payment Payments) WalletPaymentsWithConfirmations(ctx context.Context) (paymentsWithConfirmations []payments.WalletPaymentWithConfirmations, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	address, err := payment.service.depositWallets.Get(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	paymentsWithConfirmations, err = payment.service.depositWallets.PaymentsWithConfirmations(ctx, address)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return
}

// Purchase makes a purchase of `price` amount with description of `desc` and payment method with id of `paymentMethodID`.
// If a paid invoice with the same description exists, then we assume this is a retried request and don't create and pay
// another invoice.
func (payment Payments) Purchase(ctx context.Context, price int64, desc string, paymentMethodID string) (err error) {
	defer mon.Task()(&ctx)(&err)

	if desc == "" {
		return ErrPurchaseDesc.New("description cannot be empty")
	}
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	invoices, err := payment.service.accounts.Invoices().List(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	// check for any previously created unpaid invoice with the same description.
	// If draft, delete it and create new and pay. If open, pay it and don't create new.
	// If paid, skip.
	for _, inv := range invoices {
		if inv.Description == desc {
			if inv.Status == payments.InvoiceStatusPaid {
				return nil
			}
			if inv.Status == payments.InvoiceStatusDraft {
				_, err := payment.service.accounts.Invoices().Delete(ctx, inv.ID)
				if err != nil {
					return Error.Wrap(err)
				}
			} else if inv.Status == payments.InvoiceStatusOpen {
				_, err = payment.service.accounts.Invoices().Pay(ctx, inv.ID, paymentMethodID)
				return Error.Wrap(err)
			}
		}
	}

	inv, err := payment.service.accounts.Invoices().Create(ctx, user.ID, price, desc)
	if err != nil {
		return Error.Wrap(err)
	}

	_, err = payment.service.accounts.Invoices().Pay(ctx, inv.ID, paymentMethodID)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// UpdatePackage updates a user's package information unless they already have a package.
func (payment Payments) UpdatePackage(ctx context.Context, packagePlan string, purchaseTime time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	dbPackagePlan, dbPurchaseTime, err := payment.service.accounts.GetPackageInfo(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}
	if dbPackagePlan != nil || dbPurchaseTime != nil {
		return ErrAlreadyHasPackage.New("user already has package")
	}

	err = payment.service.accounts.UpdatePackage(ctx, user.ID, &packagePlan, &purchaseTime)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// ApplyCredit applies a credit of `amount` with description of `desc` to the user's balance. `amount` is in cents USD.
// If a credit with `desc` already exists, another one will not be created.
func (payment Payments) ApplyCredit(ctx context.Context, amount int64, desc string) (err error) {
	defer mon.Task()(&ctx)(&err)

	if desc == "" {
		return ErrPurchaseDesc.New("description cannot be empty")
	}
	user, err := GetUser(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	btxs, err := payment.service.accounts.Balances().ListTransactions(ctx, user.ID)
	if err != nil {
		return Error.Wrap(err)
	}

	// check for any previously created transaction with the same description.
	for _, btx := range btxs {
		if btx.Description == desc {
			return nil
		}
	}

	_, err = payment.service.accounts.Balances().ApplyCredit(ctx, user.ID, amount, desc)
	if err != nil {
		return Error.Wrap(err)
	}
	return nil
}

// GetProjectUsagePriceModel returns the project usage price model for the partner.
func (payment Payments) GetProjectUsagePriceModel(partner string) (_ *payments.ProjectUsagePriceModel) {
	model := payment.service.accounts.GetProjectUsagePriceModel(partner)
	return &model
}

func findMembershipByProjectID(memberships []ProjectMember, projectID uuid.UUID) (ProjectMember, bool) {
	for _, membership := range memberships {
		if membership.ProjectID == projectID {
			return membership, true
		}
	}
	return ProjectMember{}, false
}

// DeleteSession removes the session from the database.
func (s *Service) DeleteSession(ctx context.Context, sessionID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	return Error.Wrap(s.store.WebappSessions().DeleteBySessionID(ctx, sessionID))
}

// DeleteAllSessionsByUserIDExcept removes all sessions except the specified session from the database.
func (s *Service) DeleteAllSessionsByUserIDExcept(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) (err error) {
	defer mon.Task()(&ctx)(&err)

	sessions, err := s.store.WebappSessions().GetAllByUserID(ctx, userID)
	if err != nil {
		return Error.Wrap(err)
	}

	for _, session := range sessions {
		if session.ID != sessionID {
			err = s.DeleteSession(ctx, session.ID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// RefreshSession resets the expiration time of the session.
func (s *Service) RefreshSession(ctx context.Context, sessionID uuid.UUID) (expiresAt time.Time, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "refresh session")
	if err != nil {
		return time.Time{}, Error.Wrap(err)
	}

	duration := time.Duration(s.config.Session.InactivityTimerDuration) * time.Second
	settings, err := s.store.Users().GetSettings(ctx, user.ID)
	if err != nil && !errs.Is(err, sql.ErrNoRows) {
		return time.Time{}, Error.Wrap(err)
	}
	if settings != nil && settings.SessionDuration != nil {
		duration = *settings.SessionDuration
	}
	expiresAt = time.Now().Add(duration)

	err = s.store.WebappSessions().UpdateExpiration(ctx, sessionID, expiresAt)
	if err != nil {
		return time.Time{}, err
	}

	return expiresAt, nil
}

// VerifyForgotPasswordCaptcha returns whether the given captcha response for the forgot password page is valid.
// It will return true without error if the captcha handler has not been set.
func (s *Service) VerifyForgotPasswordCaptcha(ctx context.Context, responseToken, userIP string) (valid bool, err error) {
	defer mon.Task()(&ctx)(&err)

	if s.loginCaptchaHandler != nil {
		valid, _, err = s.loginCaptchaHandler.Verify(ctx, responseToken, userIP)
		return valid, ErrCaptcha.Wrap(err)
	}
	return true, nil
}

// GetUserSettings fetches a user's settings. It creates default settings if none exists.
func (s *Service) GetUserSettings(ctx context.Context) (settings *UserSettings, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get user settings")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	settings, err = s.store.Users().GetSettings(ctx, user.ID)
	if err != nil {
		if !errs.Is(err, sql.ErrNoRows) {
			return nil, Error.Wrap(err)
		}

		settingsReq := UpsertUserSettingsRequest{}
		// a user may have existed before a corresponding row was created in the user settings table
		// to avoid showing an old user the onboarding flow again, we check to see if the user owns any projects already
		// if so, set the "onboarding start" and "onboarding end" fields to "true"
		projects, err := s.store.Projects().GetOwn(ctx, user.ID)
		if err != nil {
			// we can still proceed with the settings upsert if there is an error retrieving projects, so log and don't return
			s.log.Warn("received error trying to get user's projects", zap.Error(err))
		}
		if len(projects) > 0 {
			t := true
			settingsReq.OnboardingStart = &(t)
			settingsReq.OnboardingEnd = &(t)
		}

		err = s.store.Users().UpsertSettings(ctx, user.ID, settingsReq)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		settings, err = s.store.Users().GetSettings(ctx, user.ID)
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}

	return settings, nil
}

// SetUserSettings updates a user's settings.
func (s *Service) SetUserSettings(ctx context.Context, request UpsertUserSettingsRequest) (settings *UserSettings, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get user settings")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	err = s.store.Users().UpsertSettings(ctx, user.ID, request)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	settings, err = s.store.Users().GetSettings(ctx, user.ID)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return settings, nil
}

// GetUserProjectInvitations returns a user's pending project member invitations.
func (s *Service) GetUserProjectInvitations(ctx context.Context) (_ []ProjectInvitation, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get project member invitations")
	if err != nil {
		return nil, Error.Wrap(err)
	}

	invites, err := s.store.ProjectInvitations().GetByEmail(ctx, user.Email)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var active []ProjectInvitation
	for _, invite := range invites {
		if !s.IsProjectInvitationExpired(&invite) {
			active = append(active, invite)
		}
	}

	return active, nil
}

// ProjectInvitationResponse represents a response to a project member invitation.
type ProjectInvitationResponse int

const (
	// ProjectInvitationDecline represents rejection of a project member invitation.
	ProjectInvitationDecline ProjectInvitationResponse = iota
	// ProjectInvitationAccept represents acceptance of a project member invitation.
	ProjectInvitationAccept
)

// RespondToProjectInvitation handles accepting or declining a user's project member invitation.
// The given project ID may be the internal or public ID.
func (s *Service) RespondToProjectInvitation(ctx context.Context, projectID uuid.UUID, response ProjectInvitationResponse) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "project member invitation response",
		zap.String("projectID", projectID.String()),
		zap.Any("response", response),
	)
	if err != nil {
		return Error.Wrap(err)
	}

	if response != ProjectInvitationAccept && response != ProjectInvitationDecline {
		return ErrValidation.New(projInviteResponseInvalidErrMsg)
	}

	if user.Status == PendingBotVerification {
		return ErrBotUser.New(contactSupportErrMsg)
	}

	proj, err := s.GetProjectNoAuth(ctx, projectID)
	if err != nil {
		return Error.Wrap(err)
	}
	projectID = proj.ID

	// log deletion errors that don't affect the outcome
	deleteWithLog := func() {
		err := s.store.ProjectInvitations().Delete(ctx, projectID, user.Email)
		if err != nil {
			s.log.Warn("error deleting project invitation",
				zap.Error(err),
				zap.String("email", user.Email),
				zap.String("projectID", projectID.String()),
			)
		}
	}

	_, err = s.isProjectMember(ctx, user.ID, projectID)
	if err == nil {
		deleteWithLog()
		if response == ProjectInvitationDecline {
			return ErrAlreadyMember.New(projInviteAlreadyMemberErrMsg)
		}
		return nil
	}

	invite, err := s.store.ProjectInvitations().Get(ctx, projectID, user.Email)
	if err != nil {
		if !errs.Is(err, sql.ErrNoRows) {
			return Error.Wrap(err)
		}
		if response == ProjectInvitationDecline {
			return nil
		}
		return ErrProjectInviteInvalid.New(projInviteInvalidErrMsg)
	}

	if s.IsProjectInvitationExpired(invite) {
		return ErrProjectInviteInvalid.New(projInviteInvalidErrMsg)
	}

	if response == ProjectInvitationDecline {
		err = Error.Wrap(s.store.ProjectInvitations().Delete(ctx, projectID, user.Email))
		if err != nil {
			return err
		}

		// Send push notification for project invitation declined
		go func() {
			// Use background context to avoid cancellation when HTTP request completes
			notifyCtx := context.Background()
			notifyUserID := user.ID   // Capture user ID before closure
			notifyEmail := user.Email // Capture email before closure
			projectName := proj.Name  // Capture project name before closure
			timestamp := time.Now().Format(time.RFC3339)
			notification := pushnotifications.Notification{
				Title:    "Project Invitation Declined",
				Body:     fmt.Sprintf("Invitation to project %s has been declined by %s at %s", projectName, notifyEmail, timestamp),
				Data:     map[string]string{"event": "project_invitation_declined", "project_name": projectName, "invitee_email": notifyEmail, "timestamp": timestamp},
				Priority: "normal", // level 2
			}
			if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
				s.log.Warn("Failed to send push notification for project invitation declined",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail),
					zap.Error(err))
			} else {
				s.log.Debug("Successfully sent push notification for project invitation declined",
					zap.Stringer("user_id", notifyUserID),
					zap.String("email", notifyEmail))
			}
		}()

		return nil
	}

	_, err = s.store.ProjectMembers().Insert(ctx, user.ID, projectID)
	if err != nil {
		return Error.Wrap(err)
	}

	deleteWithLog()

	// Send push notification for project invitation accepted
	go func() {
		// Use background context to avoid cancellation when HTTP request completes
		notifyCtx := context.Background()
		notifyUserID := user.ID   // Capture user ID before closure
		notifyEmail := user.Email // Capture email before closure
		projectName := proj.Name  // Capture project name before closure
		timestamp := time.Now().Format(time.RFC3339)
		notification := pushnotifications.Notification{
			Title:    "Project Invitation Accepted",
			Body:     fmt.Sprintf("Invitation to project %s has been accepted by %s at %s", projectName, notifyEmail, timestamp),
			Data:     map[string]string{"event": "project_invitation_accepted", "project_name": projectName, "invitee_email": notifyEmail, "timestamp": timestamp},
			Priority: "normal", // level 2
		}
		if err := s.SendPushNotificationWithPreferences(notifyCtx, notifyUserID, "account", notification); err != nil {
			s.log.Warn("Failed to send push notification for project invitation accepted",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail),
				zap.Error(err))
		} else {
			s.log.Debug("Successfully sent push notification for project invitation accepted",
				zap.Stringer("user_id", notifyUserID),
				zap.String("email", notifyEmail))
		}
	}()

	return nil
}

// ProjectInvitationOption represents whether a project invitation request is for
// inviting new members (creating records) or resending existing invitations (updating records).
type ProjectInvitationOption int

const (
	// ProjectInvitationCreate indicates to insert new project member records.
	ProjectInvitationCreate ProjectInvitationOption = iota
	// ProjectInvitationResend indicates to update existing project member records.
	ProjectInvitationResend
)

// ReinviteProjectMembers resends project invitations to the users specified by the given email slice.
// The provided project ID may be the public or internal ID.
func (s *Service) ReinviteProjectMembers(ctx context.Context, projectID uuid.UUID, emails []string) (invites []ProjectInvitation, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx,
		"reinvite project members",
		zap.String("projectID", projectID.String()),
		zap.Strings("emails", emails),
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return s.inviteProjectMembers(ctx, user, projectID, emails, ProjectInvitationResend)
}

// InviteNewProjectMember invites a user by email to the project specified by the given ID,
// which may be its public or internal ID.
func (s *Service) InviteNewProjectMember(ctx context.Context, projectID uuid.UUID, email string) (invite *ProjectInvitation, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx,
		"invite project member",
		zap.String("projectID", projectID.String()),
		zap.String("invitedEmail", email),
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	invites, err := s.inviteProjectMembers(ctx, user, projectID, []string{email}, ProjectInvitationCreate)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &invites[0], nil
}

// inviteProjectMembers invites users by email to the project specified by the given ID,
// which may be its public or internal ID.
func (s *Service) inviteProjectMembers(ctx context.Context, sender *User, projectID uuid.UUID, emails []string, opt ProjectInvitationOption) (invites []ProjectInvitation, err error) {
	defer mon.Task()(&ctx)(&err)

	isMember, err := s.isProjectMember(ctx, sender.ID, projectID)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	projectID = isMember.project.ID

	if s.config.BillingFeaturesEnabled && !(s.config.FreeTierInvitesEnabled || sender.PaidTier) {
		if _, ok := s.varPartners[string(sender.UserAgent)]; ok {
			return nil, ErrHasVarPartner.New(varPartnerInviteErr)
		}
		return nil, ErrNotPaidTier.New(paidTierInviteErrMsg)
	}

	var users []*User
	var newUserEmails []string
	var unverifiedUsers []User
	for _, email := range emails {
		invite, err := s.store.ProjectInvitations().Get(ctx, projectID, email)
		if err != nil && !errs.Is(err, sql.ErrNoRows) {
			return nil, Error.Wrap(err)
		}

		if invite != nil {
			// If we should only insert new records, a preexisting record is an issue
			if opt == ProjectInvitationCreate {
				return nil, ErrAlreadyInvited.New(projInviteExistsErrMsg, email)
			}
			if !s.IsProjectInvitationExpired(invite) {
				return nil, ErrAlreadyInvited.New(activeProjInviteExistsErrMsg, email)
			}
		} else if opt == ProjectInvitationResend {
			// If we should only update existing records, an absence of records is an issue
			return nil, ErrProjectInviteInvalid.New(projInviteDoesntExistErrMsg, email)
		}

		invitedUser, unverified, err := s.store.Users().GetByEmailWithUnverified(ctx, email)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		if invitedUser != nil {
			_, err = s.isProjectMember(ctx, invitedUser.ID, projectID)
			if err != nil && !ErrNoMembership.Has(err) {
				return nil, Error.Wrap(err)
			} else if err == nil {
				return nil, ErrAlreadyMember.New("%s is already a member", email)
			}
			users = append(users, invitedUser)
		} else if len(unverified) > 0 {
			oldest := unverified[0]
			for _, u := range unverified {
				if u.CreatedAt.Before(oldest.CreatedAt) {
					oldest = u
				}
			}
			unverifiedUsers = append(unverifiedUsers, oldest)
		} else if s.config.UnregisteredInviteEmailsEnabled {
			newUserEmails = append(newUserEmails, email)
		}
	}

	inviteTokens := make(map[string]string)
	// add project invites in transaction scope
	err = s.store.WithTx(ctx, func(ctx context.Context, tx DBTx) error {
		for _, email := range emails {
			invite, err := tx.ProjectInvitations().Upsert(ctx, &ProjectInvitation{
				ProjectID: projectID,
				Email:     email,
				InviterID: &sender.ID,
			})
			if err != nil {
				return err
			}

			var isUnverified bool
			for _, u := range unverifiedUsers {
				if email == u.Email {
					isUnverified = true
					invites = append(invites, *invite)
					break
				}
			}
			if isUnverified {
				continue
			}

			token, err := s.CreateInviteToken(ctx, isMember.project.PublicID, email, invite.CreatedAt)
			if err != nil {
				return err
			}
			inviteTokens[email] = token
			invites = append(invites, *invite)
		}
		return nil
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	baseLink := fmt.Sprintf("%s/invited", s.satelliteAddress)
	for _, invited := range users {
		inviteLink := fmt.Sprintf("%s?invite=%s", baseLink, inviteTokens[invited.Email])

		userName := invited.ShortName
		if userName == "" {
			userName = invited.FullName
		}
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: invited.Email, Name: userName}},
			&ExistingUserProjectInvitationEmail{
				InviterEmail: sender.Email,
				SignInLink:   inviteLink,
			},
		)
	}
	for _, u := range unverifiedUsers {
		token, err := s.GenerateActivationToken(ctx, u.ID, u.Email)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		activationLink := fmt.Sprintf("%s/activation?token=%s", s.satelliteAddress, token)
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: u.Email}},
			&UnverifiedUserProjectInvitationEmail{
				InviterEmail:   sender.Email,
				Region:         s.satelliteName,
				ActivationLink: activationLink,
			},
		)
	}

	for _, email := range newUserEmails {
		inviteLink := fmt.Sprintf("%s?invite=%s", baseLink, inviteTokens[email])
		s.mailService.SendRenderedAsync(
			ctx,
			[]post.Address{{Address: email}},
			&NewUserProjectInvitationEmail{
				InviterEmail: sender.Email,
				Region:       s.satelliteName,
				SignUpLink:   inviteLink,
			},
		)
	}

	return invites, nil
}

// IsProjectInvitationExpired returns whether the project member invitation has expired.
func (s *Service) IsProjectInvitationExpired(invite *ProjectInvitation) bool {
	return time.Now().After(invite.CreatedAt.Add(s.config.ProjectInvitationExpiration))
}

// GetInvitesByEmail returns project invites by email.
func (s *Service) GetInvitesByEmail(ctx context.Context, email string) (invites []ProjectInvitation, err error) {
	defer mon.Task()(&ctx)(&err)

	return s.store.ProjectInvitations().GetByEmail(ctx, email)
}

// GetInviteByToken returns a project invite given an invite token.
func (s *Service) GetInviteByToken(ctx context.Context, token string) (invite *ProjectInvitation, err error) {
	defer mon.Task()(&ctx)(&err)

	publicProjectID, email, err := s.ParseInviteToken(ctx, token)
	if err != nil {
		return nil, ErrProjectInviteInvalid.Wrap(err)
	}

	project, err := s.store.Projects().GetByPublicID(ctx, publicProjectID)
	if err != nil {
		if !errs.Is(err, sql.ErrNoRows) {
			return nil, Error.Wrap(err)
		}
		return nil, ErrProjectInviteInvalid.New(projInviteInvalidErrMsg)
	}

	invite, err = s.store.ProjectInvitations().Get(ctx, project.ID, email)
	if err != nil {
		if !errs.Is(err, sql.ErrNoRows) {
			return nil, Error.Wrap(err)
		}
		return nil, ErrProjectInviteInvalid.New(projInviteInvalidErrMsg)
	}
	if s.IsProjectInvitationExpired(invite) {
		return nil, ErrProjectInviteInvalid.New(projInviteInvalidErrMsg)
	}

	return invite, nil
}

// GetInviteLink returns a link for project invites.
func (s *Service) GetInviteLink(ctx context.Context, publicProjectID uuid.UUID, email string) (_ string, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get invite link", zap.String("projectID", publicProjectID.String()), zap.String("email", email))
	if err != nil {
		return "", Error.Wrap(err)
	}

	isMember, err := s.isProjectMember(ctx, user.ID, publicProjectID)
	if err != nil {
		return "", Error.Wrap(err)
	}

	invite, err := s.store.ProjectInvitations().Get(ctx, isMember.project.ID, email)
	if err != nil {
		if !errs.Is(err, sql.ErrNoRows) {
			return "", Error.Wrap(err)
		}
		return "", ErrProjectInviteInvalid.New(projInviteInvalidErrMsg)
	}

	token, err := s.CreateInviteToken(ctx, publicProjectID, email, invite.CreatedAt)
	if err != nil {
		return "", Error.Wrap(err)
	}

	return fmt.Sprintf("%s/invited?invite=%s", s.satelliteAddress, token), nil
}

// CreateInviteToken creates a token for project invite links.
// Internal use only, since it doesn't check if the project is valid or the user is a member of the project.
func (s *Service) CreateInviteToken(ctx context.Context, publicProjectID uuid.UUID, email string, inviteDate time.Time) (_ string, err error) {
	defer mon.Task()(&ctx)(&err)

	linkClaims := consoleauth.Claims{
		ID:         publicProjectID,
		Email:      email,
		Expiration: inviteDate.Add(s.config.ProjectInvitationExpiration),
	}

	claimJson, err := linkClaims.JSON()
	if err != nil {
		return "", err
	}

	token := consoleauth.Token{Payload: claimJson}
	signature, err := s.tokens.SignToken(token)
	if err != nil {
		return "", err
	}
	token.Signature = signature

	return token.String(), nil
}

// ParseInviteToken parses a token from project invite links.
func (s *Service) ParseInviteToken(ctx context.Context, token string) (publicID uuid.UUID, email string, err error) {
	defer mon.Task()(&ctx)(&err)

	parsedToken, err := consoleauth.FromBase64URLString(token)
	valid, err := s.tokens.ValidateToken(parsedToken)
	if err != nil {
		return uuid.UUID{}, "", err
	}
	if !valid {
		return uuid.UUID{}, "", ErrTokenInvalid.New("incorrect signature")
	}

	claims, err := consoleauth.FromJSON(parsedToken.Payload)
	if err != nil {
		return uuid.UUID{}, "", ErrTokenInvalid.New("JSON decoder: %w", err)
	}

	if time.Now().After(claims.Expiration) {
		return uuid.UUID{}, "", ErrTokenExpiration.New("invite token expired")
	}

	return claims.ID, claims.Email, nil
}

// TestSetVersioningConfig allows tests to switch the versioning config.
func (s *Service) TestSetVersioningConfig(versioning VersioningConfig) error {
	versioning.projectMap = make(map[uuid.UUID]struct{}, len(versioning.UseBucketLevelObjectVersioningProjects))
	for _, id := range versioning.UseBucketLevelObjectVersioningProjects {
		projectID, err := uuid.FromString(id)
		if err != nil {
			return Error.Wrap(err)
		}
		versioning.projectMap[projectID] = struct{}{}
	}

	s.versioningConfig = versioning

	return nil
}

// TestSetNow allows tests to have the Service act as if the current time is whatever they want.
func (s *Service) TestSetNow(now func() time.Time) {
	s.nowFn = now
}

// CreateSocialShare creates a key-value pair in both the smart contract and the database.
// The initial version is set to "v0.1".
func (s *Service) CreateSocialShare(ctx context.Context, key, value string) (err error) {
	defer mon.Task()(&ctx)(&err)
	initialVersion := "v0.1"

	err = s.socialShareHelper.UploadSocialShare(ctx, key, value, initialVersion)
	if err != nil {
		return Error.Wrap(err)
	}

	err = s.store.Web3Auth().CreateKeyVersion(ctx, []byte(key), initialVersion)
	if err != nil {
		// Rollback? For now, just error.
		return Error.Wrap(err)
	}

	return nil
}

// UpdateSocialShare updates an existing key-value pair. It fetches the current version,
// increments it, and then updates both the smart contract and the database.
func (s *Service) UpdateSocialShare(ctx context.Context, key, value string) (err error) {
	defer mon.Task()(&ctx)(&err)

	currentVersion, err := s.store.Web3Auth().GetKeyVersion(ctx, []byte(key))
	if err != nil {
		return Error.Wrap(err)
	}

	newVersion, err := incrementVersion(currentVersion)
	if err != nil {
		return Error.Wrap(err)
	}

	err = s.socialShareHelper.UpdateSocialShare(ctx, key, value, newVersion)
	if err != nil {
		return Error.Wrap(err)
	}

	err = s.store.Web3Auth().UpdateKeyVersion(ctx, []byte(key), newVersion)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// GetSocialShare retrieves a value from the smart contract for a specific key.
// The version is automatically fetched from the database.
func (s *Service) GetSocialShare(ctx context.Context, key string) (val []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	// 1. Get the current version from the database
	version, err := s.store.Web3Auth().GetKeyVersion(ctx, []byte(key))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// 2. Call the smart contract with the retrieved version
	return s.socialShareHelper.GetSocialShare(ctx, key, version)
}

// GetPaginatedSocialShares retrieves a paginated list of key-value pairs from the smart contract.
func (s *Service) GetPaginatedSocialShares(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	defer mon.Task()(&ctx)(&err)

	return s.socialShareHelper.GetPaginatedKeyValues(ctx, startIndex, count)
}

// GetTotalSocialShares retrieves the total number of keys from the smart contract.
func (s *Service) GetTotalSocialShares(ctx context.Context) (count uint64, err error) {
	defer mon.Task()(&ctx)(&err)

	return s.socialShareHelper.GetTotalKeys(ctx)
}

// SocialShareKeyExists checks if a key already has a version in the database.
func (s *Service) SocialShareKeyExists(ctx context.Context, key string) (exists bool, err error) {
	defer mon.Task()(&ctx)(&err)
	_, err = s.store.Web3Auth().GetKeyVersion(ctx, []byte(key))
	if err != nil {
		if errs.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, Error.Wrap(err)
	}
	return true, nil
}

func incrementVersion(v string) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "v") {
		return "", fmt.Errorf("invalid version format: %s", v)
	}

	majorStr := parts[0][1:]
	_, err := strconv.Atoi(majorStr)
	if err != nil {
		return "", fmt.Errorf("invalid major version: %s", v)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid minor version: %s", v)
	}

	return fmt.Sprintf("v%s.%d", majorStr, minor+1), nil
}

type CreateOAuthClientRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

type UpdateOAuthClientRequest struct {
	Name         *string   `json:"name"`
	Description  *string   `json:"description"`
	RedirectURIs *[]string `json:"redirect_uris"`
	Scopes       *[]string `json:"scopes"`
}

// Redirect URI management requests
type AddRedirectURIRequest struct {
	URI string `json:"uri"`
}

type UpdateRedirectURIRequest struct {
	OldURI string `json:"old_uri"`
	NewURI string `json:"new_uri"`
}

type DeleteRedirectURIRequest struct {
	URI string `json:"uri"`
}

func generateRandomSecret(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func hashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// --- OAuth2Request Service Layer ---

type CreateOAuth2Request struct {
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
}

type OAuth2RequestResponse struct {
	RequestID      uuid.UUID
	ClientName     string
	CurrentAccess  []string
	NeededAccess   []string
	RequiredScopes []string
	OptionalScopes []string
}

func (s *Service) CreateOAuth2Request(ctx context.Context, req CreateOAuth2Request) (*OAuth2RequestResponse, error) {
	// Validate client_id, redirect_uri, scopes (pseudo, expand as needed)
	if req.ClientID == "" || req.RedirectURI == "" || len(req.Scopes) == 0 {
		return nil, errs.New("invalid_request")
	}

	userID, err := s.getUserAndAuditLog(ctx, "create oauth2 request", zap.String("clientID", req.ClientID), zap.String("redirectURI", req.RedirectURI))
	if err != nil {
		return nil, err
	}

	// Validate that the client_id exists and is active
	client, err := s.store.DeveloperOAuthClients().GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errs.New("invalid_client_id")
	}
	if client.Status != 1 { // assuming 1 = active
		return nil, errs.New("client_inactive")
	}

	// Validate that the redirect_uri matches one of the registered URIs for the client
	uriMatch := false
	for _, uri := range client.RedirectURIs {
		fmt.Println("uri", uri)
		fmt.Println("req.RedirectURI", req.RedirectURI)
		if uri == req.RedirectURI {
			uriMatch = true
			break
		}
	}
	if !uriMatch {
		return nil, errs.New("invalid_redirect_uri")
	}

	// TODO: Handle required/optional scopes, and fill CurrentAccess, NeededAccess, RequiredScopes, OptionalScopes in the response
	// TODO: Implement security checks (rate limiting, audit logging, etc.)
	// TODO: Consider PKCE and other OAuth2 best practices for security

	id, err := uuid.New()
	if err != nil {
		return nil, err
	}

	oauthReq := &OAuth2Request{
		ID:               id,
		ClientID:         req.ClientID,
		UserID:           userID.ID,
		RedirectURI:      req.RedirectURI,
		Scopes:           strings.Join(req.Scopes, ","),
		Status:           0, // pending
		ConsentExpiresAt: s.nowFn().Add(1 * time.Minute),
		Code:             "",
		ApprovedScopes:   "",
		RejectedScopes:   "",
	}
	created, err := s.store.OAuth2Requests().Insert(ctx, oauthReq)
	if err != nil {
		return nil, err
	}

	// TODO: Fill CurrentAccess, NeededAccess, RequiredScopes, OptionalScopes as per business logic
	resp := &OAuth2RequestResponse{
		RequestID:      created.ID,
		ClientName:     client.Name,
		CurrentAccess:  []string{},
		NeededAccess:   req.Scopes,
		RequiredScopes: req.Scopes,
		OptionalScopes: []string{},
	}
	return resp, nil
}

// --- OAuth2 Consent Service Layer ---

type ConsentOAuth2Request struct {
	RequestID      uuid.UUID `json:"request_id"`
	Approve        bool      `json:"approve"`
	ApprovedScopes []string  `json:"approved_scopes"`
	RejectedScopes []string  `json:"rejected_scopes"`
}

type ConsentOAuth2Response struct {
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
}

func (s *Service) ConsentOAuth2Request(ctx context.Context, req ConsentOAuth2Request) (*ConsentOAuth2Response, error) {
	// Fetch the OAuth2 request
	oauthReq, err := s.store.OAuth2Requests().Get(ctx, req.RequestID)
	if err != nil {
		return nil, errs.New("invalid_request_id")
	}

	// Validate request is pending (status == 0)
	if oauthReq.Status != 0 {
		return nil, errs.New("request_not_pending")
	}

	// check if the request is expired
	if oauthReq.ConsentExpiresAt.Before(s.nowFn()) {
		return nil, errs.New("request_expired")
	}

	// Validate user matches oauthReq.UserID
	user, err := s.getUserAndAuditLog(ctx, "consent oauth2 request", zap.String("requestID", req.RequestID.String()))
	if err != nil {
		return nil, errs.New("unauthorized")
	}
	if user.ID != oauthReq.UserID {
		return nil, errs.New("forbidden")
	}

	var status int
	var code string
	if req.Approve {
		status = 1 // e.g., STATUS_APPROVED
		// TODO: Generate secure code (authorization code)
		uuID, err := uuid.New()
		if err != nil {
			return nil, errs.New("consent_update_failed")
		}

		code = uuID.String()
	} else {
		status = 2 // e.g., STATUS_REJECTED
		code = "REJECTED"
	}

	err = s.store.OAuth2Requests().UpdateConsent(ctx, req.RequestID,
		status, code, strings.Join(req.ApprovedScopes, ","), strings.Join(req.RejectedScopes, ","), s.nowFn().Add(1*time.Minute))
	if err != nil {
		return nil, errs.New("consent_update_failed")
	}

	return &ConsentOAuth2Response{Code: code, RedirectURI: oauthReq.RedirectURI}, nil
}

// ExchangeOAuth2CodeRequest represents the request to exchange an OAuth2 code for an access grant.
type ExchangeOAuth2CodeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	Passphrase   string `json:"passphrase"`
}

// ExchangeOAuth2CodeResponse represents the response from exchanging an OAuth2 code for an access grant.
type ExchangeOAuth2CodeResponse struct {
	AccessGrant string   `json:"access_grant"`
	Scopes      []string `json:"scopes"`
}

// ExchangeOAuth2Code exchanges an authorization code for a Storj access grant.
func (s *Service) ExchangeOAuth2Code(ctx context.Context, req ExchangeOAuth2CodeRequest) (*ExchangeOAuth2CodeResponse, error) {
	// Validate client credentials
	client, err := s.store.DeveloperOAuthClients().GetByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errs.New("invalid_client_id")
	}

	// Validate client_secret as JWT signed with the stored client secret
	parsedToken, err := jwt.Parse(req.ClientSecret, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(client.ClientSecret), nil
	})
	if err != nil || !parsedToken.Valid {
		fmt.Println("err", err)
		fmt.Println("parsedToken", parsedToken)
		fmt.Println("client.ClientSecret", client.ClientSecret)
		fmt.Println("req.ClientSecret", req.ClientSecret)
		fmt.Println("client.ClientID", client.ClientID)
		fmt.Println("req.ClientID", req.ClientID)
		return nil, errs.New("invalid_client_secret")
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errs.New("invalid_client_secret_claims")
	}

	fmt.Println("claims stage completed")
	// Check client_id in JWT payload
	jwtClientID, ok := claims["client_id"].(string)
	if !ok || jwtClientID != req.ClientID {
		return nil, errs.New("invalid_client_string")
	}
	fmt.Println("client_id stage completed")
	// Check exp in JWT payload
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errs.New("exp_not_found")
	}
	if int64(exp) < s.nowFn().Unix() {
		return nil, errs.New("client_secret_expired")
	}
	fmt.Println("exp stage completed")
	// Get OAuth2 request by code
	oauthReq, err := s.store.OAuth2Requests().GetByCode(ctx, req.Code)
	if err != nil {
		return nil, errs.New("invalid_code")
	}
	fmt.Println("oauthReq stage completed")
	user, err := s.getUserAndAuditLog(ctx, "exchange oauth2 code", zap.String("code", req.Code))
	if err != nil {
		return nil, errs.New("invalid_user")
	}
	fmt.Println("user stage completed")
	if oauthReq.UserID != user.ID {
		return nil, errs.New("invalid_user")
	}
	fmt.Println("user_id stage completed")
	// Validate code status (must be approved)
	if oauthReq.Status != 1 { // 1 = approved
		return nil, errs.New("invalid_code")
	}
	fmt.Println("code_status stage completed")
	if oauthReq.CodeExpiresAt.Before(s.nowFn()) {
		return nil, errs.New("code_expired")
	}
	fmt.Println("code_expires_at stage completed")
	if oauthReq.Code != req.Code {
		return nil, errs.New("invalid_code")
	}
	fmt.Println("code_match stage completed")
	// Validate redirect URI
	uriMatch := false
	if oauthReq.RedirectURI != "" {
		uriMatch = (oauthReq.RedirectURI == req.RedirectURI)
	} else {
		for _, uri := range client.RedirectURIs {
			if uri == req.RedirectURI {
				uriMatch = true
				break
			}
		}
	}
	if !uriMatch {
		return nil, errs.New("invalid_redirect_uri")
	}
	fmt.Println("uri_match stage completed")
	// Get user's projects
	projects, err := s.store.Projects().GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, errs.New("failed_to_get_projects")
	}
	if len(projects) == 0 {
		return nil, errs.New("no_projects")
	}
	project := projects[0]
	fmt.Println("projects stage completed")
	// Create API key for the project
	apiKeyName := fmt.Sprintf("OAUTH2_API_KEY_FOR_%s_%s", req.ClientID, oauthReq.ID.String())
	_, apiKey, err := s.CreateAPIKey(ctx, project.ID, apiKeyName)
	if err != nil {
		return nil, errs.New("failed_to_create_api_key")
	}
	fmt.Println("api_key stage completed")
	// Parse approved scopes
	approvedScopes := strings.Split(oauthReq.ApprovedScopes, ",")
	if len(approvedScopes) == 1 && approvedScopes[0] == "" {
		approvedScopes = nil
	}
	fmt.Println("approved_scopes stage completed")
	permissions := grant.Permission{
		AllowDownload: false,
		AllowUpload:   false,
		AllowList:     false,
		AllowDelete:   false,
		AllowLock:     false,
	}
	prefixes := []grant.SharePrefix{}
	for _, scope := range approvedScopes {
		if scope == "read" {
			permissions.AllowDownload = true
		} else if scope == "write" {
			permissions.AllowUpload = true
		} else if scope == "list" {
			permissions.AllowList = true
		} else if scope == "delete" {
			permissions.AllowDelete = true
		} else if scope == "lock" {
			permissions.AllowLock = true
		} else if strings.HasPrefix(scope, "bucket:") {
			// bucket:bucketName;prefix:prefix
			parts := strings.Split(scope, ";")
			prefix := grant.SharePrefix{Bucket: strings.TrimPrefix(parts[0], "bucket:") + "/"}
			if len(parts) == 2 {
				prefix.Prefix = parts[1]
			}
			prefixes = append(prefixes, prefix)
		}
	}
	fmt.Println("prefixes stage completed")
	if len(prefixes) == 0 {
		prefixes = nil
	}
	fmt.Println("prefixes_len stage completed")
	// Create access grant
	accessGrant, err := s.CreateAccessGrantForProject(ctx, project.ID, req.Passphrase, prefixes, &permissions, apiKey)
	if err != nil {
		return nil, errs.New("failed_to_create_access_grant")
	}
	fmt.Println("access_grant stage completed")
	// Mark code as used
	err = s.store.OAuth2Requests().MarkCodeUsed(ctx, oauthReq.ID)
	if err != nil {
		return nil, errs.New("failed_to_mark_code_used")
	}
	fmt.Println("mark_code_used stage completed")
	// Audit log the token exchange
	s.auditLog(ctx, "exchange oauth2 code", &user.ID, user.Email, zap.String("code", req.Code), zap.String("client_id", req.ClientID))

	return &ExchangeOAuth2CodeResponse{
		AccessGrant: accessGrant,
		Scopes:      approvedScopes,
	}, nil
}

// SubscribeNewsletter subscribes an email to the newsletter.
func (s *Service) SubscribeNewsletter(ctx context.Context, email string) (_ *EmailSubscription, err error) {
	defer mon.Task()(&ctx)(&err)

	subscription, err := s.store.EmailSubscriptions().Subscribe(ctx, email)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return subscription, nil
}

// UnsubscribeNewsletter unsubscribes an email from the newsletter.
func (s *Service) UnsubscribeNewsletter(ctx context.Context, email string) (err error) {
	defer mon.Task()(&ctx)(&err)

	err = s.store.EmailSubscriptions().Unsubscribe(ctx, email)
	if err != nil {
		return Error.Wrap(err)
	}

	return nil
}

// GetUserDeveloperAccess returns all developers with access to the current user's account
func (s *Service) GetUserDeveloperAccess(ctx context.Context) (_ []UserDeveloperAccess, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get user developer access")
	if err != nil {
		return nil, err
	}

	access, err := s.store.OAuth2Requests().GetUserDeveloperAccess(ctx, user.ID)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return access, nil
}

// GetUserDeveloperAccessHistory returns access history for a specific developer
func (s *Service) GetUserDeveloperAccessHistory(ctx context.Context, clientID string) (_ []UserAccessHistory, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "get user developer access history", zap.String("clientID", clientID))
	if err != nil {
		return nil, err
	}

	history, err := s.store.OAuth2Requests().GetUserDeveloperAccessHistory(ctx, user.ID, clientID)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return history, nil
}

// RevokeUserDeveloperAccess revokes a developer's access to the current user's account
func (s *Service) RevokeUserDeveloperAccess(ctx context.Context, clientID string) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := s.getUserAndAuditLog(ctx, "revoke user developer access", zap.String("clientID", clientID))
	if err != nil {
		return err
	}

	// Verify the client exists and user has access to it
	accessList, err := s.store.OAuth2Requests().GetUserDeveloperAccess(ctx, user.ID)
	if err != nil {
		return errs.Wrap(err)
	}

	// Check if user has active access to this client
	hasActiveAccess := false
	for _, access := range accessList {
		if access.ClientID == clientID && access.IsActive {
			hasActiveAccess = true
			break
		}
	}

	if !hasActiveAccess {
		return errs.New("no active access found for this developer")
	}

	// Revoke access
	err = s.store.OAuth2Requests().RevokeUserDeveloperAccess(ctx, user.ID, clientID)
	if err != nil {
		return errs.Wrap(err)
	}

	return nil
}
