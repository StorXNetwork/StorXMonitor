// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package mailservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/StorXNetwork/StorXMonitor/private/post"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice"
	"github.com/StorXNetwork/StorXMonitor/satellite/mailservice/simulate"
	"github.com/StorXNetwork/StorXMonitor/satellite/tenancy"
	"github.com/StorXNetwork/common/uuid"
)

type captureSender struct {
	last *post.Message
}

func (c *captureSender) FromAddress() post.Address {
	return post.Address{Address: "noreply@test.local"}
}

func (c *captureSender) SendEmail(ctx context.Context, msg *post.Message) error {
	c.last = msg
	return nil
}

func TestSendRenderedUsesDefaultSenderForResellerTenant(t *testing.T) {
	sender := &captureSender{}
	svc, err := mailservice.New(
		zaptest.NewLogger(t),
		sender,
		"",
		mailservice.TenantConfig{},
		mailservice.WhiteLabelConfig{
			BrandName:    "CyberLS",
			CompanyName:  "CyberLS",
			HomepageURL:  "https://cyberls.com",
			SupportURL:   "mailto:support@cyberls.com",
			PrimaryColor: "#0052FF",
		},
	)
	require.NoError(t, err)

	resellerID, err := uuid.FromString("4757ae17-b919-40bc-b91c-c731f3569a9a")
	require.NoError(t, err)

	svc.SetBrandingResolver(func(ctx context.Context) (mailservice.WhiteLabelConfig, bool) {
		if tenancy.ResellerIDFromContext(ctx) == resellerID {
			return mailservice.WhiteLabelConfig{
				BrandName:    "Acme Cloud",
				CompanyName:  "Acme Corp",
				HomepageURL:  "https://portal.acme.com",
				SupportURL:   "mailto:support@acme.com",
				PrimaryColor: "#0149FF",
			}, true
		}
		return mailservice.WhiteLabelConfig{}, false
	})

	ctx := tenancy.WithContext(context.Background(), &tenancy.Context{
		TenantID:   resellerID.String(),
		ResellerID: resellerID,
	})

	err = svc.SendRendered(ctx, []post.Address{{Address: "dhavalder93@gmail.com"}}, &console.LoginNotificationEmail{
		Username:   "Dhaval",
		Device:     "Desktop",
		Browser:    "Chrome",
		Location:   "Unknown Location",
		IPAddress:  "127.0.0.1",
		LoginTime:  "January 2, 2006 at 3:04 PM MST",
		SignInLink: "https://portal.acme.com/login",
	})
	require.NoError(t, err, "reseller tenant must fall back to default SMTP sender")
	require.NotNil(t, sender.last)
	require.Contains(t, sender.last.Subject, "Acme Cloud")
	require.Contains(t, sender.last.Parts[0].Content, "Acme Cloud")
	require.Contains(t, sender.last.Parts[0].Content, `bgcolor="#0149FF"`)
	require.NotContains(t, sender.last.Parts[0].Content, "StorX Network")
	require.NotContains(t, sender.last.Parts[0].Content, `background-color: {{ .PrimaryColor }}`)
}

func TestSendRenderedMainTenantStillWorks(t *testing.T) {
	sender := &captureSender{}
	svc, err := mailservice.New(
		zaptest.NewLogger(t),
		sender,
		"",
		mailservice.TenantConfig{},
		mailservice.WhiteLabelConfig{
			BrandName:   "CyberLS",
			CompanyName: "CyberLS",
		},
	)
	require.NoError(t, err)

	err = svc.SendRendered(context.Background(), []post.Address{{Address: "dhavalder93@gmail.com"}}, &console.LoginNotificationEmail{
		Username:  "Dhaval",
		SignInLink: "https://cyberls.com/login",
	})
	require.NoError(t, err)
	require.Contains(t, sender.last.Subject, "CyberLS")
}

func TestSendRenderedUsesSenderResolverForReseller(t *testing.T) {
	defaultSender := &captureSender{}
	resellerSender := &captureSender{}

	svc, err := mailservice.New(
		zaptest.NewLogger(t),
		defaultSender,
		"",
		mailservice.TenantConfig{},
		mailservice.WhiteLabelConfig{BrandName: "CyberLS", CompanyName: "CyberLS"},
	)
	require.NoError(t, err)

	resellerID, err := uuid.New()
	require.NoError(t, err)

	svc.SetSenderResolver(func(ctx context.Context) (mailservice.Sender, bool) {
		if tenancy.ResellerIDFromContext(ctx) == resellerID {
			return resellerSender, true
		}
		return nil, false
	})

	ctx := tenancy.WithContext(context.Background(), &tenancy.Context{
		TenantID:   resellerID.String(),
		ResellerID: resellerID,
	})

	err = svc.SendRendered(ctx, []post.Address{{Address: "user@example.com"}}, &console.ForgotPasswordEmail{
		UserName:  "User",
		ResetLink: "https://portal.acme.com/reset",
	})
	require.NoError(t, err)
	require.NotNil(t, resellerSender.last)
	require.Nil(t, defaultSender.last)

	err = svc.SendRendered(context.Background(), []post.Address{{Address: "user@example.com"}}, &console.ForgotPasswordEmail{
		UserName:  "User",
		ResetLink: "https://cyberls.com/reset",
	})
	require.NoError(t, err)
	require.NotNil(t, defaultSender.last)
}

func TestSimulateSenderAcceptsResellerTenant(t *testing.T) {
	log := zaptest.NewLogger(t)
	svc, err := mailservice.New(
		log,
		simulate.NewDefaultLinkClicker(log),
		"",
		mailservice.TenantConfig{},
		mailservice.WhiteLabelConfig{BrandName: "CyberLS", CompanyName: "CyberLS"},
	)
	require.NoError(t, err)

	resellerID, err := uuid.New()
	require.NoError(t, err)
	ctx := tenancy.WithContext(context.Background(), &tenancy.Context{
		TenantID:   resellerID.String(),
		ResellerID: resellerID,
	})

	err = svc.SendRendered(ctx, []post.Address{{Address: "dhavalder93@gmail.com"}}, &console.ForgotPasswordEmail{
		UserName:  "Dhaval",
		ResetLink: "https://portal.acme.com/reset",
	})
	require.NoError(t, err)
}

func TestRenderAllPresentEmailTemplates(t *testing.T) {
	t.Parallel()

	sender := &captureSender{}
	svc, err := mailservice.New(
		zaptest.NewLogger(t),
		sender,
		"",
		mailservice.TenantConfig{},
		mailservice.WhiteLabelConfig{
			BrandName:    "CyberLS",
			CompanyName:  "CyberLS",
			LogoURL:      "https://cyberls.com/cyberls-pulse-horizontal-fullcolor.svg",
			HomepageURL:  "https://cyberls.com",
			PrimaryColor: "#0d1724",
			SupportURL:   "mailto:support@cyberls.com",
		},
	)
	require.NoError(t, err)

	tests := []struct {
		name string
		msg  mailservice.Message
		want []string
	}{
		{
			name: "LoginNotification",
			msg: &console.LoginNotificationEmail{
				Username: "Dhaval", Device: "Desktop", Browser: "Chrome",
				Location: "Unknown", IPAddress: "127.0.0.1", LoginTime: "now",
				SignInLink: "https://cyberls.com/login",
			},
			want: []string{"Dhaval", "127.0.0.1", "CyberLS", `bgcolor="#0d1724"`, "cyberls-pulse-horizontal-fullcolor.svg"},
		},
		{
			name: "Forgot",
			msg:  &console.ForgotPasswordEmail{UserName: "Dhaval", ResetLink: "https://cyberls.com/reset"},
			want: []string{"Dhaval", "https://cyberls.com/reset", `bgcolor="#0d1724"`},
		},
		{
			name: "AccountActivated",
			msg:  &console.AccountActivatedEmail{Username: "Dhaval", SignInLink: "https://cyberls.com/login"},
			want: []string{"Dhaval", "Sign In to Your Account"},
		},
		{
			name: "Welcome",
			msg:  &console.AccountActivationEmail{Username: "Dhaval", ActivationLink: "https://cyberls.com/activate"},
			want: []string{"Verify My Account", "https://cyberls.com/activate"},
		},
		{
			name: "WelcomeWithCode",
			msg:  &console.AccountActivationCodeEmail{ActivationCode: "123456"},
			want: []string{"123456"},
		},
		{
			name: "RegistrationWelcome",
			msg:  &console.RegistrationWelcomeEmail{Username: "Dhaval", LoginLink: "https://cyberls.com/login"},
			want: []string{"Dhaval", "https://cyberls.com/login"},
		},
		{
			name: "ExistingUserInvite",
			msg:  &console.ExistingUserProjectInvitationEmail{InviterEmail: "boss@x.com", SignInLink: "https://cyberls.com/login"},
			want: []string{"boss@x.com", "Sign In"},
		},
		{
			name: "NewUserInvite",
			msg:  &console.NewUserProjectInvitationEmail{InviterEmail: "boss@x.com", SignUpLink: "https://cyberls.com/signup"},
			want: []string{"boss@x.com", "Create Account"},
		},
		{
			name: "UnverifiedUserInvite",
			msg:  &console.UnverifiedUserProjectInvitationEmail{InviterEmail: "boss@x.com", ActivationLink: "https://cyberls.com/activate"},
			want: []string{"boss@x.com", "Activate Account"},
		},
		{
			name: "AccountAlreadyExists",
			msg:  &console.AccountAlreadyExistsEmail{SignInLink: "https://cyberls.com/login", ResetPasswordLink: "https://cyberls.com/reset"},
			want: []string{"Sign In", "Reset password"},
		},
		{
			name: "UnknownReset",
			msg:  &console.UnknownResetPasswordEmail{Email: "a@b.com", ResetPasswordLink: "https://cyberls.com/reset", CreateAnAccountLink: "https://cyberls.com/signup"},
			want: []string{"a@b.com"},
		},
		{
			name: "LoginLockAccount",
			msg:  &console.LoginLockAccountEmail{LockoutDuration: 15 * time.Minute, ResetPasswordLink: "https://cyberls.com/reset"},
			want: []string{"15m0s", "Reset Password"},
		},
		{
			name: "ActivationLockAccount",
			msg:  &console.ActivationLockAccountEmail{LockoutDuration: 10 * time.Minute, SupportURL: "mailto:support@cyberls.com"},
			want: []string{"10m0s", "Contact Support"},
		},
		{
			name: "AccountDeactivated",
			msg:  &console.AccountDeactivatedEmail{Username: "Dhaval", SupportURL: "mailto:support@cyberls.com"},
			want: []string{"Dhaval", "Contact Support"},
		},
		{
			name: "PlanPurchased",
			msg:  &console.PlanPurchasedEmail{Username: "Dhaval", PlanName: "Pro", Price: "$10", SignInLink: "https://cyberls.com/login"},
			want: []string{"Pro", "$10"},
		},
		{
			name: "StorageUsageReminder",
			msg:  &console.StorageUsageEmail{UserName: "Dhaval", ProjectName: "Vault", Percentage: 85, StorageUsed: 42.5, Limit: 50, SignInLink: "https://cyberls.com/login"},
			want: []string{"Vault", "85%", "42.50 GB", "50.00 GB"},
		},
		{
			name: "TrialExpirationReminder",
			msg:  &console.TrialExpirationReminderEmail{SignInLink: "https://cyberls.com/login", ContactInfoURL: "mailto:support@cyberls.com"},
			want: []string{"Sign In to Upgrade"},
		},
		{
			name: "TrialExpired",
			msg:  &console.TrialExpiredEmail{SignInLink: "https://cyberls.com/login"},
			want: []string{"Sign In to Upgrade"},
		},
		{
			name: "ContactUsSubmitted",
			msg:  &console.ContactUsSubmittedEmail{Name: "Dhaval", Email: "a@b.com", Message: "hello"},
			want: []string{"Dhaval"},
		},
		{
			name: "ContactUsAdminEmail",
			msg:  &console.ContactUsForm{Name: "Dhaval", Email: "a@b.com", Message: "need help"},
			want: []string{"Dhaval", "need help"},
		},
		{
			name: "DeveloperAccountCreation",
			msg:  &console.DeveloperAccountCreationEmail{FullName: "Dev", Email: "dev@x.com", ActivationLink: "https://cyberls.com/dev"},
			want: []string{"Dev", "Activate Account"},
		},
		{
			name: "AutoBackupFailure",
			msg:  &console.AutoBackupFailureEmail{Email: "a@b.com", Error: "timeout", Method: "scheduled"},
			want: []string{"timeout", "scheduled"},
		},
		{
			name: "UpgradeExpired",
			msg:  &console.UpgradeExpiredEmail{UserName: "Dhaval"},
			want: []string{"Dhaval"},
		},
		{
			name: "UpgradeExpiring",
			msg:  &console.UpgradeExpiringEmail{UserName: "Dhaval", ExpireOn: "2026-09-01"},
			want: []string{"Dhaval", "2026-09-01"},
		},
		{
			name: "UpgradeSuccessfull",
			msg:  &console.UpgradeSuccessfullEmail{UserName: "Dhaval", GBsize: "100GB", Bandwidth: "1TB"},
			want: []string{"Dhaval", "100GB", "1TB"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			local := &captureSender{}
			svc2, err := mailservice.New(
				zaptest.NewLogger(t),
				local,
				"",
				mailservice.TenantConfig{},
				mailservice.WhiteLabelConfig{
					BrandName:    "CyberLS",
					CompanyName:  "CyberLS",
					LogoURL:      "https://cyberls.com/cyberls-pulse-horizontal-fullcolor.svg",
					HomepageURL:  "https://cyberls.com",
					PrimaryColor: "#0d1724",
					SupportURL:   "mailto:support@cyberls.com",
				},
			)
			require.NoError(t, err)

			err = svc2.SendRendered(context.Background(), []post.Address{{Address: "test@example.com"}}, tt.msg)
			require.NoError(t, err, "template %s should render", tt.msg.Template())
			require.NotNil(t, local.last)
			require.NotEmpty(t, local.last.Parts)
			body := local.last.Parts[0].Content
			require.NotContains(t, body, "{{ .")
			for _, w := range tt.want {
				require.Contains(t, body, w)
			}
		})
	}

	_ = svc
}
