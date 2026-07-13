// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package mailservice_test

import (
	"context"
	"testing"

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
