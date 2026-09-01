// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package mailservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/StorXMonitor/private/post"
)

// VerifySMTPConfig dials the SMTP host, upgrades to TLS when needed, and authenticates.
// It does not send a message. Uses the same CreateSender path as production mail.
func VerifySMTPConfig(ctx context.Context, cfg Config) (err error) {
	defer mon.Task()(&ctx)(&err)

	sender, err := CreateSender(cfg)
	if err != nil {
		return err
	}

	switch s := sender.(type) {
	case *post.SMTPSender:
		return s.Verify(ctx)
	case *post.MailV2:
		return s.Verify(ctx)
	default:
		return errs.New("SMTP verify is not supported for auth type %q", cfg.AuthType)
	}
}

// SendTestEmail sends a short test message using the same CreateSender path as production mail.
func SendTestEmail(ctx context.Context, cfg Config, toAddress string) (err error) {
	defer mon.Task()(&ctx)(&err)

	toAddress = strings.TrimSpace(toAddress)
	if toAddress == "" {
		return errs.New("recipient address is required")
	}

	sender, err := CreateSender(cfg)
	if err != nil {
		return err
	}

	from := sender.FromAddress()
	subject := fmt.Sprintf("SMTP test from %s", from.Address)

	msg := &post.Message{
		From:    from,
		To:      []post.Address{{Address: toAddress}},
		Subject: subject,
		Parts: []post.Part{{
			Type:    "text/plain; charset=UTF-8",
			Content: "This is a test email from your seller mail settings. If you received it, SMTP is configured correctly.",
		}},
	}

	return sender.SendEmail(ctx, msg)
}
