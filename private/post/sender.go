// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information

package post

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/mail"
	"net/smtp"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
)

// Address is alias of net/mail.Address.
type Address = mail.Address

var mon = monkit.Package()

// SMTPSender is smtp sender.
type SMTPSender struct {
	ServerAddress string

	From Address
	Auth smtp.Auth
}

// FromAddress implements satellite/mail.SMTPSender.
func (sender *SMTPSender) FromAddress() Address {
	return sender.From
}

// SendEmail sends email message to the given recipient.
func (sender *SMTPSender) SendEmail(ctx context.Context, msg *Message) (err error) {
	defer mon.Task()(&ctx)(&err)

	client, implicitTLS, err := sender.dialSMTP()
	if err != nil {
		return err
	}

	if err = sender.communicate(ctx, client, implicitTLS, msg); err != nil {
		return errs.Combine(err, client.Close())
	}

	return nil
}

// Verify checks SMTP host reachability, TLS, and auth without sending a message.
// Port 465 uses implicit SSL; other ports (e.g. 587) use STARTTLS.
func (sender *SMTPSender) Verify(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	client, implicitTLS, err := sender.dialSMTP()
	if err != nil {
		return errs.New("SMTP dial failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	host, _, _ := net.SplitHostPort(sender.ServerAddress)
	if sender.Auth != nil {
		if !implicitTLS {
			if err = client.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return errs.New("SMTP STARTTLS failed: %v", err)
			}
		}
		if err = client.Auth(sender.Auth); err != nil {
			return errs.New("SMTP authentication failed: %v", err)
		}
	}

	if err = client.Quit(); err != nil {
		return errs.New("SMTP quit failed: %v", err)
	}
	return nil
}

// dialSMTP connects to the SMTP server.
// Port 465 (SMTPS) uses an implicit TLS connection; otherwise a plain dial is used
// and STARTTLS is applied later in communicate/Verify.
func (sender *SMTPSender) dialSMTP() (client *smtp.Client, implicitTLS bool, err error) {
	host, port, err := net.SplitHostPort(sender.ServerAddress)
	if err != nil {
		return nil, false, err
	}

	if port == "465" {
		conn, dialErr := tls.Dial("tcp", sender.ServerAddress, &tls.Config{ServerName: host})
		if dialErr != nil {
			return nil, false, dialErr
		}
		client, err = smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return nil, false, err
		}
		return client, true, nil
	}

	client, err = smtp.Dial(sender.ServerAddress)
	if err != nil {
		return nil, false, err
	}
	return client, false, nil
}

// communicate sends mail via SMTP using provided client and message.
func (sender *SMTPSender) communicate(ctx context.Context, client *smtp.Client, implicitTLS bool, msg *Message) error {
	// suppress error because address should be validated
	// before creating SMTPSender
	host, _, _ := net.SplitHostPort(sender.ServerAddress)

	if sender.Auth != nil {
		if !implicitTLS {
			// Port 587 / submission: upgrade with STARTTLS first.
			err := client.StartTLS(&tls.Config{ServerName: host})
			if err != nil {
				return err
			}
		}

		err := client.Auth(sender.Auth)
		if err != nil {
			return err
		}
	}

	err := client.Mail(sender.From.Address)
	if err != nil {
		return err
	}

	// add recipients
	for _, to := range msg.To {
		err = client.Rcpt(to.Address)
		if err != nil {
			return err
		}
	}

	mess, err := msg.Bytes()
	if err != nil {
		return err
	}

	data, err := client.Data()
	if err != nil {
		return err
	}

	err = writeData(data, mess)
	if err != nil {
		return err
	}

	// send quit msg to stop gracefully
	return client.Quit()
}

// writeData ensures that writer will be closed after data is written.
func writeData(writer io.WriteCloser, data []byte) (err error) {
	defer func() {
		err = errs.Combine(err, writer.Close())
	}()

	_, err = writer.Write(data)
	return
}
