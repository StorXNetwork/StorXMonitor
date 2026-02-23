package post

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strconv"

	gomail "gopkg.in/mail.v2"
)

type MailV2 struct {
	ServerAddress string

	From Address
	Auth LoginAuth
}

func (m *MailV2) FromAddress() Address {
	return m.From
}

func (m *MailV2) SendEmail(ctx context.Context, msg *Message) (err error) {
	// Debug: log attempt
	toAddrs := make([]string, len(msg.To))
	for i, to := range msg.To {
		toAddrs[i] = to.Address
	}
	log.Printf("[mailv2] SendEmail: from=%q to=%v subject=%q", m.From.String(), toAddrs, msg.Subject)

	host, portStr, err := net.SplitHostPort(m.ServerAddress)
	if err != nil {
		log.Printf("[mailv2] SendEmail failed (parse address): %v", err)
		return err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("[mailv2] SendEmail failed (parse port %q): %v", portStr, err)
		return err
	}
	log.Printf("[mailv2] connecting to %s (host=%s port=%d) user=%q", m.ServerAddress, host, p, m.Auth.Username)

	g := gomail.NewMessage()
	g.SetHeader("From", m.From.String())
	if len(msg.To) > 0 {
		toStrs := make([]string, len(msg.To))
		for i, to := range msg.To {
			toStrs[i] = to.String()
		}
		g.SetHeader("To", toStrs...)
	}
	g.SetHeader("Subject", msg.Subject)

	if len(msg.Parts) > 0 {
		g.SetBody(msg.Parts[0].Type, msg.Parts[0].Content)
	} else if msg.PlainText != "" {
		g.SetBody("text/plain; charset=UTF-8", msg.PlainText)
	} else {
		g.SetBody("text/plain; charset=UTF-8", "")
	}

	d := gomail.NewDialer(host, p, m.Auth.Username, m.Auth.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if p == 465 {
		d.SSL = true
	}

	if err = d.DialAndSend(g); err != nil {
		log.Printf("[mailv2] SendEmail failed: %v", err)
		return err
	}
	log.Printf("[mailv2] sent successfully to %v", toAddrs)
	return nil
}
