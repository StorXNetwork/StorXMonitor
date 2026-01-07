// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package replication

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"
)

// WebhookSender sends webhook events to Backuptools with retry logic.
type WebhookSender struct {
	client     *http.Client
	url        string
	publicKey  *rsa.PublicKey
	log        *zap.Logger
	maxRetries int
	retryDelay time.Duration
}

// NewWebhookSender creates a new webhook sender with RSA public key encryption.
func NewWebhookSender(log *zap.Logger, url, publicKeyPath string, maxRetries int, retryDelay, timeout time.Duration) (*WebhookSender, error) {
	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return nil, Error.Wrap(fmt.Errorf("failed to load public key from %s: %w", publicKeyPath, err))
	}

	return &WebhookSender{
		client: &http.Client{
			Timeout: timeout,
		},
		url:        url,
		publicKey:  publicKey,
		log:        log,
		maxRetries: maxRetries,
		retryDelay: retryDelay,
	}, nil
}

// loadPublicKey loads an RSA public key from a PEM file.
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, Error.New("failed to decode PEM block")
	}

	var pub interface{}
	if block.Type == "PUBLIC KEY" {
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	} else if block.Type == "RSA PUBLIC KEY" {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	} else {
		return nil, Error.New("unsupported key type: %s", block.Type)
	}
	if err != nil {
		return nil, Error.Wrap(err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, Error.New("not an RSA public key")
	}

	return rsaPub, nil
}

// encryptPayload encrypts the payload using hybrid encryption (RSA + AES).
func (w *WebhookSender) encryptPayload(plaintext []byte) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, Error.Wrap(err)
	}

	encryptedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		w.publicKey,
		aesKey,
		nil,
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, Error.Wrap(err)
	}

	encryptedPayload := gcm.Seal(nonce, nonce, plaintext, nil)

	result := fmt.Sprintf("%s:%s",
		base64.URLEncoding.EncodeToString(encryptedAESKey),
		base64.URLEncoding.EncodeToString(encryptedPayload),
	)

	return []byte(result), nil
}

// SendEvent sends an event to the webhook endpoint with retry logic.
func (w *WebhookSender) SendEvent(ctx context.Context, event TableChangeEvent) error {
	plaintext, err := json.Marshal(event)
	if err != nil {
		mon.Counter("replication_webhook_marshal_error").Inc(1)
		return Error.Wrap(err)
	}

	encryptedPayload, err := w.encryptPayload(plaintext)
	if err != nil {
		mon.Counter("replication_webhook_encrypt_error").Inc(1)
		return Error.Wrap(err)
	}

	var lastErr error
	for attempt := 0; attempt < w.maxRetries; attempt++ {
		if attempt > 0 {
			backoffDelay := w.retryDelay * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDelay):
			}
		}

		err := w.sendRequest(ctx, encryptedPayload)
		if err == nil {
			mon.Counter("replication_webhook_sent_total",
				monkit.NewSeriesTag("operation", event.Operation),
				monkit.NewSeriesTag("table", event.Table),
			).Inc(1)
			w.log.Info("webhook sent successfully",
				zap.String("operation", event.Operation),
				zap.String("table", event.Table),
				zap.Int("attempt", attempt+1),
			)
			return nil
		}

		lastErr = err
		mon.Counter("replication_webhook_retry_total",
			monkit.NewSeriesTag("operation", event.Operation),
			monkit.NewSeriesTag("attempt", fmt.Sprintf("%d", attempt+1)),
		).Inc(1)

		w.log.Warn("webhook send failed, retrying",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", w.maxRetries),
			zap.String("operation", event.Operation),
		)
	}

	mon.Counter("replication_webhook_failed_total",
		monkit.NewSeriesTag("operation", event.Operation),
		monkit.NewSeriesTag("table", event.Table),
	).Inc(1)

	return ErrWebhookFailed.Wrap(fmt.Errorf("failed after %d retries: %w", w.maxRetries, lastErr))
}

// sendRequest sends a single HTTP request with encrypted payload.
func (w *WebhookSender) sendRequest(ctx context.Context, encryptedPayload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(encryptedPayload))
	if err != nil {
		return Error.Wrap(err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Encryption", "RSA-AES")

	resp, err := w.client.Do(req)
	if err != nil {
		return Error.Wrap(err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			w.log.Warn("failed to close response body", zap.Error(closeErr))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Error.New("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
