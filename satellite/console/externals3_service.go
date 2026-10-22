// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/StorXNetwork/common/encryption"
	"github.com/StorXNetwork/common/storxnetwork"
	"github.com/StorXNetwork/common/uuid"
)

// GetExternalS3 returns the current user's external S3 backend status (no secrets).
func (s *Service) GetExternalS3(ctx context.Context) (resp *ExternalS3Response, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	backend, err := s.store.ExternalS3Backends().GetByUserID(ctx, user.ID)
	if err != nil {
		if ErrExternalS3NotFound.Has(err) {
			return &ExternalS3Response{Enabled: false}, nil
		}
		return nil, Error.Wrap(err)
	}
	if backend.Status == ExternalS3StatusDisabled {
		return &ExternalS3Response{Enabled: false, Status: backend.Status}, nil
	}
	return &ExternalS3Response{
		Enabled:            backend.Status == ExternalS3StatusActive,
		Status:             backend.Status,
		Endpoint:           backend.Endpoint,
		Region:             backend.Region,
		AccessKeyID:        backend.AccessKeyID,
		GatewayAccessKeyID: backend.GatewayAccessKeyID,
		GatewayEndpoint:    backend.GatewayEndpoint,
	}, nil
}

// UpsertExternalS3 saves encrypted S3 app credentials and registers them with authservice.
func (s *Service) UpsertExternalS3(ctx context.Context, req UpsertExternalS3Request) (resp *ExternalS3Response, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}

	endpoint := strings.TrimSpace(req.Endpoint)
	accessKeyID := strings.TrimSpace(req.AccessKeyID)
	secretKey := strings.TrimSpace(req.SecretKey)
	region := NormalizeExternalS3Region(req.Region)
	if endpoint == "" || accessKeyID == "" || secretKey == "" {
		return nil, ErrValidation.New("endpoint, access_key_id, and secret_key are required")
	}

	secretEnc, secretKeyID, err := s.encryptExternalS3Secret(ctx, []byte(secretKey))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	gw, err := s.registerExternalS3WithAuth(ctx, endpoint, accessKeyID, secretKey, region)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	gwSecretEnc, gwSecretKeyID, err := s.encryptExternalS3Secret(ctx, []byte(gw.SecretKey))
	if err != nil {
		return nil, Error.Wrap(err)
	}

	backend := &ExternalS3Backend{
		UserID:             user.ID,
		Status:             ExternalS3StatusActive,
		Endpoint:           endpoint,
		Region:             region,
		AccessKeyID:        accessKeyID,
		SecretEnc:          secretEnc,
		SecretKeyID:        secretKeyID,
		GatewayAccessKeyID: gw.AccessKeyID,
		GatewaySecretEnc:   gwSecretEnc,
		GatewaySecretKeyID: gwSecretKeyID,
		GatewayEndpoint:    gw.Endpoint,
	}
	if err = s.store.ExternalS3Backends().Upsert(ctx, backend); err != nil {
		return nil, Error.Wrap(err)
	}

	return &ExternalS3Response{
		Enabled:            true,
		Status:             ExternalS3StatusActive,
		Endpoint:           endpoint,
		Region:             region,
		AccessKeyID:        accessKeyID,
		GatewayAccessKeyID: gw.AccessKeyID,
		GatewayEndpoint:    gw.Endpoint,
		GatewaySecretKey:   gw.SecretKey,
	}, nil
}

// DeleteExternalS3 removes the user's external S3 backend.
func (s *Service) DeleteExternalS3(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return ErrUnauthorized.Wrap(err)
	}
	return Error.Wrap(s.store.ExternalS3Backends().Delete(ctx, user.ID))
}

// EnsureExternalS3Gateway returns usable gateway credentials, re-registering with auth if needed.
func (s *Service) EnsureExternalS3Gateway(ctx context.Context, userID uuid.UUID) (accessKeyID, secretKey, endpoint string, err error) {
	defer mon.Task()(&ctx)(&err)

	backend, err := s.store.ExternalS3Backends().GetByUserID(ctx, userID)
	if err != nil {
		return "", "", "", err
	}
	if backend.Status == ExternalS3StatusDisabled {
		return "", "", "", ErrExternalS3NotFound.New("external s3 disabled")
	}
	if len(backend.SecretEnc) == 0 {
		return "", "", "", ErrExternalS3NeedsReauth.New("re-enter S3 credentials")
	}

	if backend.GatewayAccessKeyID != "" && len(backend.GatewaySecretEnc) > 0 && backend.GatewayEndpoint != "" {
		cachedSecret, decErr := s.decryptExternalS3Secret(ctx, backend.GatewaySecretKeyID, backend.GatewaySecretEnc)
		if decErr == nil && s.authHasGatewayKey(ctx, backend.GatewayAccessKeyID) {
			return backend.GatewayAccessKeyID, string(cachedSecret), backend.GatewayEndpoint, nil
		}
	}

	appSecret, err := s.decryptExternalS3Secret(ctx, backend.SecretKeyID, backend.SecretEnc)
	if err != nil {
		return "", "", "", Error.Wrap(err)
	}
	gw, err := s.registerExternalS3WithAuth(ctx, backend.Endpoint, backend.AccessKeyID, string(appSecret), NormalizeExternalS3Region(backend.Region))
	if err != nil {
		return "", "", "", Error.Wrap(err)
	}
	gwSecretEnc, gwSecretKeyID, err := s.encryptExternalS3Secret(ctx, []byte(gw.SecretKey))
	if err != nil {
		return "", "", "", Error.Wrap(err)
	}
	backend.Status = ExternalS3StatusActive
	backend.GatewayAccessKeyID = gw.AccessKeyID
	backend.GatewaySecretEnc = gwSecretEnc
	backend.GatewaySecretKeyID = gwSecretKeyID
	backend.GatewayEndpoint = gw.Endpoint
	if err = s.store.ExternalS3Backends().Upsert(ctx, backend); err != nil {
		return "", "", "", Error.Wrap(err)
	}
	return gw.AccessKeyID, gw.SecretKey, gw.Endpoint, nil
}

// EnsureExternalS3GatewayForCurrentUser is the owner-facing ensure for vault unlock.
func (s *Service) EnsureExternalS3GatewayForCurrentUser(ctx context.Context) (resp *ExternalS3Response, err error) {
	defer mon.Task()(&ctx)(&err)

	user, err := GetUser(ctx)
	if err != nil {
		return nil, ErrUnauthorized.Wrap(err)
	}
	accessKeyID, secretKey, endpoint, err := s.EnsureExternalS3Gateway(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	backend, _ := s.store.ExternalS3Backends().GetByUserID(ctx, user.ID)
	resp = &ExternalS3Response{
		Enabled:            true,
		Status:             ExternalS3StatusActive,
		GatewayAccessKeyID: accessKeyID,
		GatewayEndpoint:    endpoint,
		GatewaySecretKey:   secretKey,
	}
	if backend != nil {
		resp.Endpoint = backend.Endpoint
		resp.Region = backend.Region
		resp.AccessKeyID = backend.AccessKeyID
		resp.Status = backend.Status
	}
	return resp, nil
}

type externalS3GatewayCreds struct {
	AccessKeyID string
	SecretKey   string
	Endpoint    string
}

func (s *Service) registerExternalS3WithAuth(ctx context.Context, endpoint, accessKeyID, secretKey, region string) (*externalS3GatewayCreds, error) {
	authURL := strings.TrimSpace(s.externalS3AuthURL)
	if authURL == "" {
		return nil, ErrExternalS3Invalid.New("external S3 auth service URL is not configured")
	}
	base := strings.TrimRight(authURL, "/")
	if strings.HasSuffix(base, "/v1/access") {
		base = strings.TrimSuffix(base, "/v1/access")
	}
	url := base + "/v1/access/external"

	body := map[string]string{
		"endpoint":      endpoint,
		"access_key_id": accessKeyID,
		"secret_key":    secretKey,
		"region":        region,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token := strings.TrimSpace(s.externalS3AuthToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth service request failed: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = res.Status
		}
		return nil, fmt.Errorf("auth service register failed (%d): %s", res.StatusCode, msg)
	}
	var parsed struct {
		AccessKeyID string `json:"access_key_id"`
		SecretKey   string `json:"secret_key"`
		Endpoint    string `json:"endpoint"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("auth service response: %w", err)
	}
	if parsed.AccessKeyID == "" || parsed.SecretKey == "" || parsed.Endpoint == "" {
		return nil, ErrExternalS3Invalid.New("auth service returned incomplete gateway credentials")
	}
	return &externalS3GatewayCreds{
		AccessKeyID: parsed.AccessKeyID,
		SecretKey:   parsed.SecretKey,
		Endpoint:    parsed.Endpoint,
	}, nil
}

func (s *Service) authHasGatewayKey(ctx context.Context, accessKeyID string) bool {
	authURL := strings.TrimSpace(s.externalS3AuthURL)
	if authURL == "" || accessKeyID == "" {
		return false
	}
	base := strings.TrimRight(authURL, "/")
	if strings.HasSuffix(base, "/v1/access") {
		base = strings.TrimSuffix(base, "/v1/access")
	}
	url := base + "/v1/access/" + accessKeyID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	if token := strings.TrimSpace(s.externalS3AuthToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode == http.StatusOK
}

func (s *Service) encryptExternalS3Secret(ctx context.Context, plaintext []byte) ([]byte, int, error) {
	if s.kmsService != nil {
		enc, keyID, err := s.kmsService.EncryptPassphrase(ctx, plaintext)
		if err == nil {
			return enc, keyID, nil
		}
		s.log.Warn("kms encrypt failed for external s3; falling back to local key")
	}
	var n storxnetwork.Nonce
	if _, err := rand.Read(n[:]); err != nil {
		return nil, 0, err
	}
	cipherText, err := encryption.EncryptSecretBox(plaintext, s.localExternalS3Key(), &n)
	if err != nil {
		return nil, 0, err
	}
	out := make([]byte, storxnetwork.NonceSize+len(cipherText))
	copy(out[:storxnetwork.NonceSize], n[:])
	copy(out[storxnetwork.NonceSize:], cipherText)
	return out, externalS3LocalKeyID, nil
}

func (s *Service) decryptExternalS3Secret(ctx context.Context, keyID int, encrypted []byte) ([]byte, error) {
	if keyID != externalS3LocalKeyID && s.kmsService != nil {
		return s.kmsService.DecryptPassphrase(ctx, keyID, encrypted)
	}
	if len(encrypted) < storxnetwork.NonceSize {
		return nil, ErrExternalS3Invalid.New("ciphertext too short")
	}
	var n storxnetwork.Nonce
	copy(n[:], encrypted[:storxnetwork.NonceSize])
	return encryption.DecryptSecretBox(encrypted[storxnetwork.NonceSize:], s.localExternalS3Key(), &n)
}

func (s *Service) localExternalS3Key() *storxnetwork.Key {
	material := strings.TrimSpace(s.externalS3AuthToken)
	if material == "" {
		material = "storx-external-s3-local-dev-key"
	}
	sum := sha256.Sum256([]byte("external-s3:" + material))
	var key storxnetwork.Key
	copy(key[:], sum[:])
	return &key
}
