// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleauth

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"

	"github.com/zeebo/errs"
)

// TODO: change to JWT or Macaroon based auth

// Token represents authentication data structure.
type Token struct {
	Payload   []byte
	Signature []byte
	Key       string
}

// String returns base64URLEncoded data joined with .
func (t Token) String() string {
	payload := base64.URLEncoding.EncodeToString(t.Payload)
	signature := base64.URLEncoding.EncodeToString(t.Signature)
	if t.Key != "" {
		key := base64.URLEncoding.EncodeToString([]byte(t.Key))
		return strings.Join([]string{payload, signature, key}, ".")
	}

	return strings.Join([]string{payload, signature}, ".")
}

// FromBase64URLString creates Token instance from base64URLEncoded string representation.
func FromBase64URLString(token string) (Token, error) {
	i := strings.Split(token, ".")
	if len(i) < 2 {
		return Token{}, errs.New("invalid token format")
	}

	payload := i[0]
	signature := i[1]
	payloadDecoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(payload)))
	signatureDecoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(signature)))

	payloadBytes, err := io.ReadAll(payloadDecoder)
	if err != nil {
		return Token{}, errs.New("decoding token's signature failed: %s", err)
	}

	signatureBytes, err := io.ReadAll(signatureDecoder)
	if err != nil {
		return Token{}, errs.New("decoding token's body failed: %s", err)
	}

	if len(i) == 2 {
		return Token{Payload: payloadBytes, Signature: signatureBytes}, nil
	}

	key := i[2]
	keyDecoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(key)))
	keyBytes, err := io.ReadAll(keyDecoder)
	if err != nil {
		return Token{}, errs.New("decoding token's key failed: %s", err)
	}

	return Token{Payload: payloadBytes, Signature: signatureBytes, Key: string(keyBytes)}, nil
}
