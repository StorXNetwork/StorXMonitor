// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleauth

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"storj.io/common/uuid"
)

// TODO: change to JWT or Macaroon based auth

// Claims represents data signed by server and used for authentication.
type Claims struct {
	ID         uuid.UUID `json:"id"`
	Email      string    `json:"email,omitempty"`
	Expiration time.Time `json:"expires,omitempty"`
}

// JSON returns json representation of Claims.
func (c *Claims) JSON() ([]byte, error) {
	ctx := context.Background()
	var err error
	defer mon.Task()(&ctx)(&err)

	buffer := bytes.NewBuffer(nil)

	err = json.NewEncoder(buffer).Encode(c)
	return buffer.Bytes(), err
}

// FromJSON returns Claims instance, parsed from JSON.
func FromJSON(data []byte) (*Claims, error) {
	ctx := context.Background()
	var err error
	defer mon.Task()(&ctx)(&err)

	claims := new(Claims)

	err = json.NewDecoder(bytes.NewReader(data)).Decode(claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
