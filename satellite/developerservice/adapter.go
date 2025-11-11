// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package developerservice

import (
	"context"

	"storj.io/storj/satellite/console"
)

// ConsoleServiceAdapter adapts console.Service to RegistrationTokenChecker interface.
type ConsoleServiceAdapter struct {
	store  console.DB
	config console.Config
}

// NewConsoleServiceAdapter creates a new adapter for console service.
func NewConsoleServiceAdapter(store console.DB, config console.Config) *ConsoleServiceAdapter {
	return &ConsoleServiceAdapter{
		store:  store,
		config: config,
	}
}

// CheckRegistrationSecret checks registration secret.
func (a *ConsoleServiceAdapter) CheckRegistrationSecret(ctx context.Context, tokenSecret console.RegistrationSecret) (*console.RegistrationToken, error) {
	if a.config.OpenRegistrationEnabled && tokenSecret.IsZero() {
		// in this case we're going to let the registration happen without a token
		return nil, nil
	}

	// in all other cases, require a registration token
	registrationToken, err := a.store.RegistrationTokens().GetBySecret(ctx, tokenSecret)
	if err != nil {
		return nil, console.ErrUnauthorized.Wrap(err)
	}
	// if a registration token is already associated with an user ID, that means the token is already used
	// we should terminate the account creation process and return an error
	if registrationToken.OwnerID != nil {
		return nil, console.ErrValidation.New("This registration token has already been used")
	}

	return registrationToken, nil
}
