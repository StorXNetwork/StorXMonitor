// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package console

import (
	"context"

	"storj.io/storj/satellite/console/consoleauth"
)

// DB contains access to different satellite databases.
//
// architecture: Database
type DB interface {
	// Users is a getter for Users repository.
	Users() Users

	// Web3Auth is a getter for Web3Auth repository.
	Web3Auth() Web3Auth

	// Developers is getter for Developers repository.
	Developers() Developers
	// Projects is a getter for Projects repository.
	Projects() Projects
	// ProjectMembers is a getter for ProjectMembers repository.
	ProjectMembers() ProjectMembers
	// ProjectInvitations is a getter for ProjectInvitations repository.
	ProjectInvitations() ProjectInvitations
	// APIKeys is a getter for APIKeys repository.
	APIKeys() APIKeys
	// RegistrationTokens is a getter for RegistrationTokens repository.
	RegistrationTokens() RegistrationTokens
	// ResetPasswordTokens is a getter for ResetPasswordTokens repository.
	ResetPasswordTokens() ResetPasswordTokens
	// WebappSessions is a getter for WebappSessions repository.
	WebappSessions() consoleauth.WebappSessions
	// WebappSessionDevelopers is a getter for WebappSessionDevelopers repository.
	WebappSessionDevelopers() consoleauth.WebappSessionDevelopers
	// AccountFreezeEvents is a getter for AccountFreezeEvents repository.
	AccountFreezeEvents() AccountFreezeEvents
	// DeveloperOAuthClients is a getter for DeveloperOAuthClients repository.
	DeveloperOAuthClients() DeveloperOAuthClients

	// OAuth2Requests is a getter for OAuth2Requests repository.
	OAuth2Requests() OAuth2Requests

	// WithTx is a method for executing transactions with retrying as necessary.
	WithTx(ctx context.Context, fn func(ctx context.Context, tx DBTx) error) error
}

// DBTx extends Database with transaction scope.
type DBTx interface {
	DB
	// Commit is a method for committing and closing transaction.
	Commit() error
	// Rollback is a method for rollback and closing transaction.
	Rollback() error
}
