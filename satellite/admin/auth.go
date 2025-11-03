// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"storj.io/common/uuid"
)

// AuthService handles JWT token generation and validation for admin authentication.
type AuthService struct {
	secretKey  []byte
	expiration time.Duration
	issuer     string
}

// Config contains configuration for admin auth service.
type AuthConfig struct {
	SecretKey  string        `help:"secret key for signing JWT tokens"`
	Expiration time.Duration `help:"token expiration time" default:"24h"`
	Issuer     string        `help:"token issuer identifier" default:"storj-admin"`
}

// NewAuthService creates a new admin authentication service.
func NewAuthService(config AuthConfig) *AuthService {
	return &AuthService{
		secretKey:  []byte(config.SecretKey),
		expiration: config.Expiration,
		issuer:     config.Issuer,
	}
}

// AdminClaims represents JWT claims for admin tokens.
type AdminClaims struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	TokenType string    `json:"token_type"`
	IssuedAt  time.Time `json:"iat"`
	jwt.RegisteredClaims
}

// GenerateToken generates a new JWT token for admin authentication.
func (s *AuthService) GenerateToken(ctx context.Context, email string) (string, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	now := time.Now()
	expiresAt := now.Add(s.expiration)

	id, err := uuid.New()
	if err != nil {
		return "", err
	}

	claims := &AdminClaims{
		Email:     email,
		Role:      "admin",
		TokenType: "admin",
		IssuedAt:  now,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			ID:        id.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims if valid.
func (s *AuthService) ValidateToken(ctx context.Context, tokenString string) (*AdminClaims, error) {
	var err error
	defer mon.Task()(&ctx)(&err)

	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AdminClaims); ok && token.Valid {
		// Verify issuer
		if claims.Issuer != s.issuer {
			return nil, errors.New("invalid token issuer")
		}

		// Verify token type
		if claims.TokenType != "admin" {
			return nil, errors.New("invalid token type")
		}

		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// IsTokenExpired checks if a token is expired.
func (s *AuthService) IsTokenExpired(ctx context.Context, tokenString string) (bool, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return true, err
	}

	now := time.Now()
	if claims.ExpiresAt != nil {
		return now.After(claims.ExpiresAt.Time), nil
	}

	return false, nil
}
