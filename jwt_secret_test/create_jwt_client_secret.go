package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the payload structure for the client_secret JWT
type JWTClaims struct {
	ClientID string `json:"client_id"`
	jwt.RegisteredClaims
}

func createJWTClientSecret(clientID, clientSecret string, expiryMinutes int) (string, error) {
	// Calculate expiry time
	expiryTime := time.Now().Add(time.Duration(expiryMinutes) * time.Minute)

	// Create claims
	claims := JWTClaims{
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiryTime),
		},
	}

	// Create token with HS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the client_secret
	tokenString, err := token.SignedString([]byte(clientSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

func main() {
	// Client credentials from the provided data
	clientID := "e45fa79a-05f5-4f00-bbfe-bd0a14aead0a"
	clientSecret := "$2a$10$JXG5oUhb7JTVHMyVdEca/.0g7uEJCsRROe7V93lIc7ooIoZ5GLUFa"

	// Create JWT client_secret
	jwtClientSecret, err := createJWTClientSecret(clientID, clientSecret, 5)
	if err != nil {
		fmt.Printf("Error creating JWT: %v\n", err)
		return
	}

	// Display results
	fmt.Println("=== JWT Client Secret Generator (Go) ===")
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Printf("Client Secret: %s\n", clientSecret)
	fmt.Printf("JWT Client Secret: %s\n\n", jwtClientSecret)

	// Decode and display JWT payload for verification
	token, err := jwt.ParseWithClaims(jwtClientSecret, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(clientSecret), nil
	})

	if err != nil {
		fmt.Printf("Error parsing JWT: %v\n", err)
		return
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		fmt.Println("=== JWT Payload (Decoded) ===")
		payload := map[string]interface{}{
			"client_id": claims.ClientID,
			"exp":       claims.ExpiresAt.Unix(),
		}
		payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(payloadJSON))
		fmt.Println()

		// Show expiry information
		fmt.Println("=== Expiry Information ===")
		fmt.Printf("Current Time: %s\n", time.Now().Format(time.RFC3339))
		fmt.Printf("Expiry Time: %s\n", claims.ExpiresAt.Format(time.RFC3339))
		// Use Unix timestamp for time calculation
		expTime := time.Unix(claims.ExpiresAt.Unix(), 0)
		fmt.Printf("Time Remaining: %s\n\n", time.Until(expTime))
	}

	// Example curl request
	fmt.Println("=== Example curl Request ===")
	fmt.Printf(`curl -X POST \
  http://localhost:10100/api/v0/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "%s",
    "client_secret": "%s",
    "redirect_uri": "https://myapp.com/callback",
    "code": "AUTH_CODE_FROM_CONSENT",
    "passphrase": "your-passphrase"
  }'`, clientID, jwtClientSecret)
	fmt.Println()
}
