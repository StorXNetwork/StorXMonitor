package main

import (
	"encoding/json"
	"fmt"
	"os"
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
	// Check if correct number of arguments provided
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run create_jwt_client_secret.go <client_id> <client_secret> <redirect_uri>")
		fmt.Println("Example: go run create_jwt_client_secret.go 26787adf-82fd-4838-b790-fbded3057755 '$2a$10$IvVS16zgyNYl77BF26.9zOQSaJeLSStxK20csim5H2OFXJhRofnAW' 'https://myapp.com/callback'")
		os.Exit(1)
	}

	// Read arguments
	clientID := os.Args[1]
	clientSecret := os.Args[2]
	redirectURI := os.Args[3]

	// Create JWT client_secret
	jwtClientSecret, err := createJWTClientSecret(clientID, clientSecret, 5)
	if err != nil {
		fmt.Printf("Error creating JWT: %v\n", err)
		os.Exit(1)
	}

	// Display results
	fmt.Println("=== JWT Client Secret Generator (Go) ===")
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Printf("Client Secret: %s\n", clientSecret)
	fmt.Printf("Redirect URI: %s\n", redirectURI)
	fmt.Printf("JWT Client Secret: %s\n\n", jwtClientSecret)

	// Decode and display JWT payload for verification
	token, err := jwt.ParseWithClaims(jwtClientSecret, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(clientSecret), nil
	})

	if err != nil {
		fmt.Printf("Error parsing JWT: %v\n", err)
		os.Exit(1)
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

	// Print the OAuth2 integration URL
	fmt.Println("=== OAuth2 Integration URL ===")
	integrationURL := fmt.Sprintf("https://storx.io/oauth2-integration?client_id=%s&client_secret=%s&redirect_uri=%s&scope=read,write",
		clientID, jwtClientSecret, redirectURI)
	fmt.Println(integrationURL)
	fmt.Println()

}
