package socialmedia

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"bytes"

	"net/http"
	"net/url"
)

type TokenDetails struct {
	Acr              string        `json:"acr"`
	Amr              []string      `json:"amr"`
	AtHash           string        `json:"at_hash"`
	Aud              []string      `json:"aud"`
	AuthTime         int64         `json:"auth_time"`
	DomainLive       bool          `json:"domain_live"`
	Eip4361Message   string        `json:"eip4361_message"`
	Eip4361Signature string        `json:"eip4361_signature"`
	Exp              int64         `json:"exp"`
	Iat              int64         `json:"iat"`
	Iss              string        `json:"iss"`
	Jti              string        `json:"jti"`
	Nonce            string        `json:"nonce"`
	Proof            Proof         `json:"proof"`
	Rat              int64         `json:"rat"`
	Sid              string        `json:"sid"`
	Sub              string        `json:"sub"`
	VerifiedAddress  []interface{} `json:"verified_addresses"`
	WalletAddress    string        `json:"wallet_address"`
	WalletTypeHint   string        `json:"wallet_type_hint"`
}

type Proof struct {
	V1SigEthereum map[string]V1SigEthereum `json:"v1.sig.ethereum"`
}

type V1SigEthereum struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Template  struct {
		Format string            `json:"format"`
		Params map[string]string `json:"params"`
	} `json:"template"`
	Type string `json:"type"`
}

func ParseToken(tokenStr string) (*TokenDetails, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	decodedPayload, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %v", err)
	}

	var tokenDetails TokenDetails
	if err := json.Unmarshal(decodedPayload, &tokenDetails); err != nil {
		return nil, fmt.Errorf("error unmarshalling payload: %v", err)
	}

	return &tokenDetails, nil
}
func GetToken(code, codeVerifier string) (*UnstoppableResponse, error) {
	// Define request body
	body := url.Values{}
	body.Set("client_id", configVal.UnstoppableDomainClientSecret)
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("code_verifier", codeVerifier)
	body.Set("redirect_uri", configVal.UnstoppableDomainRedirectUrl)

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "https://auth.unstoppabledomains.com/oauth2/token", bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Basic Authentication header
	req.SetBasicAuth(configVal.UnstoppableDomainClientID, configVal.UnstoppableDomainClientSecret)

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response UnstoppableResponse
	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

type UnstoppableResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}
