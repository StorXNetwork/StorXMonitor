package socialmedia

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

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
func GetRegisterToken(code, codeVerifier string) (*UnstoppableResponse, error) {
	cnf := GetConfig()

	// Define request body
	body := url.Values{}
	body.Set("client_id", cnf.UnstoppableDomainClientID)
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("code_verifier", codeVerifier)
	body.Set("redirect_uri", fmt.Sprint("http://localhost:10002", "/unstoppable_register"))

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "https://auth.unstoppabledomains.com/oauth2/token", bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Basic Authentication header
	req.SetBasicAuth(cnf.UnstoppableDomainClientID, cnf.UnstoppableDomainClientSecret)

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

func GetLoginToken(code, codeVerifier string) (*UnstoppableResponse, error) {
	cnf := GetConfig()

	// Define request body
	body := url.Values{}
	body.Set("client_id", cnf.UnstoppableDomainClientID)
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("code_verifier", codeVerifier)
	body.Set("redirect_uri", fmt.Sprint("http://localhost:10002", "/unstoppable_login"))

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "https://auth.unstoppabledomains.com/oauth2/token", bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Basic Authentication header
	req.SetBasicAuth(cnf.UnstoppableDomainClientID, cnf.UnstoppableDomainClientSecret)

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

var pkceMask = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~."

func GetRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// getRandomBytes generates random bytes of the specified length
func getRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// generateCodeVerifier generates a code verifier of the specified length using PKCE mask
func generateCodeVerifier(length int) (string, error) {
	pkceMask := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.~"
	randomBytes, err := getRandomBytes(length)
	if err != nil {
		return "", err
	}
	verifier := make([]byte, length)
	for i, b := range randomBytes {
		verifier[i] = pkceMask[int(b)%len(pkceMask)]
	}
	return string(verifier), nil
}

func GenerateCodeVerifier(length int) (string, error) {
	bytes, err := GetRandomBytes(length)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, b := range bytes {
		sb.WriteByte(pkceMask[int(b)%len(pkceMask)])
	}
	return sb.String(), nil
}

func GenerateCodeChallengeAndVerifier(length int, method string) (string, string, error) {
	verifier, err := generateCodeVerifier(length)
	if err != nil {
		return "", "", err
	}
	switch method {
	case "plain":
		return verifier, verifier, nil
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		challenge := toUrlEncodedBase64(h[:])
		return verifier, challenge, nil
	default:
		return "", "", fmt.Errorf("bad challenge method")
	}
}

func Sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func toBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func toUrlEncodedBase64(data []byte) string {
	base64Str := toBase64(data)
	encoded := strings.ReplaceAll(base64Str, "=", "")
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	return encoded
}

func GetSortedScope(scope string) string {
	scopes := strings.Fields(scope)
	sort.Strings(scopes)
	return strings.Join(scopes, " ")
}

func RecordCacheKey(record map[string]string) string {
	keys := make([]string, 0, len(record))
	for k, v := range record {
		if v != "" {
			keys = append(keys, k+"="+v)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, "&")
}

func EncodeState(state interface{}) (string, error) {
	randomBytes, _ := GetRandomBytes(32)
	randomBase64 := toUrlEncodedBase64(randomBytes)
	var encodedState string
	if state != nil {
		stateJSON, err := json.Marshal(state)
		if err != nil {
			return "", err
		}
		escapedState := url.QueryEscape(string(stateJSON))
		encodedState = toUrlEncodedBase64([]byte(escapedState))
	}
	return randomBase64 + "." + encodedState, nil
}

func GenerateNonce() (string, error) {
	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Convert bytes to base64 string
	nonce := base64.StdEncoding.EncodeToString(randomBytes)
	return nonce, nil
}

var (
	ReqStore               sync.Map
	UnstoppableDomainScope = "openid wallet messaging:notifications:optional"
)

// ReqOptions contains request parameters and headers
type ReqOptions struct {
	BaseURL     string
	QueryParams QueryParams
	Headers     map[string]string
}

// QueryParams contains query parameters
type QueryParams struct {
	CodeChallenge       string `url:"code_challenge"`
	Nonce               string `url:"nonce"`
	State               string `url:"state"`
	FlowID              string `url:"flow_id"`
	ClientID            string `url:"client_id"`
	ClientSecret        string `url:"client_secret"`
	ClientAuthMethod    string `url:"client_auth_method"`
	MaxAge              string `url:"max_age"`
	Prompt              string `url:"prompt"`
	RedirectURI         string `url:"redirect_uri"`
	ResponseMode        string `url:"response_mode"`
	Scope               string `url:"scope"`
	CodeChallengeMethod string `url:"code_challenge_method"`
	ResponseType        string `url:"response_type"`
	PackageName         string `url:"package_name"`
	PackageVersion      string `url:"package_version"`
}

// toMap converts QueryParams struct to a map
func (qp QueryParams) ToMap() map[string]string {
	params := make(map[string]string)
	params["code_challenge"] = qp.CodeChallenge
	params["nonce"] = qp.Nonce
	params["state"] = qp.State
	params["flow_id"] = qp.FlowID
	params["client_id"] = qp.ClientID
	params["client_secret"] = qp.ClientSecret
	params["client_auth_method"] = qp.ClientAuthMethod
	params["max_age"] = qp.MaxAge
	params["prompt"] = qp.Prompt
	params["redirect_uri"] = qp.RedirectURI
	params["response_mode"] = qp.ResponseMode
	params["scope"] = qp.Scope
	params["code_challenge_method"] = qp.CodeChallengeMethod
	params["response_type"] = qp.ResponseType
	params["package_name"] = qp.PackageName
	params["package_version"] = qp.PackageVersion
	return params
}